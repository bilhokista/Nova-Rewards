//! # Admin Roles Contract
//!
//! Role-based access control (RBAC) for the Nova Rewards protocol.
//!
//! ## Roles
//! - `ADMIN`    – full control; can grant/revoke any role and call all privileged functions.
//! - `MERCHANT` – can call merchant-scoped privileged functions (e.g. update_rate).
//! - `OPERATOR` – can call operator-scoped privileged functions (e.g. pause, withdraw).
//!
//! ## Usage
//! ```ignore
//! client.initialize(&owner, &signers_vec, &threshold);
//!
//! // Grant / revoke roles (owner only)
//! client.grant_role(&address, &Role::Merchant);
//! client.revoke_role(&address, &Role::Merchant);
//!
//! // Two-step owner transfer
//! client.propose_admin(&new_owner);
//! client.accept_admin();
//!
//! // M-of-N WASM upgrade (signers configured at initialize)
//! client.approve_upgrade(&signer, &new_wasm_hash);
//! ```
#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, vec, Address, BytesN, Env,
    Vec,
};

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized     = 2,
    Unauthorized       = 3,
    NoPendingAdmin     = 4,
    NotSigner          = 5,
    AlreadyApproved    = 6,
}

// ── Roles ─────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Role {
    Admin,
    Merchant,
    Operator,
}

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Owner,
    PendingOwner,
    Signers,
    Threshold,
    /// Stores `true` when `address` holds `role`.
    Role(Address, Role),
    /// Signers that approved upgrading to the given WASM hash.
    UpgradeApprovals(BytesN<32>),
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct AdminRolesContract;

#[contractimpl]
impl AdminRolesContract {
    // ── Init ──────────────────────────────────────────────────────────────────

    /// One-time setup. The `owner` is automatically granted the `Admin` role.
    pub fn initialize(
        env: Env,
        owner: Address,
        signers: Vec<Address>,
        threshold: u32,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Owner) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Owner, &owner);
        env.storage().instance().set(&DataKey::Signers, &signers);
        env.storage().instance().set(&DataKey::Threshold, &threshold);
        // Owner implicitly holds Admin role
        env.storage()
            .persistent()
            .set(&DataKey::Role(owner.clone(), Role::Admin), &true);
        Ok(())
    }

    // ── RBAC core ─────────────────────────────────────────────────────────────

    /// Grant `role` to `account`. Restricted to the contract owner.
    ///
    /// Emits `("RoleGranted", account)` with data `role`.
    pub fn grant_role(env: Env, account: Address, role: Role) -> Result<(), Error> {
        Self::require_owner(&env)?;
        env.storage()
            .persistent()
            .set(&DataKey::Role(account.clone(), role.clone()), &true);
        env.events()
            .publish((symbol_short!("RoleGrant"), account), role);
        Ok(())
    }

    /// Revoke `role` from `account`. Restricted to the contract owner.
    ///
    /// Emits `("RoleRevoked", account)` with data `role`.
    pub fn revoke_role(env: Env, account: Address, role: Role) -> Result<(), Error> {
        Self::require_owner(&env)?;
        env.storage()
            .persistent()
            .remove(&DataKey::Role(account.clone(), role.clone()));
        env.events()
            .publish((symbol_short!("RoleRevok"), account), role);
        Ok(())
    }

    /// Returns `true` if `account` holds `role`.
    pub fn has_role(env: Env, account: Address, role: Role) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Role(account, role))
            .unwrap_or(false)
    }

    // ── Two-step owner transfer ───────────────────────────────────────────────

    /// Propose a new owner (owner-only). The candidate must call `accept_admin`.
    pub fn propose_admin(env: Env, new_owner: Address) -> Result<(), Error> {
        Self::require_owner(&env)?;
        env.storage()
            .instance()
            .set(&DataKey::PendingOwner, &new_owner);
        env.events().publish(
            (symbol_short!("adm_prop"), Self::owner(&env)),
            new_owner,
        );
        Ok(())
    }

    /// Accept ownership transfer (pending owner only).
    pub fn accept_admin(env: Env) -> Result<(), Error> {
        let pending: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingOwner)
            .ok_or(Error::NoPendingAdmin)?;
        pending.require_auth();

        let old = Self::owner(&env);
        env.storage().instance().set(&DataKey::Owner, &pending);
        env.storage().instance().remove(&DataKey::PendingOwner);
        // Grant Admin role to new owner
        env.storage()
            .persistent()
            .set(&DataKey::Role(pending.clone(), Role::Admin), &true);

        env.events()
            .publish((symbol_short!("adm_xfer"), old), pending);
        Ok(())
    }

    // ── Multisig ──────────────────────────────────────────────────────────────

    /// Update multisig threshold. Restricted to the contract owner.
    pub fn update_threshold(env: Env, threshold: u32) -> Result<(), Error> {
        Self::require_owner(&env)?;
        env.storage().instance().set(&DataKey::Threshold, &threshold);
        Ok(())
    }

    /// Replace the signer set. Requires `Admin` role.
    pub fn update_signers(env: Env, caller: Address, signers: Vec<Address>) -> Result<(), Error> {
        caller.require_auth();
        Self::require_role(&env, &caller, &Role::Admin)?;
        env.storage().instance().set(&DataKey::Signers, &signers);
        Ok(())
    }

    // ── Privileged functions (role-gated) ─────────────────────────────────────

    /// Mint tokens. Requires `Admin` role.
    pub fn mint(env: Env, caller: Address, _to: Address, _amount: i128) -> Result<(), Error> {
        caller.require_auth();
        Self::require_role(&env, &caller, &Role::Admin)
    }

    /// Withdraw funds. Requires `Operator` role.
    pub fn withdraw(env: Env, caller: Address, _to: Address, _amount: i128) -> Result<(), Error> {
        caller.require_auth();
        Self::require_role(&env, &caller, &Role::Operator)
    }

    /// Update reward rate. Requires `Merchant` role.
    pub fn update_rate(env: Env, caller: Address, _rate: u32) -> Result<(), Error> {
        caller.require_auth();
        Self::require_role(&env, &caller, &Role::Merchant)
    }

    /// Pause the protocol. Requires `Operator` role.
    pub fn pause(env: Env, caller: Address) -> Result<(), Error> {
        caller.require_auth();
        Self::require_role(&env, &caller, &Role::Operator)
    }

    // ── Read-only ─────────────────────────────────────────────────────────────

    pub fn get_admin(env: Env) -> Address {
        Self::owner(&env)
    }

    pub fn get_pending_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::PendingOwner)
    }

    pub fn get_threshold(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::Threshold).unwrap_or(1)
    }

    pub fn get_signers(env: Env) -> Vec<Address> {
        env.storage().instance().get(&DataKey::Signers).unwrap_or(vec![&env])
    }

    // ── Upgrade (M-of-N multisig) ─────────────────────────────────────────────

    /// Approve upgrading to `new_wasm_hash`. The upgrade executes once the
    /// number of distinct signer approvals reaches the threshold.
    ///
    /// Emits `("upgraded",)` with data `new_wasm_hash` when the upgrade executes.
    pub fn approve_upgrade(env: Env, signer: Address, new_wasm_hash: BytesN<32>) -> Result<(), Error> {
        signer.require_auth();
        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;
        if !signers.contains(&signer) {
            return Err(Error::NotSigner);
        }

        let key = DataKey::UpgradeApprovals(new_wasm_hash.clone());
        let mut approvals: Vec<Address> =
            env.storage().instance().get(&key).unwrap_or(vec![&env]);
        if approvals.contains(&signer) {
            return Err(Error::AlreadyApproved);
        }
        approvals.push_back(signer);

        if approvals.len() >= Self::get_threshold(env.clone()) {
            env.storage().instance().remove(&key);
            env.events()
                .publish((symbol_short!("upgraded"),), new_wasm_hash.clone());
            env.deployer().update_current_contract_wasm(new_wasm_hash);
        } else {
            env.storage().instance().set(&key, &approvals);
        }
        Ok(())
    }

    pub fn get_upgrade_approvals(env: Env, new_wasm_hash: BytesN<32>) -> u32 {
        env.storage()
            .instance()
            .get::<_, Vec<Address>>(&DataKey::UpgradeApprovals(new_wasm_hash))
            .map_or(0, |approvals| approvals.len())
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn owner(env: &Env) -> Address {
        env.storage().instance().get(&DataKey::Owner).expect("not initialized")
    }

    fn require_owner(env: &Env) -> Result<(), Error> {
        let owner = env
            .storage()
            .instance()
            .get(&DataKey::Owner)
            .ok_or(Error::NotInitialized)?;
        Address::require_auth(&owner);
        Ok(())
    }

    fn require_role(env: &Env, account: &Address, role: &Role) -> Result<(), Error> {
        let has: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Role(account.clone(), role.clone()))
            .unwrap_or(false);
        if !has {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}


// ── Tests ─────────────────────────────────────────────────────────────────────
// RBAC behaviour is covered by tests/admin_tests.rs; these cover the
// owner-gated multisig settings and the upgrade path.

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, vec, Env};

    fn setup_two_signers() -> (Env, Address, Address, AdminRolesContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register(AdminRolesContract, ());
        let client = AdminRolesContractClient::new(&env, &id);
        let s1 = Address::generate(&env);
        let s2 = Address::generate(&env);
        client.initialize(&s1, &vec![&env, s1.clone(), s2.clone()], &2);
        (env, s1, s2, client)
    }

    #[test]
    fn test_update_threshold_requires_owner_auth() {
        let env = Env::default();
        let id = env.register(AdminRolesContract, ());
        let client = AdminRolesContractClient::new(&env, &id);
        let owner = Address::generate(&env);
        client.initialize(&owner, &vec![&env], &1);
        // No auths mocked: the owner has not signed, so the call must fail.
        assert!(client.try_update_threshold(&2).is_err());
        assert_eq!(client.get_threshold(), 1);
    }

    #[test]
    fn test_upgrade_approval_accumulates() {
        let (env, s1, _s2, client) = setup_two_signers();
        let hash = BytesN::from_array(&env, &[0u8; 32]);
        client.approve_upgrade(&s1, &hash);
        assert_eq!(client.get_upgrade_approvals(&hash), 1);
    }

    #[test]
    fn test_non_signer_upgrade_rejected() {
        let (env, _s1, _s2, client) = setup_two_signers();
        let outsider = Address::generate(&env);
        let hash = BytesN::from_array(&env, &[1u8; 32]);
        let err = client.try_approve_upgrade(&outsider, &hash).unwrap_err().unwrap();
        assert_eq!(err, Error::NotSigner);
    }

    #[test]
    fn test_duplicate_upgrade_approval_rejected() {
        let (env, s1, _s2, client) = setup_two_signers();
        let hash = BytesN::from_array(&env, &[2u8; 32]);
        client.approve_upgrade(&s1, &hash);
        let err = client.try_approve_upgrade(&s1, &hash).unwrap_err().unwrap();
        assert_eq!(err, Error::AlreadyApproved);
    }
}
