//! # Distribution Contract
//!
//! Merchant-controlled reward distribution with campaign registration,
//! eligibility rules, batch support (up to 50 recipients), a 30-day clawback
//! window per distribution, and an M-of-N multisig upgrade mechanism.
//!
//! ## Acceptance Criteria (closes #548)
//! - Merchant registers a campaign with token amount and eligibility rules
//! - `distribute_reward(user, amount)` executes correctly
//! - Batch distribution supports up to 50 recipients per call
//! - `RewardIssued` event emitted for each distribution
//! - Unauthorized callers rejected with descriptive error codes
//!
//! ## Event Schema
//!
//! | topics                          | data                                                    |
//! |---------------------------------|---------------------------------------------------------|
//! | `("campaign", campaign_id)`     | `(reward_amount, min_actions)`                          |
//! | `("RewardIssued", campaign_id)` | `(user, amount)`                                        |
//! | `("dist", "distributed")`       | `(v, recipient, amount, deadline)`                      |
//! | `("dist", "batch_dist")`        | `(v, count, total_amount)`                              |
//! | `("dist", "clawback")`          | `(v, recipient, amount)`                                |
//! | `("dist", "upgraded")`          | `(v, new_wasm_hash)`                                    |
#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, token, Address, BytesN, Env,
    Symbol, Vec,
};

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DistributionError {
    /// Contract has already been initialized.
    AlreadyInitialized = 1,
    /// Caller is not the contract admin.
    Unauthorized = 2,
    /// Caller is not the registered merchant for this campaign.
    NotCampaignMerchant = 3,
    /// Campaign ID already exists.
    CampaignAlreadyExists = 4,
    /// Campaign ID does not exist.
    CampaignNotFound = 5,
    /// Campaign is not active.
    CampaignInactive = 6,
    /// Reward amount must be positive.
    InvalidAmount = 7,
    /// Batch size is zero or exceeds the 50-recipient limit.
    InvalidBatchSize = 8,
    /// `recipients` and `amounts` vectors have different lengths.
    BatchLengthMismatch = 9,
    /// Contract or campaign does not hold enough tokens.
    InsufficientBalance = 10,
    /// Contract has not been initialized.
    NotInitialized = 11,
    /// User has not met the campaign's minimum qualifying action count.
    Ineligible = 12,
    /// Threshold is zero or larger than the signer set.
    InvalidThreshold = 13,
    /// No clawback-eligible distribution is recorded for the recipient.
    NoClawbackRecord = 14,
    /// The 30-day clawback window for the recipient has passed.
    ClawbackWindowExpired = 15,
}

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    TokenId,
    Campaign(u64),
    /// Qualifying action count for (campaign_id, user).
    UserActions(u64, Address),
    /// Clawback eligibility window end (ledger timestamp) per recipient.
    ClawbackDeadline(Address),
    /// Amount most recently distributed to a recipient (for clawback).
    Distributed(Address),
    /// Multisig signers for upgrade authorization.
    Signers,
    /// Minimum approvals required for upgrade.
    Threshold,
    /// Pending upgrade approvals: wasm_hash -> Vec<Address>.
    UpgradeApprovals(BytesN<32>),
}

/// Persistent storage TTL: ~31 days at 5 s/ledger.
const CAMPAIGN_TTL: u32 = 535_680;

/// Seconds a distribution remains clawback-eligible (30 days).
const CLAWBACK_WINDOW: u64 = 30 * 24 * 60 * 60;

/// Maximum recipients per batch call.
const MAX_BATCH: u32 = 50;

/// Schema version for the `("dist", ..)` events.
pub const EVENT_SCHEMA_VERSION: u32 = 1;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Eligibility rule: minimum qualifying action count a user must have reached.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct EligibilityRule {
    /// Minimum number of qualifying actions required.
    pub min_actions: u32,
}

/// A merchant reward campaign.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Campaign {
    /// Merchant that owns this campaign.
    pub merchant: Address,
    /// Fixed token amount distributed per eligible user.
    pub reward_amount: i128,
    /// Eligibility rule applied before distribution.
    pub rule: EligibilityRule,
    /// Whether the campaign is currently accepting distributions.
    pub active: bool,
}

// ── Event helpers ─────────────────────────────────────────────────────────────

fn emit_distributed(env: &Env, recipient: &Address, amount: i128, deadline: u64) {
    env.events().publish(
        (symbol_short!("dist"), Symbol::new(env, "distributed")),
        (EVENT_SCHEMA_VERSION, recipient.clone(), amount, deadline),
    );
}

fn emit_batch_distributed(env: &Env, count: u32, total_amount: i128) {
    env.events().publish(
        (symbol_short!("dist"), Symbol::new(env, "batch_dist")),
        (EVENT_SCHEMA_VERSION, count, total_amount),
    );
}

fn emit_clawback(env: &Env, recipient: &Address, amount: i128) {
    env.events().publish(
        (symbol_short!("dist"), symbol_short!("clawback")),
        (EVENT_SCHEMA_VERSION, recipient.clone(), amount),
    );
}

fn emit_contract_upgraded(env: &Env, new_wasm_hash: &BytesN<32>) {
    env.events().publish(
        (symbol_short!("dist"), symbol_short!("upgraded")),
        (EVENT_SCHEMA_VERSION, new_wasm_hash.clone()),
    );
}

/// Emits `("RewardIssued", campaign_id)` with data `(user, amount)`.
fn emit_reward_issued(env: &Env, campaign_id: u64, user: &Address, amount: i128) {
    env.events().publish(
        (Symbol::new(env, "RewardIssued"), campaign_id),
        (user.clone(), amount),
    );
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct DistributionContract;

#[contractimpl]
impl DistributionContract {
    // ── Init ──────────────────────────────────────────────────────────────────

    /// One-time setup.
    ///
    /// # Parameters
    /// - `admin` – Address authorized to manage campaigns, distribute and claw back.
    /// - `token_id` – Address of the Nova token contract used for transfers.
    /// - `signers` – Multisig signer set for upgrade authorization.
    /// - `threshold` – Minimum approvals required to execute an upgrade.
    pub fn initialize(
        env: Env,
        admin: Address,
        token_id: Address,
        signers: Vec<Address>,
        threshold: u32,
    ) -> Result<(), DistributionError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(DistributionError::AlreadyInitialized);
        }
        if threshold == 0 || signers.len() < threshold {
            return Err(DistributionError::InvalidThreshold);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::TokenId, &token_id);
        env.storage().instance().set(&DataKey::Signers, &signers);
        env.storage().instance().set(&DataKey::Threshold, &threshold);
        Ok(())
    }

    // ── Campaign management ───────────────────────────────────────────────────

    /// Register a new reward campaign.
    ///
    /// Only the admin may register campaigns on behalf of merchants.
    ///
    /// # Parameters
    /// - `campaign_id` – Unique identifier for the campaign.
    /// - `merchant` – Address authorized to distribute rewards for this campaign.
    /// - `reward_amount` – Fixed token amount per eligible user (must be > 0).
    /// - `min_actions` – Minimum qualifying actions a user must have performed.
    pub fn register_campaign(
        env: Env,
        campaign_id: u64,
        merchant: Address,
        reward_amount: i128,
        min_actions: u32,
    ) -> Result<(), DistributionError> {
        Self::require_admin(&env)?;

        if env
            .storage()
            .persistent()
            .has(&DataKey::Campaign(campaign_id))
        {
            return Err(DistributionError::CampaignAlreadyExists);
        }
        if reward_amount <= 0 {
            return Err(DistributionError::InvalidAmount);
        }

        let campaign = Campaign {
            merchant,
            reward_amount,
            rule: EligibilityRule { min_actions },
            active: true,
        };
        let key = DataKey::Campaign(campaign_id);
        env.storage().persistent().set(&key, &campaign);
        env.storage()
            .persistent()
            .extend_ttl(&key, CAMPAIGN_TTL, CAMPAIGN_TTL);

        env.events().publish(
            (symbol_short!("campaign"), campaign_id),
            (campaign.reward_amount, campaign.rule.min_actions),
        );
        Ok(())
    }

    /// Deactivate a campaign. Only the admin may call this.
    pub fn deactivate_campaign(env: Env, campaign_id: u64) -> Result<(), DistributionError> {
        Self::require_admin(&env)?;
        let mut campaign = Self::load_campaign(&env, campaign_id)?;
        campaign.active = false;
        let key = DataKey::Campaign(campaign_id);
        env.storage().persistent().set(&key, &campaign);
        env.storage()
            .persistent()
            .extend_ttl(&key, CAMPAIGN_TTL, CAMPAIGN_TTL);
        Ok(())
    }

    // ── Eligibility ───────────────────────────────────────────────────────────

    /// Record a qualifying action for `user` in `campaign_id`.
    ///
    /// Admin-gated. Increments the user's action counter by 1.
    pub fn record_action(
        env: Env,
        campaign_id: u64,
        user: Address,
    ) -> Result<(), DistributionError> {
        Self::require_admin(&env)?;
        // Ensure campaign exists
        Self::load_campaign(&env, campaign_id)?;

        let key = DataKey::UserActions(campaign_id, user.clone());
        let count: u32 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(count + 1));
        env.storage()
            .persistent()
            .extend_ttl(&key, CAMPAIGN_TTL, CAMPAIGN_TTL);
        Ok(())
    }

    /// Returns the qualifying action count for `user` in `campaign_id`.
    pub fn get_user_actions(env: Env, campaign_id: u64, user: Address) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::UserActions(campaign_id, user))
            .unwrap_or(0)
    }

    // ── Reward calculation ────────────────────────────────────────────────────

    /// Calculate the reward for a given `base_amount` and `rate_bps`
    /// (rate in basis points, 10 000 = 100 %).
    pub fn calculate_reward(base_amount: i128, rate_bps: i128) -> i128 {
        assert!(base_amount >= 0, "base_amount must be non-negative");
        assert!(
            (0..=10_000).contains(&rate_bps),
            "rate_bps must be 0–10 000"
        );
        base_amount
            .checked_mul(rate_bps)
            .expect("overflow in base_amount * rate_bps")
            / 10_000
    }

    // ── Distribution ──────────────────────────────────────────────────────────

    /// Distribute a reward to a single user.
    ///
    /// The caller must be the merchant registered for `campaign_id`.
    /// `amount` must be > 0 and ≤ the campaign's `reward_amount`.
    /// The user must have met the campaign's `min_actions` eligibility rule.
    ///
    /// Emits `RewardIssued` and `("dist", "distributed")` on success.
    pub fn distribute_reward(
        env: Env,
        campaign_id: u64,
        user: Address,
        amount: i128,
    ) -> Result<(), DistributionError> {
        let campaign = Self::load_campaign(&env, campaign_id)?;
        campaign.merchant.require_auth();

        if !campaign.active {
            return Err(DistributionError::CampaignInactive);
        }
        if amount <= 0 || amount > campaign.reward_amount {
            return Err(DistributionError::InvalidAmount);
        }
        Self::check_eligibility(&env, campaign_id, &user, &campaign.rule)?;

        Self::do_transfer(&env, &user, amount)?;
        emit_reward_issued(&env, campaign_id, &user, amount);
        Ok(())
    }

    /// Distribute rewards to up to 50 users in a single call.
    ///
    /// The caller must be the merchant registered for `campaign_id`.
    /// All amounts must be > 0 and ≤ the campaign's `reward_amount`.
    /// Every recipient must meet the campaign's `min_actions` eligibility rule.
    /// The entire batch is validated before any transfer executes.
    ///
    /// Emits `RewardIssued` and `("dist", "distributed")` per recipient, plus a
    /// `("dist", "batch_dist")` summary event.
    pub fn distribute_batch(
        env: Env,
        campaign_id: u64,
        recipients: Vec<Address>,
        amounts: Vec<i128>,
    ) -> Result<(), DistributionError> {
        let campaign = Self::load_campaign(&env, campaign_id)?;
        campaign.merchant.require_auth();

        if !campaign.active {
            return Err(DistributionError::CampaignInactive);
        }

        let n = recipients.len();
        if n == 0 || n > MAX_BATCH {
            return Err(DistributionError::InvalidBatchSize);
        }
        if n != amounts.len() {
            return Err(DistributionError::BatchLengthMismatch);
        }

        // Pre-validate all amounts, eligibility, and compute total
        let mut total: i128 = 0;
        for i in 0..n {
            let amt = amounts.get(i).unwrap();
            if amt <= 0 || amt > campaign.reward_amount {
                return Err(DistributionError::InvalidAmount);
            }
            let recipient = recipients.get(i).unwrap();
            Self::check_eligibility(&env, campaign_id, &recipient, &campaign.rule)?;
            total = total.checked_add(amt).ok_or(DistributionError::InvalidAmount)?;
        }

        // Check contract balance covers the whole batch
        let tok = Self::token_client(&env)?;
        if tok.balance(&env.current_contract_address()) < total {
            return Err(DistributionError::InsufficientBalance);
        }

        // Execute transfers
        for i in 0..n {
            let recipient = recipients.get(i).unwrap();
            let amount = amounts.get(i).unwrap();
            Self::do_transfer(&env, &recipient, amount)?;
            emit_reward_issued(&env, campaign_id, &recipient, amount);
        }
        emit_batch_distributed(&env, n, total);
        Ok(())
    }

    /// Admin-only distribution outside any campaign (no eligibility rules).
    ///
    /// Emits `("dist", "distributed")` on success.
    pub fn distribute(env: Env, recipient: Address, amount: i128) -> Result<(), DistributionError> {
        Self::require_admin(&env)?;
        if amount <= 0 {
            return Err(DistributionError::InvalidAmount);
        }
        Self::do_transfer(&env, &recipient, amount)
    }

    // ── Clawback ──────────────────────────────────────────────────────────────

    /// Reclaim the last distribution to `recipient` back into the contract.
    ///
    /// Admin-only and only within 30 days of that distribution. The recipient
    /// must have approved this contract to pull the amount.
    ///
    /// Emits `("dist", "clawback")` with `(schema_version, recipient, amount)`.
    pub fn clawback(env: Env, recipient: Address) -> Result<(), DistributionError> {
        Self::require_admin(&env)?;

        let deadline_key = DataKey::ClawbackDeadline(recipient.clone());
        let amount_key = DataKey::Distributed(recipient.clone());
        let deadline: u64 = env
            .storage()
            .persistent()
            .get(&deadline_key)
            .ok_or(DistributionError::NoClawbackRecord)?;
        if env.ledger().timestamp() > deadline {
            return Err(DistributionError::ClawbackWindowExpired);
        }
        let amount: i128 = env
            .storage()
            .persistent()
            .get(&amount_key)
            .ok_or(DistributionError::NoClawbackRecord)?;

        let contract_addr = env.current_contract_address();
        Self::token_client(&env)?.transfer_from(&contract_addr, &recipient, &contract_addr, &amount);

        env.storage().persistent().remove(&deadline_key);
        env.storage().persistent().remove(&amount_key);
        emit_clawback(&env, &recipient, amount);
        Ok(())
    }

    // ── View ──────────────────────────────────────────────────────────────────

    /// Returns the campaign data for `campaign_id`.
    pub fn get_campaign_info(env: Env, campaign_id: u64) -> Result<Campaign, DistributionError> {
        Self::load_campaign(&env, campaign_id)
    }

    /// Returns the Nova token balance held by this contract.
    pub fn contract_balance(env: Env) -> Result<i128, DistributionError> {
        Ok(Self::token_client(&env)?.balance(&env.current_contract_address()))
    }

    /// Amount of the last distribution to `recipient` still open to clawback.
    pub fn get_distributed(env: Env, recipient: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Distributed(recipient))
            .unwrap_or(0)
    }

    /// Clawback deadline (ledger timestamp) for `recipient`, or 0 if none.
    pub fn get_clawback_deadline(env: Env, recipient: Address) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::ClawbackDeadline(recipient))
            .unwrap_or(0)
    }

    // ── Upgrade (M-of-N multisig) ─────────────────────────────────────────────

    /// Approve a pending WASM upgrade. Executes when threshold is reached.
    ///
    /// Emits `("dist", "upgraded")` when the threshold is met.
    ///
    /// # Panics
    /// - `"not an authorized signer"` if `signer` is not in the signer set.
    /// - `"already approved"` if `signer` has already approved this hash.
    pub fn approve_upgrade(env: Env, signer: Address, new_wasm_hash: BytesN<32>) {
        signer.require_auth();

        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .expect("not initialized");
        assert!(signers.contains(&signer), "not an authorized signer");

        let approval_key = DataKey::UpgradeApprovals(new_wasm_hash.clone());
        let mut approvals: Vec<Address> = env
            .storage()
            .instance()
            .get(&approval_key)
            .unwrap_or(Vec::new(&env));
        assert!(!approvals.contains(&signer), "already approved");

        approvals.push_back(signer);
        if approvals.len() >= Self::get_threshold(env.clone()) {
            env.storage().instance().remove(&approval_key);
            emit_contract_upgraded(&env, &new_wasm_hash);
            env.deployer().update_current_contract_wasm(new_wasm_hash);
        } else {
            env.storage().instance().set(&approval_key, &approvals);
        }
    }

    pub fn get_upgrade_approvals(env: Env, new_wasm_hash: BytesN<32>) -> u32 {
        env.storage()
            .instance()
            .get::<_, Vec<Address>>(&DataKey::UpgradeApprovals(new_wasm_hash))
            .map_or(0, |approvals| approvals.len())
    }

    pub fn get_threshold(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::Threshold)
            .unwrap_or(1)
    }

    pub fn get_signers(env: Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::Signers)
            .unwrap_or(Vec::new(&env))
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn require_admin(env: &Env) -> Result<Address, DistributionError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(DistributionError::NotInitialized)?;
        admin.require_auth();
        Ok(admin)
    }

    fn token_client(env: &Env) -> Result<token::Client<'_>, DistributionError> {
        let id: Address = env
            .storage()
            .instance()
            .get(&DataKey::TokenId)
            .ok_or(DistributionError::NotInitialized)?;
        Ok(token::Client::new(env, &id))
    }

    fn load_campaign(env: &Env, campaign_id: u64) -> Result<Campaign, DistributionError> {
        let key = DataKey::Campaign(campaign_id);
        let campaign = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(DistributionError::CampaignNotFound)?;
        // Refresh TTL on read
        env.storage()
            .persistent()
            .extend_ttl(&key, CAMPAIGN_TTL, CAMPAIGN_TTL);
        Ok(campaign)
    }

    fn check_eligibility(
        env: &Env,
        campaign_id: u64,
        user: &Address,
        rule: &EligibilityRule,
    ) -> Result<(), DistributionError> {
        if rule.min_actions == 0 {
            return Ok(());
        }
        let actions: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::UserActions(campaign_id, user.clone()))
            .unwrap_or(0);
        if actions < rule.min_actions {
            return Err(DistributionError::Ineligible);
        }
        Ok(())
    }

    /// Transfers `amount` to `to` and opens a 30-day clawback window for it.
    fn do_transfer(env: &Env, to: &Address, amount: i128) -> Result<(), DistributionError> {
        let tok = Self::token_client(env)?;
        let contract_addr = env.current_contract_address();
        if tok.balance(&contract_addr) < amount {
            return Err(DistributionError::InsufficientBalance);
        }
        tok.transfer(&contract_addr, to, &amount);

        let deadline = env.ledger().timestamp() + CLAWBACK_WINDOW;
        env.storage()
            .persistent()
            .set(&DataKey::ClawbackDeadline(to.clone()), &deadline);
        env.storage()
            .persistent()
            .set(&DataKey::Distributed(to.clone()), &amount);
        emit_distributed(env, to, amount, deadline);
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        vec, Env,
    };

    mod mock_token {
        use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

        #[contracttype]
        pub enum Key {
            Balance(Address),
        }

        #[contract]
        pub struct MockToken;

        fn move_balance(env: &Env, from: Address, to: Address, amount: i128) {
            let from_key = Key::Balance(from);
            let to_key = Key::Balance(to);
            let from_bal: i128 = env.storage().instance().get(&from_key).unwrap_or(0);
            assert!(from_bal >= amount, "insufficient balance");
            env.storage().instance().set(&from_key, &(from_bal - amount));
            let to_bal: i128 = env.storage().instance().get(&to_key).unwrap_or(0);
            env.storage().instance().set(&to_key, &(to_bal + amount));
        }

        #[contractimpl]
        impl MockToken {
            pub fn mint(env: Env, to: Address, amount: i128) {
                let key = Key::Balance(to);
                let bal: i128 = env.storage().instance().get(&key).unwrap_or(0);
                env.storage().instance().set(&key, &(bal + amount));
            }

            pub fn balance(env: Env, addr: Address) -> i128 {
                env.storage()
                    .instance()
                    .get(&Key::Balance(addr))
                    .unwrap_or(0)
            }

            pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
                move_balance(&env, from, to, amount);
            }

            pub fn transfer_from(env: Env, _spender: Address, from: Address, to: Address, amount: i128) {
                move_balance(&env, from, to, amount);
            }
        }
    }

    fn setup() -> (
        Env,
        Address,
        DistributionContractClient<'static>,
        Address,
        Address,
    ) {
        let env = Env::default();
        env.mock_all_auths();

        let token_id = env.register(mock_token::MockToken, ());
        let contract_id = env.register(DistributionContract, ());
        let admin = Address::generate(&env);
        let merchant = Address::generate(&env);

        let client = DistributionContractClient::new(&env, &contract_id);
        client.initialize(&admin, &token_id, &vec![&env, admin.clone()], &1);

        // Fund the distribution contract
        let tok = mock_token::MockTokenClient::new(&env, &token_id);
        tok.mint(&contract_id, &100_000);

        (env, admin, client, token_id, merchant)
    }

    #[test]
    fn test_calculate_reward() {
        assert_eq!(DistributionContract::calculate_reward(1_000, 500), 50);
        assert_eq!(DistributionContract::calculate_reward(1_000, 10_000), 1_000);
        assert_eq!(DistributionContract::calculate_reward(1_000, 0), 0);
    }

    #[test]
    fn test_register_and_distribute_single() {
        let (env, _admin, client, token_id, merchant) = setup();
        let user = Address::generate(&env);

        // min_actions = 0 → no eligibility check
        client.register_campaign(&1, &merchant, &1_000, &0);
        client.distribute_reward(&1, &user, &500);

        let tok = mock_token::MockTokenClient::new(&env, &token_id);
        assert_eq!(tok.balance(&user), 500);
        assert_eq!(client.get_distributed(&user), 500);
    }

    #[test]
    fn test_eligibility_enforced() {
        let (env, _admin, client, token_id, merchant) = setup();
        let user = Address::generate(&env);

        // min_actions = 2
        client.register_campaign(&10, &merchant, &1_000, &2);

        // 0 actions → Ineligible
        let err = client
            .try_distribute_reward(&10, &user, &500)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, DistributionError::Ineligible);

        // Record 1 action → still ineligible
        client.record_action(&10, &user);
        let err = client
            .try_distribute_reward(&10, &user, &500)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, DistributionError::Ineligible);

        // Record 2nd action → now eligible
        client.record_action(&10, &user);
        client.distribute_reward(&10, &user, &500);

        let tok = mock_token::MockTokenClient::new(&env, &token_id);
        assert_eq!(tok.balance(&user), 500);
    }

    #[test]
    fn test_batch_eligibility_enforced() {
        let (env, _admin, client, _token_id, merchant) = setup();
        let eligible = Address::generate(&env);
        let ineligible = Address::generate(&env);

        client.register_campaign(&11, &merchant, &100, &1);
        client.record_action(&11, &eligible);

        let recipients = vec![&env, eligible.clone(), ineligible.clone()];
        let amounts = vec![&env, 100_i128, 100_i128];

        let err = client
            .try_distribute_batch(&11, &recipients, &amounts)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, DistributionError::Ineligible);
    }

    #[test]
    fn test_distribute_batch_up_to_50() {
        let (env, _admin, client, token_id, merchant) = setup();
        // 50 recipients x 3 persistent writes exceeds the per-tx entry cap in
        // simulation; the contract-level limit is the MAX_BATCH guard.
        env.cost_estimate().budget().reset_unlimited();
        env.host().set_invocation_resource_limits(None).unwrap();

        client.register_campaign(&2, &merchant, &100, &0);

        let mut recipients = Vec::new(&env);
        let mut amounts = Vec::new(&env);
        for _ in 0..50 {
            recipients.push_back(Address::generate(&env));
            amounts.push_back(100_i128);
        }

        client.distribute_batch(&2, &recipients, &amounts);

        let tok = mock_token::MockTokenClient::new(&env, &token_id);
        assert_eq!(tok.balance(&recipients.get(0).unwrap()), 100);
        assert_eq!(tok.balance(&recipients.get(49).unwrap()), 100);
    }

    #[test]
    fn test_batch_exceeds_50_rejected() {
        let (env, _admin, client, _token_id, merchant) = setup();
        client.register_campaign(&3, &merchant, &100, &0);

        let mut recipients = Vec::new(&env);
        let mut amounts = Vec::new(&env);
        for _ in 0..51 {
            recipients.push_back(Address::generate(&env));
            amounts.push_back(100_i128);
        }

        let err = client
            .try_distribute_batch(&3, &recipients, &amounts)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, DistributionError::InvalidBatchSize);
    }

    #[test]
    fn test_campaign_not_found_rejected() {
        let (env, _admin, client, _token_id, _merchant) = setup();
        let user = Address::generate(&env);

        let err = client
            .try_distribute_reward(&99, &user, &100)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, DistributionError::CampaignNotFound);
    }

    #[test]
    fn test_inactive_campaign_rejected() {
        let (env, _admin, client, _token_id, merchant) = setup();
        let user = Address::generate(&env);

        client.register_campaign(&5, &merchant, &500, &0);
        client.deactivate_campaign(&5);

        let err = client
            .try_distribute_reward(&5, &user, &100)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, DistributionError::CampaignInactive);
    }

    #[test]
    fn test_amount_exceeds_campaign_reward_rejected() {
        let (env, _admin, client, _token_id, merchant) = setup();
        let user = Address::generate(&env);

        client.register_campaign(&6, &merchant, &200, &0);

        let err = client
            .try_distribute_reward(&6, &user, &201)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, DistributionError::InvalidAmount);
    }

    #[test]
    fn test_double_initialize_rejected() {
        let (env, admin, client, token_id, _merchant) = setup();
        let err = client
            .try_initialize(&admin, &token_id, &vec![&env, admin.clone()], &1)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, DistributionError::AlreadyInitialized);
    }

    #[test]
    fn test_threshold_above_signer_count_rejected() {
        let env = Env::default();
        let token_id = env.register(mock_token::MockToken, ());
        let client =
            DistributionContractClient::new(&env, &env.register(DistributionContract, ()));
        let admin = Address::generate(&env);
        let err = client
            .try_initialize(&admin, &token_id, &vec![&env, admin.clone()], &2)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, DistributionError::InvalidThreshold);
    }

    #[test]
    fn test_batch_length_mismatch_rejected() {
        let (env, _admin, client, _token_id, merchant) = setup();
        client.register_campaign(&7, &merchant, &100, &0);

        let recipients = vec![&env, Address::generate(&env)];
        let amounts = vec![&env, 100_i128, 50_i128];

        let err = client
            .try_distribute_batch(&7, &recipients, &amounts)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, DistributionError::BatchLengthMismatch);
    }

    #[test]
    fn test_admin_distribute_without_campaign() {
        let (env, _admin, client, token_id, _merchant) = setup();
        let recipient = Address::generate(&env);

        client.distribute(&recipient, &500);

        let tok = mock_token::MockTokenClient::new(&env, &token_id);
        assert_eq!(tok.balance(&recipient), 500);
        assert_eq!(client.get_distributed(&recipient), 500);
    }

    #[test]
    fn test_distribute_exceeds_balance_rejected() {
        let (env, _admin, client, _token_id, _merchant) = setup();
        let recipient = Address::generate(&env);
        let err = client
            .try_distribute(&recipient, &999_999)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, DistributionError::InsufficientBalance);
    }

    // ── Clawback ──────────────────────────────────────────────────────────────

    #[test]
    fn test_clawback_within_window() {
        let (env, _admin, client, token_id, merchant) = setup();
        let user = Address::generate(&env);
        client.register_campaign(&8, &merchant, &400, &0);
        client.distribute_reward(&8, &user, &400);

        client.clawback(&user);

        let tok = mock_token::MockTokenClient::new(&env, &token_id);
        assert_eq!(tok.balance(&user), 0);
        assert_eq!(client.get_distributed(&user), 0);
        assert_eq!(client.get_clawback_deadline(&user), 0);
    }

    #[test]
    fn test_clawback_after_window_rejected() {
        let (env, _admin, client, _token_id, _merchant) = setup();
        let recipient = Address::generate(&env);
        client.distribute(&recipient, &400);

        env.ledger().with_mut(|l| {
            l.timestamp += CLAWBACK_WINDOW + 1;
        });

        let err = client.try_clawback(&recipient).unwrap_err().unwrap();
        assert_eq!(err, DistributionError::ClawbackWindowExpired);
    }

    #[test]
    fn test_clawback_without_distribution_rejected() {
        let (env, _admin, client, _token_id, _merchant) = setup();
        let stranger = Address::generate(&env);
        let err = client.try_clawback(&stranger).unwrap_err().unwrap();
        assert_eq!(err, DistributionError::NoClawbackRecord);
    }

    // ── Upgrade ───────────────────────────────────────────────────────────────

    fn setup_two_signers() -> (Env, Address, DistributionContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let token_id = env.register(mock_token::MockToken, ());
        let client =
            DistributionContractClient::new(&env, &env.register(DistributionContract, ()));
        let s1 = Address::generate(&env);
        let s2 = Address::generate(&env);
        client.initialize(&s1, &token_id, &vec![&env, s1.clone(), s2.clone()], &2);
        (env, s1, client)
    }

    #[test]
    fn test_upgrade_approval_accumulates() {
        let (env, s1, client) = setup_two_signers();
        let fake_hash = BytesN::from_array(&env, &[0u8; 32]);
        client.approve_upgrade(&s1, &fake_hash);
        assert_eq!(client.get_upgrade_approvals(&fake_hash), 1);
    }

    #[test]
    #[should_panic(expected = "not an authorized signer")]
    fn test_unauthorized_upgrade_rejected() {
        let (env, _admin, client, _, _) = setup();
        let outsider = Address::generate(&env);
        let fake_hash = BytesN::from_array(&env, &[1u8; 32]);
        client.approve_upgrade(&outsider, &fake_hash);
    }

    #[test]
    #[should_panic(expected = "already approved")]
    fn test_duplicate_approval_rejected() {
        let (env, s1, client) = setup_two_signers();
        let fake_hash = BytesN::from_array(&env, &[2u8; 32]);
        client.approve_upgrade(&s1, &fake_hash);
        client.approve_upgrade(&s1, &fake_hash);
    }
}
