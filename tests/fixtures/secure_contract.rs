#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Balance(Address),
}

const LEDGER_THRESHOLD: u32 = 1000;
const LEDGER_EXTEND: u32 = 50000;

#[contract]
pub struct SecureContract;

#[contractimpl]
impl SecureContract {
    pub fn set_admin(env: Env, admin: Address, new_admin: Address) {
        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage().instance().extend_ttl(LEDGER_THRESHOLD, LEDGER_EXTEND);
    }

    pub fn deposit(env: Env, from: Address, token: Address, amount: i128) {
        from.require_auth();

        // 1. Checks and internal effects FIRST (CEI pattern)
        let current_balance: i128 = env.storage().persistent().get(&DataKey::Balance(from.clone())).unwrap_or(0);
        let new_balance = current_balance.checked_add(amount).expect("Balance overflow");
        
        env.storage().persistent().set(&DataKey::Balance(from.clone()), &new_balance);
        env.storage().persistent().extend_ttl(&DataKey::Balance(from.clone()), LEDGER_THRESHOLD, LEDGER_EXTEND);

        // 2. External interaction LAST
        let client = soroban_sdk::token::Client::new(&env, &token);
        client.transfer(&from, &env.current_contract_address(), &amount);
    }
}
