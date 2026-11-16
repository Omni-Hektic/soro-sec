#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, Symbol};

#[contract]
pub struct VulnerableContract;

#[contractimpl]
impl VulnerableContract {
    // VULNERABILITY (SG002): Missing require_auth on privileged function
    pub fn set_admin(env: Env, new_admin: Address) {
        // VULNERABILITY (SG005): Raw symbol_short used as storage key without enum
        // VULNERABILITY (SG001): Storage set without extend_ttl
        env.storage().instance().set(&symbol_short!("admin"), &new_admin);
    }

    // VULNERABILITY (SG003): External token transfer BEFORE internal state mutation (CEI violation)
    // VULNERABILITY (SG004): Raw balance addition without checked math
    pub fn deposit(env: Env, from: Address, token: Address, amount: i128) {
        from.require_auth();

        // External interaction
        let client = soroban_sdk::token::Client::new(&env, &token);
        client.transfer(&from, &env.current_contract_address(), &amount);

        // State mutation after interaction (CEI violation)
        let current_balance: i128 = env.storage().persistent().get(&from).unwrap_or(0);
        let new_balance = current_balance + amount; // Unchecked math
        env.storage().persistent().set(&from, &new_balance);
    }
}
