use crossterm::terminal::{Clear, ClearType};

use crate::totp::Totp;
use std::time::{SystemTime, UNIX_EPOCH};

pub mod aegis;

pub fn print_accounts(accounts: &[Totp]) -> Result<(), Box<dyn std::error::Error>> {
    let time_left = 30 - (SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() % 30);

    for account in accounts {
        let code = account.generate(None)?;
        println!(
            "{:<10}: {}  (update in {:02} sec) {}",
            account.name,
            code,
            time_left,
            Clear(ClearType::UntilNewLine)
        );
    }

    Ok(())
}
