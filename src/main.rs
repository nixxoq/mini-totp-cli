use crossterm::{cursor, execute};
use mini_totp_cli::{totp::Totp, utils};
use std::{thread::sleep, time::Duration};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let totp = Totp::new("Test".to_owned(), "JBSWY3DPEHPK3PXP".to_owned(), 6, 30);

    let accounts = vec![totp];

    let mut stdout = std::io::stdout();

    execute!(stdout, cursor::Hide)?;

    loop {
        let _ = utils::print_accounts(&accounts);

        println!("Press Ctrl+C to exit");

        sleep(Duration::from_secs(1));

        execute!(stdout, cursor::MoveUp((accounts.len() + 1) as u16))?;
    }
}
