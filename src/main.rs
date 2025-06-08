use mini_totp_cli::totp::Totp;
use std::{
    io::Write,
    thread::sleep,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn main() {
    let totp = Totp::new("Test".to_owned(), "JBSWY3DPEHPK3PXP".to_owned(), 6, 30);

    loop {
        match totp.generate(None) {
            Ok(code) => {
                let time_left = 30
                    - (SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        % 30);
                print!("\rCode: {}  (update in {:02} sec)", code, time_left);
                std::io::stdout().flush().unwrap();
            }
            Err(e) => eprintln!("Error while generating code: {}", e),
        }
        sleep(Duration::from_secs(1));
    }
}
