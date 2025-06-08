use super::*;

use hmac::Mac;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Totp {
    pub name: String,
    secret: String,
    pub digits: u32,
    pub period: u64,
}

impl Totp {
    pub fn new(name: String, secret: String, digits: u32, period: u64) -> Self {
        Totp {
            name,
            secret,
            digits,
            period,
        }
    }

    pub fn generate(&self, time: Option<SystemTime>) -> Result<String, Box<dyn std::error::Error>> {
        let current_unix_time = time
            .unwrap_or(SystemTime::now())
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        let time_step = current_unix_time / self.period;

        let secret_key_bytes =
            base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &self.secret)
                .ok_or("Invalid base32 key".to_owned())?;

        let time_step_bytes = time_step.to_be_bytes();

        let mut mac = HmacSha1::new_from_slice(&secret_key_bytes)?;
        mac.update(&time_step_bytes);
        let hmac_result = mac.finalize().into_bytes();

        // Get last 4 bits from last byte and convert to usize
        let offset = (hmac_result[19] & 0x0F) as usize;
        let truncated_hash_slice = &hmac_result[offset..offset + 4];

        // Convert slice to array [u8; 4]
        let mut truncated_hash_array = [0u8; 4];
        truncated_hash_array.copy_from_slice(truncated_hash_slice);
        // Convert array to u32 (big-endian) and clear the highest bit
        let code_number = u32::from_be_bytes(truncated_hash_array) & 0x7FFFFFFF;

        // Modulo digits to extract the code
        let modulo = 10u32.pow(self.digits);
        let final_code = code_number % modulo;

        Ok(format!(
            "{:0width$}",
            final_code,
            width = self.digits as usize
        ))
    }
}
