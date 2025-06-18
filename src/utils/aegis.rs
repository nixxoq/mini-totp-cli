use std::{fs::File, io::Read, path::Path};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, generic_array::GenericArray},
};
use base64::{Engine, prelude::BASE64_STANDARD};
use hex;
use scrypt::{Params as ScryptParams, scrypt};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize)]
struct Header {
    params: Params,
    slots: Vec<Slot>,
}

#[derive(Deserialize)]
struct Slot {
    #[serde(rename = "type")]
    type_: u32,
    key: String,
    key_params: Params,
    salt: String,
    n: u32,
    r: u32,
    p: u32,
}

#[derive(Deserialize)]
struct Params {
    nonce: String,
    tag: String,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Entry {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(flatten)]
    pub other: Value,
}

pub struct Aegis {
    entries: Vec<Entry>,
}

#[derive(Debug)]
pub enum SearchBy<'a> {
    Name(&'a str),
    Issuer(&'a str),
    Both { name: &'a str, issuer: &'a str },
}

// TODO: review this
impl Aegis {
    pub fn new<P>(db_path: P, password: &[u8]) -> Result<Self, String>
    where
        P: AsRef<Path>,
    {
        let mut file = File::open(db_path).map_err(|e| format!("Failed to open file: {}", e))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| format!("Failed to read file: {}", e))?;

        Self::decrypt_db(&contents, password)
    }

    /// Decrypts the database contents using the provided password.
    ///
    /// How it works (explained in mooooore detail, including bytes etc.):
    /// 1. Reads the encrypted database contents from the file.
    /// 2. Parses the JSON data and extracts the header.
    /// 3. Validates the header and deserializes it into a `Header` struct.
    /// 4. Retrieves the password slots from the header.
    /// 5. Decrypts the AES-256 key using the provided password and the salt.
    /// 6. Decrypts the database entries using the decrypted AES-256 key.
    ///
    /// # Arguments
    ///
    /// * `contents` - The encrypted database contents.
    /// * `password` - The password used to encrypt the database.
    ///
    /// # Returns
    ///
    /// A `Result` containing the decrypted database or an error message.
    fn decrypt_db(contents: &str, password: &[u8]) -> Result<Self, String> {
        let data: Value =
            serde_json::from_str(contents).map_err(|e| format!("Invalid JSON: {}", e))?;

        let header = data
            .get("header")
            .ok_or("Missing header field".to_string())?;
        let header: Header =
            serde_json::from_value(header.clone()).map_err(|e| format!("Invalid header: {}", e))?;

        let slots: Vec<&Slot> = header.slots.iter().filter(|slot| slot.type_ == 1).collect();

        if slots.is_empty() {
            return Err("No password slots found".to_string());
        }

        // okay... get master key by decrypting aes256 key with salt
        let mut master_key = None;
        for slot in slots {
            let salt = hex::decode(&slot.salt).map_err(|e| format!("Invalid salt hex: {}", e))?;

            let log_n = (slot.n as f64).log2() as u8;
            let params = ScryptParams::new(log_n, slot.r, slot.p, 32)
                .map_err(|_| "Invalid scrypt parameters".to_string())?;

            let mut key = [0u8; 32];
            scrypt(password, &salt, &params, &mut key)
                .map_err(|_| "Scrypt derivation failed".to_string())?;

            let nonce_bytes = hex::decode(&slot.key_params.nonce)
                .map_err(|e| format!("Invalid nonce hex: {}", e))?;
            let nonce = Nonce::from_slice(&nonce_bytes);

            let ciphertext =
                hex::decode(&slot.key).map_err(|e| format!("Invalid key hex: {}", e))?;
            let tag =
                hex::decode(&slot.key_params.tag).map_err(|e| format!("Invalid tag hex: {}", e))?;

            let mut full_ciphertext = ciphertext;
            full_ciphertext.extend_from_slice(&tag);

            let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
            if let Ok(decrypted) = cipher.decrypt(nonce, full_ciphertext.as_ref()) {
                master_key = Some(decrypted);
                break;
            }
        }

        // if master_key is None, return error
        let master_key = master_key.ok_or("Failed to decrypt master key".to_string())?;

        let db_b64 = data
            .get("db")
            .and_then(Value::as_str)
            .ok_or("Missing or invalid db field".to_string())?;
        let db_encrypted = BASE64_STANDARD
            .decode(db_b64)
            .map_err(|e| format!("Base64 decode failed: {}", e))?;

        let nonce_bytes =
            hex::decode(&header.params.nonce).map_err(|e| format!("Invalid nonce hex: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let tag = hex::decode(&header.params.tag).map_err(|e| format!("Invalid tag hex: {}", e))?;

        let mut full_db = db_encrypted;
        full_db.extend_from_slice(&tag);

        // use decrypted master_key for main database decryption
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&master_key));
        let db_decrypted = cipher
            .decrypt(nonce, full_db.as_ref())
            .map_err(|_| "Database decryption failed".to_string())?;

        let db_str = String::from_utf8(db_decrypted)
            .map_err(|e| format!("UTF-8 conversion failed: {}", e))?;

        let db_value: Value =
            serde_json::from_str(&db_str).map_err(|e| format!("JSON parse failed: {}", e))?;

        // okay
        let entries = db_value
            .get("entries")
            .ok_or("Missing entries field".to_string())?;
        let entries: Vec<Entry> = serde_json::from_value(entries.clone())
            .map_err(|e| format!("Invalid entries format: {}", e))?;

        Ok(Self { entries })
    }

    pub fn get_all(&self) -> &[Entry] {
        &self.entries
    }

    /// Get entries by search criteria
    ///
    /// # Arguments
    /// * `criteria` - The search criteria to use
    ///
    /// # Returns
    /// A vector of entries that match the search criteria
    ///
    /// # Examples
    /// ```
    /// use mini_totp_cli::utils::aegis::{SearchBy, Aegis};
    ///
    /// let aegis = Aegis::new("path", b"password");
    /// let entries = aegis.expect("error").get_by(SearchBy::Name("example"));
    /// ```
    pub fn get_by(&self, criteria: SearchBy) -> Vec<Entry> {
        self.entries
            .iter()
            .filter(|entry| match criteria {
                SearchBy::Name(name) => entry
                    .name
                    .as_ref()
                    .map(|n| n.to_lowercase().contains(&name.to_lowercase()))
                    .unwrap_or(false),
                SearchBy::Issuer(issuer) => entry
                    .issuer
                    .as_ref()
                    .map(|i| i.to_lowercase().contains(&issuer.to_lowercase()))
                    .unwrap_or(false),
                SearchBy::Both { name, issuer } => {
                    let name_match = entry
                        .name
                        .as_ref()
                        .map(|n| n.to_lowercase().contains(&name.to_lowercase()))
                        .unwrap_or(false);

                    let issuer_match = entry
                        .issuer
                        .as_ref()
                        .map(|i| i.to_lowercase().contains(&issuer.to_lowercase()))
                        .unwrap_or(false);

                    name_match && issuer_match
                }
            })
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_search() {
        let entries = vec![
            Entry {
                name: Some("GitHub".to_string()),
                issuer: Some("GitHub".to_string()),
                other: json!({}),
            },
            Entry {
                name: Some("Google".to_string()),
                issuer: Some("Google".to_string()),
                other: json!({}),
            },
            Entry {
                name: Some("Work Account".to_string()),
                issuer: Some("Company".to_string()),
                other: json!({}),
            },
            Entry {
                name: None,
                issuer: Some("Unknown".to_string()),
                other: json!({}),
            },
        ];

        let db = Aegis { entries };

        // Search by name
        let results = db.get_by(SearchBy::Name("hub"));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name.as_deref(), Some("GitHub"));

        // Search by issuer
        let results = db.get_by(SearchBy::Issuer("oogl"));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].issuer.as_deref(), Some("Google"));

        // Search by both
        let results = db.get_by(SearchBy::Both {
            name: "work",
            issuer: "company",
        });
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name.as_deref(), Some("Work Account"));

        // Case insensitivity
        let results = db.get_by(SearchBy::Name("GITHUB"));
        assert_eq!(results.len(), 1);

        // No match
        let results = db.get_by(SearchBy::Name("Twitter"));
        assert_eq!(results.len(), 0);

        // Entry without name
        let results = db.get_by(SearchBy::Issuer("Unknown"));
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn get_all() {
        match Aegis::new(
            "test.json", // will be created soon
            "pwd".as_bytes(),
        ) {
            Ok(db) => {
                let entries = db.get_all();
                // let res = db.get_by(SearchBy::Name("idk"));
                // entries.iter().for_each(|entry| println!("{:#?}", entry));
                // println!("{:#?}", entries);
                assert_eq!(entries.len(), 4);
            }
            Err(e) => panic!("Failed to load Aegis database: {}", e), // it should fail
        }
    }
}
