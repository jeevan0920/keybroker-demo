// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::*;
use keybroker_common::{PublicWrappingKey, WrappedKeyData};
use rsa::{BigUint, Oaep, Pkcs1v15Encrypt, RsaPublicKey};
use sha2::Sha256;

use crate::error::Result;
use std::collections::HashMap;

const RSA_KEY_TYPE: &str = "RSA";
const RSA_PKCS15_ALGORITHM: &str = "RSA1_5";
const RSA_OAEP_ALGORITHM: &str = "RSA-OAEP";

/// Trait defining the interface for key management operations
pub trait KeyManager: Send + Sync {
    /// Retrieve a key from the key manager
    fn get_key(&self, key_id: &str) -> Result<Vec<u8>>;
    
    /// Store a key in the key manager
    fn store_key(&mut self, key_id: &str, data: Vec<u8>) -> Result<()>;
}

/// Implementation of an in-memory key manager
pub struct InMemoryKeyManager {
    keys: HashMap<String, Vec<u8>>,
}

impl InMemoryKeyManager {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }
}

impl KeyManager for InMemoryKeyManager {
    fn get_key(&self, key_id: &str) -> Result<Vec<u8>> {
        self.keys
            .get(key_id)
            .cloned()
            .ok_or(crate::error::Error::KeyStore(
                crate::error::KeyStoreErrorKind::KeyNotFound,
            ))
    }

    fn store_key(&mut self, key_id: &str, data: Vec<u8>) -> Result<()> {
        self.keys.insert(key_id.to_owned(), data);
        Ok(())
    }
}

/// Hashicorp Vault key manager implementation
pub struct HashicorpKeyManager {
    // TODO: Add fields for Vault configuration
    // vault_addr: String,
    // vault_token: String,
    // vault_path: String,
}

impl HashicorpKeyManager {
    pub fn new(/*vault_addr: String, vault_token: String, vault_path: String*/) -> Self {
        Self {
            // TODO: Initialize Vault client configuration
        }
    }
}

impl KeyManager for HashicorpKeyManager {
    fn get_key(&self, key_id: &str) -> Result<Vec<u8>> {
        // TODO: Implement Vault key retrieval
        // For now, return a mock key for testing
        Ok(b"mock_vault_key".to_vec())
    }

    fn store_key(&mut self, key_id: &str, data: Vec<u8>) -> Result<()> {
        // TODO: Implement Vault key storage
        Ok(())
    }
}

/// A minimally simple key store that supports multiple key manager backends.
/// The key store handles the wrapping (encryption) of keys retrieved from the
/// configured key manager.
pub struct KeyStore {
    key_manager: Box<dyn KeyManager>,
}

impl KeyStore {
    /// Create a new key store with the specified key manager
    pub fn new(key_manager: Box<dyn KeyManager>) -> KeyStore {
        KeyStore { key_manager }
    }

    /// Create a new key store with the default in-memory key manager
    pub fn new_in_memory() -> KeyStore {
        KeyStore {
            key_manager: Box::new(InMemoryKeyManager::new()),
        }
    }

    /// Store a new key in the key store.
    ///
    /// Key data here is provided as plain text. That's because this is an initialization
    /// function that is only used by the internals of the key broker to build the contents
    /// of the store from trusted internal sources, such as command-line arguments or a local
    /// configuration file.
    pub fn store_key(&mut self, key_id: &str, data: Vec<u8>) -> Result<()> {
        self.key_manager.store_key(key_id, data)
    }

    /// Obtain a wrapped (encrypted) data item from the store.
    pub fn wrap_key(
        &self,
        key_id: &String,
        wrapping_key: &PublicWrappingKey,
    ) -> Result<WrappedKeyData> {
        if wrapping_key.kty != *RSA_KEY_TYPE {
            return Err(crate::error::Error::KeyStore(
                crate::error::KeyStoreErrorKind::UnsupportedWrappingKeyType,
            ));
        }

        let k_mod = URL_SAFE_NO_PAD.decode(&wrapping_key.n)?;
        let n = BigUint::from_bytes_be(&k_mod);
        let k_exp = URL_SAFE_NO_PAD.decode(&wrapping_key.e)?;
        let e = BigUint::from_bytes_be(&k_exp);

        let mut rng = rand::thread_rng();
        let rsa_pub_key = RsaPublicKey::new(n, e)?;

        let data = self.key_manager.get_key(key_id)?;
        let wrapped_data = {
            if wrapping_key.alg == *RSA_PKCS15_ALGORITHM {
                rsa_pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &data)
            } else if wrapping_key.alg == *RSA_OAEP_ALGORITHM {
                let padding = Oaep::new::<Sha256>();
                rsa_pub_key.encrypt(&mut rng, padding, &data)
            } else {
                return Err(crate::error::Error::KeyStore(
                    crate::error::KeyStoreErrorKind::UnsupportedWrappingKeyAlgorithm,
                ));
            }
        }?;

        let data_base64 = URL_SAFE_NO_PAD.encode(wrapped_data);
        Ok(WrappedKeyData { data: data_base64 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{traits::PublicKeyParts, RsaPrivateKey};

    fn key_store_round_trip(kty: &str, alg: &str) {
        let mut store = KeyStore::new_in_memory();

        // Put a key into the store
        let key_id = "skywalker";
        let key_content = "May the force be with you.";
        store
            .store_key(key_id, key_content.as_bytes().to_vec())
            .expect("Failed to store key");

        // Create an ephemeral wrapping key-pair
        let mut rng = rand::thread_rng();
        let bits = 1024;
        let priv_key =
            RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate ephemeral wrapping key.");

        // Get the public key and deconstruct into modulus and exponent
        let pub_key = RsaPublicKey::from(&priv_key);
        let k_mod = pub_key.n();
        let k_exp = pub_key.e();

        // Create base64 strings for n and e
        let k_mod_base64 = URL_SAFE_NO_PAD.encode(BigUint::to_bytes_be(k_mod));
        let k_exp_base64 = URL_SAFE_NO_PAD.encode(BigUint::to_bytes_be(k_exp));

        // Turn this into API-level input
        let wrapping_key = PublicWrappingKey {
            kty: kty.to_string(),
            alg: alg.to_string(),
            n: k_mod_base64,
            e: k_exp_base64,
        };

        // Make the API call
        let wrapped_data = store
            .wrap_key(&key_id.to_string(), &wrapping_key)
            .expect("Key store did not return the wrapped key.");

        // Decode and decrypt with the private key.
        let ciphertext = URL_SAFE_NO_PAD
            .decode(wrapped_data.data)
            .expect("Failed to base64-decode the wrapped data from the key store.");
        let plaintext = {
            if alg == RSA_PKCS15_ALGORITHM {
                priv_key
                    .decrypt(Pkcs1v15Encrypt, &ciphertext)
                    .expect("Failed to decrypt wrapped data from the key store.")
            } else if alg == RSA_OAEP_ALGORITHM {
                let padding = Oaep::new::<Sha256>();
                priv_key
                    .decrypt(padding, &ciphertext)
                    .expect("Failed to decrypt wrapped data from the key store.")
            } else {
                vec![]
            }
        };

        // Check we got it back
        assert_eq!(key_content.as_bytes(), &plaintext);
    }

    #[test]
    fn round_trip_rsa_pkcs15() {
        key_store_round_trip(RSA_KEY_TYPE, RSA_PKCS15_ALGORITHM)
    }

    #[test]
    fn round_trip_rsa_oaep() {
        key_store_round_trip(RSA_KEY_TYPE, RSA_OAEP_ALGORITHM)
    }
}
