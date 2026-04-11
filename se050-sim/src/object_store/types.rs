use serde::{Deserialize, Serialize};

/// Types of EC curves supported by the simulator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ECCurve {
    NistP256,
    Ed25519,
}

impl ECCurve {
    /// Parse from the SE050 curve constant byte.
    pub fn from_se050_byte(b: u8) -> Option<Self> {
        match b {
            0x03 => Some(ECCurve::NistP256),
            0x40 => Some(ECCurve::Ed25519),
            _ => None,
        }
    }
}

/// Secure objects stored in the simulator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecureObject {
    ECKeyPair {
        curve: ECCurve,
        /// Private key bytes (32 bytes for P-256/Ed25519)
        private_key: Vec<u8>,
        /// Public key bytes (65 bytes uncompressed for P-256, 32 bytes for Ed25519)
        public_key: Vec<u8>,
    },
    ECPublicKey {
        curve: ECCurve,
        public_key: Vec<u8>,
    },
    RSAKeyPair {
        key_size_bits: u16,
        /// PKCS#1 DER-encoded private key
        private_key_der: Vec<u8>,
    },
    AESKey {
        key: Vec<u8>,
    },
    Binary {
        data: Vec<u8>,
    },
    UserID {
        value: Vec<u8>,
    },
    Counter {
        value: u64,
    },
    HMACKey {
        key: Vec<u8>,
    },
}

impl SecureObject {
    /// Get the SE050 secure object type code.
    pub fn type_code(&self) -> u8 {
        match self {
            SecureObject::ECKeyPair { .. } => 0x01,
            SecureObject::ECPublicKey { .. } => 0x03,
            SecureObject::RSAKeyPair { .. } => 0x04,
            SecureObject::AESKey { .. } => 0x09,
            SecureObject::Binary { .. } => 0x0B,
            SecureObject::UserID { .. } => 0x0C,
            SecureObject::Counter { .. } => 0x0D,
            SecureObject::HMACKey { .. } => 0x11,
        }
    }

    /// Get the size of the object's primary data in bytes.
    pub fn data_size(&self) -> usize {
        match self {
            SecureObject::ECKeyPair { public_key, .. } => public_key.len(),
            SecureObject::ECPublicKey { public_key, .. } => public_key.len(),
            SecureObject::RSAKeyPair { key_size_bits, .. } => (*key_size_bits as usize) / 8,
            SecureObject::AESKey { key } => key.len(),
            SecureObject::Binary { data } => data.len(),
            SecureObject::UserID { value } => value.len(),
            SecureObject::Counter { .. } => 8,
            SecureObject::HMACKey { key } => key.len(),
        }
    }
}
