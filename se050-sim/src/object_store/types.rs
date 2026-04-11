use serde::{Deserialize, Serialize};

/// Types of EC curves supported by the simulator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ECCurve {
    NistP224,
    NistP256,
    NistP384,
    Ed25519,
    Curve25519,
}

impl ECCurve {
    /// Parse from the SE050 curve constant byte.
    pub fn from_se050_byte(b: u8) -> Option<Self> {
        match b {
            0x02 => Some(ECCurve::NistP224),
            0x03 => Some(ECCurve::NistP256),
            0x04 => Some(ECCurve::NistP384),
            0x40 => Some(ECCurve::Ed25519),
            0x41 => Some(ECCurve::Curve25519),
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
    /// Get the SE050 secure object type code (v7.2.0+ curve-specific for EC).
    pub fn type_code(&self) -> u8 {
        match self {
            SecureObject::ECKeyPair { curve, .. } => match curve {
                ECCurve::NistP224 => 0x25, // kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P224
                ECCurve::NistP256 => 0x29, // kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P256
                ECCurve::NistP384 => 0x2D, // kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P384
                ECCurve::Ed25519 => 0x01,
                ECCurve::Curve25519 => 0x69, // kSE05x_SecObjTyp_EC_KEY_PAIR_MONT_DH_25519
            },
            SecureObject::ECPublicKey { curve, .. } => match curve {
                ECCurve::NistP224 => 0x26, // kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P224
                ECCurve::NistP256 => 0x2A, // kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P256
                ECCurve::NistP384 => 0x2E, // kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P384
                ECCurve::Ed25519 => 0x03,
                ECCurve::Curve25519 => 0x6B, // kSE05x_SecObjTyp_EC_PUB_KEY_MONT_DH_25519
            },
            SecureObject::RSAKeyPair { .. } => 0x04,
            SecureObject::AESKey { .. } => 0x09,
            SecureObject::Binary { .. } => 0x0B,
            SecureObject::UserID { .. } => 0x0C,
            SecureObject::Counter { .. } => 0x0D,
            SecureObject::HMACKey { .. } => 0x11,
        }
    }

    /// Get the SE050 EC curve ID for EC key objects.
    pub fn curve_id(&self) -> Option<u8> {
        let curve = match self {
            SecureObject::ECKeyPair { curve, .. } => Some(curve),
            SecureObject::ECPublicKey { curve, .. } => Some(curve),
            _ => None,
        }?;
        Some(match curve {
            ECCurve::NistP224 => 0x02,
            ECCurve::NistP256 => 0x03,
            ECCurve::NistP384 => 0x04,
            ECCurve::Ed25519 => 0x40,
            ECCurve::Curve25519 => 0x41,
        })
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
