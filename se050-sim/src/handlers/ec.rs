use crate::apdu::*;
use crate::object_store::types::{ECCurve, SecureObject};
use crate::object_store::ObjectStore;
use crate::tlv::{self, Tlv, TAG_1, TAG_2, TAG_3, TAG_5, TAG_7};

use ecdsa::signature::{Signer, Verifier};
use rand::rngs::OsRng;

/// Handle WRITE EC key command (key generation when P2=Default and no private key data).
pub fn handle_write_ec_key(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    // Extract object ID from Tag1
    let obj_id = match tlv::find_tlv(&tlvs, TAG_1) {
        Some(t) if t.value.len() == 4 => {
            let mut id = [0u8; 4];
            id.copy_from_slice(&t.value);
            id
        }
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    // Extract curve from Tag2
    let curve = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if !t.value.is_empty() => match ECCurve::from_se050_byte(t.value[0]) {
            Some(c) => c,
            None => return ApduResponse::error(SW_WRONG_DATA),
        },
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    // Check if private key data is provided in Tag3
    let has_private_key = tlv::find_tlv(&tlvs, TAG_3).is_some();

    if apdu.key_type() == P1_KEY_PAIR && !has_private_key {
        // Generate a new key pair
        match curve {
            ECCurve::NistP224 => generate_p224_keypair(obj_id, store),
            ECCurve::NistP256 => generate_p256_keypair(obj_id, store),
            ECCurve::NistP384 => generate_p384_keypair(obj_id, store),
            ECCurve::Ed25519 => generate_ed25519_keypair(obj_id, store),
        }
    } else if has_private_key {
        // Import private key - extract from Tag3
        let private_key_data = tlv::find_tlv(&tlvs, TAG_3).unwrap().value.clone();
        import_ec_key(obj_id, curve, &private_key_data, apdu.key_type(), store)
    } else {
        ApduResponse::error(SW_WRONG_DATA)
    }
}

fn generate_p224_keypair(obj_id: [u8; 4], store: &mut ObjectStore) -> ApduResponse {
    let sk = p224::ecdsa::SigningKey::random(&mut OsRng);
    let pk = sk.verifying_key();
    store.insert(obj_id, SecureObject::ECKeyPair {
        curve: ECCurve::NistP224,
        private_key: sk.to_bytes().to_vec(),
        public_key: pk.to_encoded_point(false).as_bytes().to_vec(),
    });
    ApduResponse::success()
}

fn generate_p256_keypair(obj_id: [u8; 4], store: &mut ObjectStore) -> ApduResponse {
    let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
    let pk = sk.verifying_key();
    store.insert(obj_id, SecureObject::ECKeyPair {
        curve: ECCurve::NistP256,
        private_key: sk.to_bytes().to_vec(),
        public_key: pk.to_encoded_point(false).as_bytes().to_vec(),
    });
    ApduResponse::success()
}

fn generate_p384_keypair(obj_id: [u8; 4], store: &mut ObjectStore) -> ApduResponse {
    let sk = p384::ecdsa::SigningKey::random(&mut OsRng);
    let pk = sk.verifying_key();
    store.insert(obj_id, SecureObject::ECKeyPair {
        curve: ECCurve::NistP384,
        private_key: sk.to_bytes().to_vec(),
        public_key: pk.to_encoded_point(false).as_bytes().to_vec(),
    });
    ApduResponse::success()
}

fn generate_ed25519_keypair(obj_id: [u8; 4], store: &mut ObjectStore) -> ApduResponse {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    store.insert(
        obj_id,
        SecureObject::ECKeyPair {
            curve: ECCurve::Ed25519,
            private_key: signing_key.to_bytes().to_vec(),
            public_key: verifying_key.to_bytes().to_vec(),
        },
    );

    ApduResponse::success()
}

fn import_ec_key(
    obj_id: [u8; 4],
    curve: ECCurve,
    private_key_data: &[u8],
    _key_type: u8,
    store: &mut ObjectStore,
) -> ApduResponse {
    // For import, just store the raw key data. We'll reconstruct
    // the signing key when needed for sign/verify operations.
    store.insert(
        obj_id,
        SecureObject::ECKeyPair {
            curve,
            private_key: private_key_data.to_vec(),
            public_key: vec![], // derived on demand
        },
    );
    ApduResponse::success()
}

fn p224_sign(private_key: &[u8], data: &[u8]) -> ApduResponse {
    let Ok(sk) = p224::ecdsa::SigningKey::from_bytes(private_key.into()) else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };
    let sig: p224::ecdsa::DerSignature = sk.sign(data);
    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, sig.as_bytes())])
}
fn p256_sign(private_key: &[u8], data: &[u8]) -> ApduResponse {
    let Ok(sk) = p256::ecdsa::SigningKey::from_bytes(private_key.into()) else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };
    let sig: p256::ecdsa::DerSignature = sk.sign(data);
    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, sig.as_bytes())])
}
fn p384_sign(private_key: &[u8], data: &[u8]) -> ApduResponse {
    let Ok(sk) = p384::ecdsa::SigningKey::from_bytes(private_key.into()) else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };
    let sig: p384::ecdsa::DerSignature = sk.sign(data);
    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, sig.as_bytes())])
}

fn p224_verify(private_key: &[u8], data: &[u8], sig_data: &[u8]) -> bool {
    let Ok(sk) = p224::ecdsa::SigningKey::from_bytes(private_key.into()) else { return false };
    let vk = sk.verifying_key();
    let Ok(sig) = p224::ecdsa::DerSignature::try_from(sig_data) else { return false };
    vk.verify(data, &sig).is_ok()
}
fn p256_verify(private_key: &[u8], data: &[u8], sig_data: &[u8]) -> bool {
    let Ok(sk) = p256::ecdsa::SigningKey::from_bytes(private_key.into()) else { return false };
    let vk = sk.verifying_key();
    let Ok(sig) = p256::ecdsa::DerSignature::try_from(sig_data) else { return false };
    vk.verify(data, &sig).is_ok()
}
fn p384_verify(private_key: &[u8], data: &[u8], sig_data: &[u8]) -> bool {
    let Ok(sk) = p384::ecdsa::SigningKey::from_bytes(private_key.into()) else { return false };
    let vk = sk.verifying_key();
    let Ok(sig) = p384::ecdsa::DerSignature::try_from(sig_data) else { return false };
    vk.verify(data, &sig).is_ok()
}

/// Handle signature generation (EC + RSA).
/// INS=Crypto, P1=Signature, P2=Sign
/// Tag1=key_id(4B), Tag2=algo(1B), Tag3=data
pub fn handle_sign(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let key_id = match tlv::find_tlv(&tlvs, TAG_1) {
        Some(t) if t.value.len() == 4 => {
            let mut id = [0u8; 4];
            id.copy_from_slice(&t.value);
            id
        }
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let algo = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if !t.value.is_empty() => t.value[0],
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let input_data = match tlv::find_tlv(&tlvs, TAG_3) {
        Some(t) => &t.value,
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    let key_obj = match store.get(&key_id) {
        Some(obj) => obj.clone(),
        None => return ApduResponse::error(SW_FILE_NOT_FOUND),
    };

    match &key_obj {
        SecureObject::ECKeyPair { curve: ECCurve::NistP224, private_key, .. } => {
            p224_sign(private_key, input_data)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP256, private_key, .. } => {
            p256_sign(private_key, input_data)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP384, private_key, .. } => {
            p384_sign(private_key, input_data)
        }
        SecureObject::ECKeyPair {
            curve: ECCurve::Ed25519,
            private_key,
            ..
        } => {
            if private_key.len() != 32 {
                return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(private_key);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
            use ed25519_dalek::Signer;
            let signature = signing_key.sign(input_data);
            ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &signature.to_bytes())])
        }
        SecureObject::RSAKeyPair { .. } => {
            super::rsa::handle_rsa_sign(&key_obj, algo, input_data)
        }
        _ => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}

/// Handle signature verification (EC + RSA).
/// INS=Crypto, P1=Signature, P2=Verify
/// EC: Tag1=key_id, Tag2=algo, Tag3=data, Tag5=signature
/// RSA: Tag1=key_id, Tag2=algo, Tag3=data, Tag3(bug)=signature
pub fn handle_verify(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let key_id = match tlv::find_tlv(&tlvs, TAG_1) {
        Some(t) if t.value.len() == 4 => {
            let mut id = [0u8; 4];
            id.copy_from_slice(&t.value);
            id
        }
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let algo = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if !t.value.is_empty() => t.value[0],
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    // Get data from Tag3. For RSA verify (driver bug), signature is also in Tag3.
    let tag3_entries = tlv::find_tlvs(&tlvs, TAG_3);
    let input_data = match tag3_entries.first() {
        Some(t) => t.value.clone(),
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    // Signature: try Tag5 first (correct per spec), then second Tag3 (driver bug)
    let sig_data = if let Some(t) = tlv::find_tlv(&tlvs, TAG_5) {
        t.value.clone()
    } else if tag3_entries.len() >= 2 {
        tag3_entries[1].value.clone()
    } else {
        return ApduResponse::error(SW_WRONG_DATA);
    };

    let key_obj = match store.get(&key_id) {
        Some(obj) => obj.clone(),
        None => return ApduResponse::error(SW_FILE_NOT_FOUND),
    };

    let result = match &key_obj {
        SecureObject::ECKeyPair { curve: ECCurve::NistP224, private_key, .. } => {
            return if p224_verify(private_key, &input_data, &sig_data) {
                ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &[0x01])])
            } else {
                ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &[0x02])])
            };
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP256, private_key, .. } => {
            p256_verify(private_key, &input_data, &sig_data)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP384, private_key, .. } => {
            p384_verify(private_key, &input_data, &sig_data)
        }
        SecureObject::ECKeyPair {
            curve: ECCurve::Ed25519,
            public_key,
            ..
        } => {
            if public_key.len() != 32 || sig_data.len() != 64 {
                return ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &[0x02])]);
            }
            let mut pk_bytes = [0u8; 32];
            pk_bytes.copy_from_slice(public_key);
            let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes) else {
                return ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &[0x02])]);
            };
            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&sig_data);
            let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            use ed25519_dalek::Verifier;
            verifying_key.verify(&input_data, &signature).is_ok()
        }
        SecureObject::RSAKeyPair { .. } => {
            return super::rsa::handle_rsa_verify(&key_obj, algo, &input_data, &sig_data);
        }
        _ => {
            return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
        }
    };

    let result_byte = if result { 0x01 } else { 0x02 };
    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &[result_byte])])
}

/// Handle ECDH shared secret generation.
/// INS=Crypto, P1=EC, P2=DH(0x0F)
/// Tag1=privateKeyID(4B), Tag2=peerPublicKey, Tag7=sharedSecretOutputID(4B)
/// The shared secret is stored as a binary object at sharedSecretOutputID.
pub fn handle_ecdh(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let key_id = match tlv::find_tlv(&tlvs, TAG_1) {
        Some(t) if t.value.len() == 4 => {
            let mut id = [0u8; 4];
            id.copy_from_slice(&t.value);
            id
        }
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let peer_pubkey = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if !t.value.is_empty() => &t.value,
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let output_id = match tlv::find_tlv(&tlvs, TAG_7) {
        Some(t) if t.value.len() == 4 => {
            let mut id = [0u8; 4];
            id.copy_from_slice(&t.value);
            id
        }
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let key_obj = match store.get(&key_id) {
        Some(obj) => obj.clone(),
        None => return ApduResponse::error(SW_FILE_NOT_FOUND),
    };

    let shared_secret = match &key_obj {
        SecureObject::ECKeyPair { curve: ECCurve::NistP224, private_key, .. } => {
            p224_ecdh(private_key, peer_pubkey)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP256, private_key, .. } => {
            p256_ecdh(private_key, peer_pubkey)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP384, private_key, .. } => {
            p384_ecdh(private_key, peer_pubkey)
        }
        _ => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    match shared_secret {
        Some(secret) => {
            // Optionally reverse endianness if P2 indicates DH_REVERSE
            let secret = if apdu.p2 == 0x2F {
                secret.into_iter().rev().collect()
            } else {
                secret
            };
            store.insert(output_id, SecureObject::Binary { data: secret });
            ApduResponse::success()
        }
        None => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}

fn p224_ecdh(private_key: &[u8], peer_pubkey: &[u8]) -> Option<Vec<u8>> {
    let sk = p224::SecretKey::from_bytes(private_key.into()).ok()?;
    let peer_pk = p224::PublicKey::from_sec1_bytes(peer_pubkey).ok()?;
    let shared = p224::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer_pk.as_affine());
    Some(shared.raw_secret_bytes().to_vec())
}

fn p256_ecdh(private_key: &[u8], peer_pubkey: &[u8]) -> Option<Vec<u8>> {
    let sk = p256::SecretKey::from_bytes(private_key.into()).ok()?;
    let peer_pk = p256::PublicKey::from_sec1_bytes(peer_pubkey).ok()?;
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer_pk.as_affine());
    Some(shared.raw_secret_bytes().to_vec())
}

fn p384_ecdh(private_key: &[u8], peer_pubkey: &[u8]) -> Option<Vec<u8>> {
    let sk = p384::SecretKey::from_bytes(private_key.into()).ok()?;
    let peer_pk = p384::PublicKey::from_sec1_bytes(peer_pubkey).ok()?;
    let shared = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer_pk.as_affine());
    Some(shared.raw_secret_bytes().to_vec())
}
