use crate::apdu::*;
use crate::object_store::types::{ECCurve, SecureObject};
use crate::object_store::ObjectStore;
use crate::tlv::{self, Tlv, TAG_1, TAG_2, TAG_3, TAG_5};

use p256::ecdsa::signature::Signer;
use p256::ecdsa::signature::Verifier;
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
            ECCurve::NistP256 => generate_p256_keypair(obj_id, store),
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

fn generate_p256_keypair(obj_id: [u8; 4], store: &mut ObjectStore) -> ApduResponse {
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_bytes = signing_key.to_bytes().to_vec();
    let public_bytes = verifying_key
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    store.insert(
        obj_id,
        SecureObject::ECKeyPair {
            curve: ECCurve::NistP256,
            private_key: private_bytes,
            public_key: public_bytes,
        },
    );

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
    key_type: u8,
    store: &mut ObjectStore,
) -> ApduResponse {
    match (curve.clone(), key_type) {
        (ECCurve::NistP256, P1_KEY_PAIR | P1_PRIVATE_KEY) => {
            let Ok(signing_key) = p256::ecdsa::SigningKey::from_bytes(
                p256::FieldBytes::from_slice(private_key_data),
            ) else {
                return ApduResponse::error(SW_WRONG_DATA);
            };
            let public_bytes = signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            store.insert(
                obj_id,
                SecureObject::ECKeyPair {
                    curve,
                    private_key: private_key_data.to_vec(),
                    public_key: public_bytes,
                },
            );
            ApduResponse::success()
        }
        _ => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
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
        SecureObject::ECKeyPair {
            curve: ECCurve::NistP256,
            private_key,
            ..
        } => {
            let Ok(signing_key) = p256::ecdsa::SigningKey::from_bytes(
                p256::FieldBytes::from_slice(private_key),
            ) else {
                return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
            };
            let signature: p256::ecdsa::DerSignature = signing_key.sign(input_data);
            ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, signature.as_bytes())])
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
        SecureObject::ECKeyPair {
            curve: ECCurve::NistP256,
            private_key,
            ..
        } => {
            let Ok(signing_key) = p256::ecdsa::SigningKey::from_bytes(
                p256::FieldBytes::from_slice(private_key),
            ) else {
                return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
            };
            let verifying_key = signing_key.verifying_key();
            let Ok(signature) =
                p256::ecdsa::DerSignature::try_from(sig_data.as_slice())
            else {
                return ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &[0x02])]);
            };
            verifying_key.verify(&input_data, &signature).is_ok()
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
