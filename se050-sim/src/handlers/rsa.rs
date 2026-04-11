use crate::apdu::*;
use crate::object_store::types::SecureObject;
use crate::object_store::ObjectStore;
use crate::tlv::{self, Tlv, TAG_1, TAG_2, TAG_3};

use rand::rngs::OsRng;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::signature::SignatureEncoding;
use sha2::digest::{const_oid::AssociatedOid, Digest, FixedOutputReset};

/// Handle WRITE RSA key (key generation).
/// P1=RSA(0x02)|KeyPair(0x60), P2=RAW(0x4F)
/// Tag1=obj_id(4B), Tag2=key_size(2B big-endian, in bits)
pub fn handle_write_rsa_key(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let obj_id = match tlv::find_tlv(&tlvs, TAG_1) {
        Some(t) if t.value.len() == 4 => {
            let mut id = [0u8; 4];
            id.copy_from_slice(&t.value);
            id
        }
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let key_size_bits = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if t.value.len() == 2 => ((t.value[0] as u16) << 8) | (t.value[1] as u16),
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let key_size_usize = key_size_bits as usize;
    if ![1024, 2048, 3072, 4096].contains(&key_size_usize) {
        return ApduResponse::error(SW_WRONG_DATA);
    }

    let private_key = match RsaPrivateKey::new(&mut OsRng, key_size_usize) {
        Ok(k) => k,
        Err(_) => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    let der = match private_key.to_pkcs1_der() {
        Ok(d) => d.as_bytes().to_vec(),
        Err(_) => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    store.insert(
        obj_id,
        SecureObject::RSAKeyPair {
            key_size_bits,
            private_key_der: der,
        },
    );

    ApduResponse::success()
}

/// Handle RSA sign command.
/// Tag1=key_id(4B), Tag2=algo(1B), Tag3=data
pub fn handle_rsa_sign(
    key_obj: &SecureObject,
    algo: u8,
    input_data: &[u8],
) -> ApduResponse {
    let SecureObject::RSAKeyPair { private_key_der, .. } = key_obj else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };

    let private_key = match RsaPrivateKey::from_pkcs1_der(private_key_der) {
        Ok(k) => k,
        Err(_) => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    let signature = match algo {
        // PKCS#1 v1.5 variants
        0x28 => pkcs1v15_sign::<sha2::Sha256>(&private_key, input_data),
        0x29 => pkcs1v15_sign::<sha2::Sha384>(&private_key, input_data),
        0x2A => pkcs1v15_sign::<sha2::Sha512>(&private_key, input_data),
        // PSS variants
        0x2C => pss_sign::<sha2::Sha256>(&private_key, input_data),
        0x2D => pss_sign::<sha2::Sha384>(&private_key, input_data),
        0x2E => pss_sign::<sha2::Sha512>(&private_key, input_data),
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    match signature {
        Some(sig) => ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &sig)]),
        None => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}

/// Handle RSA verify command.
pub fn handle_rsa_verify(
    key_obj: &SecureObject,
    algo: u8,
    data: &[u8],
    signature: &[u8],
) -> ApduResponse {
    let SecureObject::RSAKeyPair { private_key_der, .. } = key_obj else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };

    let private_key = match RsaPrivateKey::from_pkcs1_der(private_key_der) {
        Ok(k) => k,
        Err(_) => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };
    let public_key = RsaPublicKey::from(&private_key);

    let ok = match algo {
        // PKCS#1 v1.5 variants
        0x28 => pkcs1v15_verify::<sha2::Sha256>(&public_key, data, signature),
        0x29 => pkcs1v15_verify::<sha2::Sha384>(&public_key, data, signature),
        0x2A => pkcs1v15_verify::<sha2::Sha512>(&public_key, data, signature),
        // PSS variants
        0x2C => pss_verify::<sha2::Sha256>(&public_key, data, signature),
        0x2D => pss_verify::<sha2::Sha384>(&public_key, data, signature),
        0x2E => pss_verify::<sha2::Sha512>(&public_key, data, signature),
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let result_byte = if ok { 0x01 } else { 0x02 };
    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &[result_byte])])
}

/// Handle RSA encrypt oneshot.
/// P1=RSA(0x02), P2=EncryptOneshot(0x37)
/// Tag1=key_id(4B), Tag2=algo(1B), Tag3=plaintext
pub fn handle_rsa_encrypt(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
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

    let plaintext = match tlv::find_tlv(&tlvs, TAG_3) {
        Some(t) => &t.value,
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    let key_obj = match store.get(&key_id) {
        Some(obj) => obj.clone(),
        None => return ApduResponse::error(SW_FILE_NOT_FOUND),
    };

    let SecureObject::RSAKeyPair { private_key_der, .. } = &key_obj else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };

    let private_key = match RsaPrivateKey::from_pkcs1_der(private_key_der) {
        Ok(k) => k,
        Err(_) => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };
    let public_key = RsaPublicKey::from(&private_key);

    let ciphertext = match algo {
        0x0A => public_key.encrypt(&mut OsRng, Pkcs1v15Encrypt, plaintext).ok(),
        0x0F => {
            use rsa::Oaep;
            public_key
                .encrypt(&mut OsRng, Oaep::new::<sha2::Sha256>(), plaintext)
                .ok()
        }
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    match ciphertext {
        Some(ct) => ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &ct)]),
        None => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}

/// Handle RSA decrypt oneshot.
/// P1=RSA(0x02), P2=DecryptOneshot(0x38)
/// Tag1=key_id(4B), Tag2=algo(1B), Tag3=ciphertext
pub fn handle_rsa_decrypt(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
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

    let ciphertext = match tlv::find_tlv(&tlvs, TAG_3) {
        Some(t) => &t.value,
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    let key_obj = match store.get(&key_id) {
        Some(obj) => obj.clone(),
        None => return ApduResponse::error(SW_FILE_NOT_FOUND),
    };

    let SecureObject::RSAKeyPair { private_key_der, .. } = &key_obj else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };

    let private_key = match RsaPrivateKey::from_pkcs1_der(private_key_der) {
        Ok(k) => k,
        Err(_) => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    let plaintext = match algo {
        0x0A => private_key.decrypt(Pkcs1v15Encrypt, ciphertext).ok(),
        0x0F => {
            use rsa::Oaep;
            private_key
                .decrypt(Oaep::new::<sha2::Sha256>(), ciphertext)
                .ok()
        }
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    match plaintext {
        Some(pt) => ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &pt)]),
        None => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}

// ---- Internal crypto helpers ----

fn pkcs1v15_sign<D>(private_key: &RsaPrivateKey, data: &[u8]) -> Option<Vec<u8>>
where
    D: Digest + AssociatedOid,
{
    use rsa::signature::Signer;
    let signing_key = rsa::pkcs1v15::SigningKey::<D>::new(private_key.clone());
    let sig = signing_key.sign(data);
    Some(sig.to_vec())
}

fn pkcs1v15_verify<D>(public_key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> bool
where
    D: Digest + AssociatedOid,
{
    use rsa::signature::Verifier;
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<D>::new(public_key.clone());
    let Ok(sig) = rsa::pkcs1v15::Signature::try_from(signature) else {
        return false;
    };
    verifying_key.verify(data, &sig).is_ok()
}

fn pss_sign<D>(private_key: &RsaPrivateKey, data: &[u8]) -> Option<Vec<u8>>
where
    D: Digest + FixedOutputReset,
{
    use rsa::signature::RandomizedSigner;
    let signing_key = rsa::pss::SigningKey::<D>::new(private_key.clone());
    let sig = signing_key.sign_with_rng(&mut OsRng, data);
    Some(sig.to_bytes().to_vec())
}

fn pss_verify<D>(public_key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> bool
where
    D: Digest + FixedOutputReset,
{
    use rsa::signature::Verifier;
    let verifying_key = rsa::pss::VerifyingKey::<D>::new(public_key.clone());
    let Ok(sig) = rsa::pss::Signature::try_from(signature) else {
        return false;
    };
    verifying_key.verify(data, &sig).is_ok()
}
