use crate::apdu::*;
use crate::object_store::ObjectStore;
use crate::tlv::{self, Tlv, TAG_1, TAG_2};
use sha2::Digest;

/// Handle Digest OneShot command.
/// INS=Crypto, P1=Default, P2=Oneshot
/// Tag1=digest_mode(1B), Tag2=data_to_hash
pub fn handle_digest_oneshot(apdu: &ParsedApdu, _store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let digest_mode = match tlv::find_tlv(&tlvs, TAG_1) {
        Some(t) if !t.value.is_empty() => t.value[0],
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let data = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) => &t.value,
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    // Digest mode constants (from AN12413 Table 35)
    let hash = match digest_mode {
        0x04 => {
            // SHA-256
            sha2::Sha256::digest(data).to_vec()
        }
        0x05 => {
            // SHA-384
            sha2::Sha384::digest(data).to_vec()
        }
        0x06 => {
            // SHA-512
            sha2::Sha512::digest(data).to_vec()
        }
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &hash)])
}
