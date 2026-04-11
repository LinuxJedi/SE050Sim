/// Command dispatch: routes parsed APDUs to the appropriate handler
/// based on CLA, INS (masked with 0x1F), P1, and P2.

use crate::apdu::*;
use crate::handlers;
use crate::object_store::ObjectStore;

pub fn dispatch(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    // SELECT command (CLA=0x00, INS=0xA4)
    if apdu.cla == 0x00 && apdu.ins == 0xA4 {
        return handlers::session::handle_select(apdu, store);
    }

    // All other SE050 proprietary commands use CLA=0x80 or 0x84
    if apdu.cla != 0x80 && apdu.cla != 0x84 {
        return ApduResponse::error(SW_INS_NOT_SUPPORTED);
    }

    let base_ins = apdu.base_ins();
    let cred_type = apdu.cred_type();

    match base_ins {
        INS_WRITE => match cred_type {
            P1_EC => handlers::ec::handle_write_ec_key(apdu, store),
            P1_RSA => handlers::rsa::handle_write_rsa_key(apdu, store),
            P1_AES => handlers::aes::handle_write_aes_key(apdu, store),
            P1_BINARY | P1_USERID | P1_COUNTER => {
                handlers::object_mgmt::handle_write(apdu, store)
            }
            _ => ApduResponse::error(SW_WRONG_P1P2),
        },

        INS_READ => handlers::object_mgmt::handle_read(apdu, store),

        INS_CRYPTO => match (cred_type, apdu.p2) {
            (P1_SIGNATURE, P2_SIGN) => handlers::ec::handle_sign(apdu, store),
            (P1_SIGNATURE, P2_VERIFY) => handlers::ec::handle_verify(apdu, store),
            (P1_CIPHER, P2_ENCRYPT_ONESHOT) => {
                handlers::aes::handle_encrypt_oneshot(apdu, store)
            }
            (P1_CIPHER, P2_DECRYPT_ONESHOT) => {
                handlers::aes::handle_decrypt_oneshot(apdu, store)
            }
            (P1_RSA, P2_ENCRYPT_ONESHOT) => {
                handlers::rsa::handle_rsa_encrypt(apdu, store)
            }
            (P1_RSA, P2_DECRYPT_ONESHOT) => {
                handlers::rsa::handle_rsa_decrypt(apdu, store)
            }
            (P1_DEFAULT, P2_ONESHOT) => handlers::digest::handle_digest_oneshot(apdu, store),
            _ => ApduResponse::error(SW_WRONG_P1P2),
        },

        INS_MGMT => {
            match apdu.p2 {
                P2_VERSION | P2_MEMORY | P2_RANDOM | P2_DELETE_ALL => {
                    handlers::management::handle(apdu, store)
                }
                P2_EXIST | P2_DELETE_OBJECT => {
                    handlers::object_mgmt::handle_mgmt(apdu, store)
                }
                _ => ApduResponse::error(SW_WRONG_P1P2),
            }
        }

        _ => ApduResponse::error(SW_INS_NOT_SUPPORTED),
    }
}
