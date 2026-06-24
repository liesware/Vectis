use crate::error::DynError;
use crate::ops::contracts::{PublicDerKey, PublicKeys, PublicRawKey};
use crate::ops::keys::{self, KeysDbState, LoadedOpsKey};

pub use crate::ops::contracts::PublicKeysOutput;

pub fn public_keys(loaded_key: &LoadedOpsKey) -> PublicKeysOutput {
    let keys = loaded_key.keys();

    PublicKeysOutput {
        info: loaded_key.aad().to_string(),
        keys: PublicKeys {
            eddsa: PublicDerKey {
                alg: keys.eddsa().variant().to_string(),
                public_key_der_hex: keys.eddsa().public_key_der_hex().to_string(),
            },
            xecdh: PublicRawKey {
                alg: keys.xecdh().variant().to_string(),
                public_key_hex: keys.xecdh().public_key_hex().to_string(),
            },
            ml_dsa: PublicDerKey {
                alg: keys.ml_dsa().variant().to_string(),
                public_key_der_hex: keys.ml_dsa().public_key_der_hex().to_string(),
            },
            ml_kem: PublicDerKey {
                alg: keys.ml_kem().variant().to_string(),
                public_key_der_hex: keys.ml_kem().public_key_der_hex().to_string(),
            },
        },
    }
}

pub fn public_keys_from_state(
    keys_db_state: &KeysDbState,
    id: &str,
) -> Result<PublicKeysOutput, DynError> {
    let loaded_key = keys::get_loaded_key(keys_db_state, id)?;

    Ok(public_keys(loaded_key))
}
