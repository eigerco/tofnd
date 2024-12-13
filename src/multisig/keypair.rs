use crate::multisig::aleo_schnorr_signature::AleoSchnorrSignature;
use crate::{proto::Algorithm, TofndResult};
use anyhow::anyhow;
use tofn::{
    ecdsa, ed25519,
    sdk::api::{MessageDigest, SecretRecoveryKey},
};

use super::aleo_schnorr_signature::CurrentNetwork;

pub enum KeyPair {
    Ecdsa(ecdsa::KeyPair),
    Ed25519(ed25519::KeyPair),
    AleoSchnorr(AleoSchnorrSignature<CurrentNetwork>),
}

impl KeyPair {
    /// Create a new `KeyPair` from the provided `SecretRecoveryKey` and `session_nonce` deterministically, for the given `algorithm`.
    pub fn new(
        secret_recovery_key: &SecretRecoveryKey,
        session_nonce: &[u8],
        algorithm: Algorithm,
    ) -> TofndResult<Self> {
        Ok(match algorithm {
            Algorithm::Ecdsa => {
                let key_pair = ecdsa::keygen(secret_recovery_key, session_nonce)
                    .map_err(|_| anyhow!("Cannot generate keypair"))?;

                Self::Ecdsa(key_pair)
            }
            Algorithm::Ed25519 => {
                let key_pair = ed25519::keygen(secret_recovery_key, session_nonce)
                    .map_err(|_| anyhow!("Cannot generate keypair"))?;

                Self::Ed25519(key_pair)
            }
            Algorithm::AleoSchnorr => {
                // TODO: Private key is hard-coded, we need to do this the right way
                let s = "APrivateKey1zkp59qjQHrFAmXuQHfuL6935YqGhRmoxVNZbh7GZqGsWrmg";
                Self::AleoSchnorr(AleoSchnorrSignature::new(s)?)
            }
        })
    }

    pub fn encoded_verifying_key(&self) -> Vec<u8> {
        match self {
            Self::Ecdsa(key_pair) => key_pair.encoded_verifying_key().into(),
            Self::Ed25519(key_pair) => key_pair.encoded_verifying_key().into(),
            Self::AleoSchnorr(account) => account.address().to_string().into_bytes(),
        }
    }

    pub fn sign(&self, msg_to_sign: &MessageDigest) -> TofndResult<Vec<u8>> {
        match self {
            Self::Ecdsa(key_pair) => ecdsa::sign(key_pair.signing_key(), msg_to_sign),
            Self::Ed25519(key_pair) => ed25519::sign(key_pair, msg_to_sign),
            Self::AleoSchnorr(account) => Ok(account.sign_bytes(msg_to_sign.as_ref())?),
        }
        .map_err(|e| anyhow!("signing failed: {e:?}"))
    }
}
