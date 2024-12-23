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
                // TODO: the following keygen function should be used. We need to generate the key
                // using secret_recovery_key and session_nonce to get the same keypair
                // let private_key = super::aleo_schnorr_signature::keygen::<CurrentNetwork>()?;
                let private_key = "APrivateKey1zkp59qjQHrFAmXuQHfuL6935YqGhRmoxVNZbh7GZqGsWrmg";
                let private_key = <snarkvm::prelude::PrivateKey::<CurrentNetwork> as std::str::FromStr>::from_str(private_key).unwrap();
                Self::AleoSchnorr(AleoSchnorrSignature::new(private_key)?)
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
            Self::AleoSchnorr(account) => {
                let sign = account.sign_bytes(msg_to_sign.as_ref())?;
                Ok(sign.to_string().as_bytes().to_vec())
            }
        }
        .map_err(|e| anyhow!("signing failed: {e:?}"))
    }
}
