use crate::{proto::Algorithm, TofndResult};
use anyhow::anyhow;
use tofn::{
    aleo_schnorr, ecdsa, ed25519,
    sdk::api::{MessageDigest, SecretRecoveryKey},
};

const _: () = {
    let feature_count = 0
        + if cfg!(feature = "aleo-testnet") { 1 } else { 0 }
        + if cfg!(feature = "aleo-mainnet") { 1 } else { 0 }
        + if cfg!(feature = "aleo-canary") { 1 } else { 0 };

    assert!(
        feature_count == 1,
        "Exactly one of 'aleo-testnet', 'aleo-mainnet', or 'aleo-canary' must be enabled"
    );
};

#[cfg(feature = "aleo-testnet")]
pub type CurrentNetwork = snarkvm_console_network::TestnetV0;

#[cfg(feature = "aleo-mainnet")]
pub type CurrentNetwork = snarkvm_console_network::MainnetV0;

#[cfg(feature = "aleo-canary")]
pub type CurrentNetwork = snarkvm_console_network::CanaryV0;

pub enum KeyPair {
    Ecdsa(ecdsa::KeyPair),
    Ed25519(ed25519::KeyPair),
    AleoSchnorr(aleo_schnorr::KeyPair<CurrentNetwork>),
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
                let key_pair = tofn::aleo_schnorr::keygen::<CurrentNetwork>(
                    secret_recovery_key,
                    session_nonce,
                )
                .map_err(|_| anyhow!("Cannot generate keypair"))?;

                Self::AleoSchnorr(key_pair)
            }
        })
    }

    pub fn encoded_verifying_key(&self) -> TofndResult<Vec<u8>> {
        match self {
            Self::Ecdsa(key_pair) => Ok(key_pair.encoded_verifying_key().into()),
            Self::Ed25519(key_pair) => Ok(key_pair.encoded_verifying_key().into()),
            Self::AleoSchnorr(key_pair) => {
                let bytes = key_pair
                    .encoded_verifying_key()
                    .map_err(|_| anyhow!("Failed to get aleo schnorr verify key"))?;

                Ok(bytes.to_vec())
            }
        }
    }

    pub fn sign(&self, msg_to_sign: &MessageDigest) -> TofndResult<Vec<u8>> {
        match self {
            Self::Ecdsa(key_pair) => ecdsa::sign(key_pair.signing_key(), msg_to_sign),
            Self::Ed25519(key_pair) => ed25519::sign(key_pair, msg_to_sign),
            Self::AleoSchnorr(key_pair) => aleo_schnorr::sign(key_pair, msg_to_sign),
        }
        .map_err(|e| anyhow!("signing failed: {e:?}"))
    }
}
