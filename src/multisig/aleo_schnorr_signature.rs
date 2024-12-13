use std::str::FromStr as _;

use rand::SeedableRng as _;
use rand_chacha::ChaChaRng;
use snarkos_account::Account;
use snarkvm::prelude::Address;
use snarkvm::prelude::Signature;
use snarkvm::prelude::{FromBytes as _, Network, PrivateKey, ToBytes};

use crate::TofndResult;

pub type CurrentNetwork = snarkvm::prelude::TestnetV0;

#[derive(Debug)]
pub struct AleoSchnorrSignature<N: Network> {
    aleo_account: Account<N>,
}

impl<N: Network> AleoSchnorrSignature<N> {
    pub fn new(private_key: &str) -> TofndResult<Self> {
        let private_key = PrivateKey::from_str(private_key)
            .map_err(|e| anyhow::anyhow!("Cannot generate aleo private key: {e:?}"))?;

        let aleo_account = Account::try_from(private_key)
            .map_err(|e| anyhow::anyhow!("Cannot generate aleo address: {e:?}"))?;

        Ok(Self { aleo_account })
    }

    pub fn sign_bytes(&self, msg: &[u8]) -> TofndResult<Vec<u8>> {
        self.aleo_account
            .sign_bytes(msg, &mut ChaChaRng::from_entropy())
            .map_err(|e| anyhow::anyhow!("Failed to sign aleo data: {e:?}"))?
            .to_bytes_le()
            .map_err(|e| anyhow::anyhow!("Failed to translate aleo signiture to bytes: {e:?}"))
    }

    pub fn address(&self) -> String {
        self.aleo_account.address().to_string()
    }

    #[cfg(test)]
    pub fn verify(address: &str, signature: &[u8], message: &[u8]) -> TofndResult<bool> {
        let address = Address::<N>::from_str(address)
            .map_err(|e| anyhow::anyhow!("Cannot generate aleo address: {e:?}"))?;
        let signature = Signature::<N>::read_le(signature)
            .map_err(|e| anyhow::anyhow!("Cannot generate aleo signature type: {e:?}"))?;

        Ok(signature.verify_bytes(&address, message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let aleo_shnorr = AleoSchnorrSignature::<CurrentNetwork>::new(
            "APrivateKey1zkp59qjQHrFAmXuQHfuL6935YqGhRmoxVNZbh7GZqGsWrmg",
        ).unwrap();
        let message = [32u8; 32];

        let signature = aleo_shnorr.sign_bytes(&message).unwrap();
        let address = aleo_shnorr.address();
        assert!(AleoSchnorrSignature::<CurrentNetwork>::verify(
            &address, &signature, &message
        ).unwrap())
    }
}
