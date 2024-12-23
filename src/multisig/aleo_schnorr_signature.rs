use std::str::FromStr as _;

use rand::SeedableRng as _;
use rand_chacha::ChaChaRng;
use snarkos_account::Account;
use snarkvm::prelude::Signature;
use snarkvm::prelude::{Network, PrivateKey};

use crate::TofndResult;

pub type CurrentNetwork = snarkvm::prelude::TestnetV0;

#[derive(Debug)]
pub struct AleoSchnorrSignature<N: Network> {
    aleo_account: Account<N>,
}

impl<N: Network> AleoSchnorrSignature<N> {
    pub fn new(private_key: PrivateKey<N>) -> TofndResult<Self> {
        let aleo_account = Account::try_from(private_key)
            .map_err(|e| anyhow::anyhow!("Cannot generate aleo address: {e:?}"))?;

        Ok(Self { aleo_account })
    }

    pub fn sign_bytes(&self, msg: &[u8]) -> TofndResult<Signature<N>> {
        self.aleo_account
            .sign_bytes(msg, &mut ChaChaRng::from_entropy())
            .map_err(|e| anyhow::anyhow!("Failed to sign aleo data: {e:?}"))
    }

    pub fn address(&self) -> String {
        self.aleo_account.address().to_string()
    }

    #[cfg(test)]
    pub fn verify(address: &str, signature: &Signature<N>, message: &[u8]) -> TofndResult<bool> {
        use snarkvm::prelude::Address;

        let address = Address::<N>::from_str(address)
            .map_err(|e| anyhow::anyhow!("Cannot generate aleo address: {e:?}"))?;

        Ok(signature.verify_bytes(&address, message))
    }
}

// TODO: this should moved into tofn crate
#[allow(dead_code)]
pub fn keygen<N: Network>() -> TofndResult<PrivateKey<N>> {
    PrivateKey::<N>::new(&mut ChaChaRng::from_entropy())
        .map_err(|e| anyhow::anyhow!("Cannot generate aleo private key: {e:?}"))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_sign_verify() {
        let private_key = "APrivateKey1zkp59qjQHrFAmXuQHfuL6935YqGhRmoxVNZbh7GZqGsWrmg";
        let private_key = PrivateKey::<CurrentNetwork>::from_str(private_key).unwrap();
        let aleo_shnorr = AleoSchnorrSignature::<CurrentNetwork>::new(private_key).unwrap();
        let message = [
            0xa9, 0x43, 0x2b, 0x0d, 0x1a, 0x23, 0xfa, 0x47, 0x7a, 0x1c, 0xe3, 0x7c, 0xe6, 0xfa,
            0x6f, 0x78, 0x8a, 0x43, 0xce, 0x72, 0xbf, 0xf2, 0x86, 0x3e, 0x39, 0xcc, 0x54, 0x27,
            0x0f, 0xc6, 0x23, 0x58,
        ];

        let signature = aleo_shnorr.sign_bytes(&message).unwrap();
        let address = aleo_shnorr.address();
        assert!(
            AleoSchnorrSignature::<CurrentNetwork>::verify(&address, &signature, &message).unwrap()
        )
    }
}
