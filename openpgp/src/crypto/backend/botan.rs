//! Implementation of Sequoia crypto API using the Botan cryptographic library.

use crate::{
    Result,
    crypto::SessionKey,
    types::*,
};

pub mod aead;
pub mod asymmetric;
pub mod ecdh;
pub mod hash;
pub mod symmetric;

/// Returns a short, human-readable description of the backend.
pub fn backend() -> String {
    "Botan".to_string()
}

/// Fills the given buffer with random data.
pub fn random(buf: &mut [u8]) {
    let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
    rng.fill(buf).unwrap();
}

/// HKDF instantiated with SHA256.
///
/// Used to derive message keys from session keys, and key
/// encapsulating keys from S2K mechanisms.  In both cases, using a
/// KDF that includes algorithm information in the given `info`
/// provides key space separation between cipher algorithms and modes.
///
/// `salt`, if given, SHOULD be 32 bytes of salt matching the digest
/// size of the hash function.  If it is not give, 32 zeros are used
/// instead.
///
/// `okm` must not be larger than 255 * 32 (the size of the hash
/// digest).
pub fn hkdf_sha256(ikm: &SessionKey, salt: Option<&[u8]>, info: &[u8],
                   okm: &mut SessionKey)
                   -> Result<()>
{
    assert!(okm.len() <= 255 * 32);

    const NO_SALT: [u8; 32] = [0; 32];
    let salt = salt.unwrap_or(&NO_SALT);

    // XXX: It'd be nice to write that directly to `okm`, but botan-rs
    // does not have such an interface.
    let okm_heap: SessionKey =
        botan::kdf("HKDF(SHA-256)", okm.len(), &*ikm, salt, info)?
        .into();

    // XXX: Now copy the secret.
    let l = okm.len().min(okm_heap.len());
    okm[..l].copy_from_slice(&okm_heap[..l]);

    Ok(())
}

impl PublicKeyAlgorithm {
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match &self {
            RSAEncryptSign | RSAEncrypt | RSASign | DSA | ECDH | ECDSA | EdDSA |
            ElGamalEncrypt | ElGamalEncryptSign
                => true,
            Private(_) | Unknown(_)
                => false,
        }
    }
}

impl Curve {
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        use self::Curve::*;
        match &self {
            NistP256 | NistP384 | NistP521 | Ed25519 | Cv25519 |
            BrainpoolP256 | BrainpoolP512
                => true,
            Unknown(_) if self.is_brainpoolp384() // XXX
                => true,
            Unknown(_)
                => false,
        }
    }
}

impl AEADAlgorithm {
    /// Returns the best AEAD mode supported by the backend.
    ///
    /// This SHOULD return OCB, which is the mandatory-to-implement
    /// algorithm and the most performing one, but fall back to any
    /// supported algorithm.
    pub(crate) const fn const_default() -> AEADAlgorithm {
        AEADAlgorithm::OCB
    }

    pub(crate) fn is_supported_by_backend(&self) -> bool {
        use self::AEADAlgorithm::*;
        match &self {
            EAX | OCB | GCM
                => true,
            Private(_) | Unknown(_)
                => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn supports_symmetric_algo(&self, algo: &SymmetricAlgorithm) -> bool {
        match &self {
            AEADAlgorithm::EAX =>
                match algo {
                    SymmetricAlgorithm::AES128 |
                    SymmetricAlgorithm::AES192 |
                    SymmetricAlgorithm::AES256 |
                    SymmetricAlgorithm::Twofish |
                    SymmetricAlgorithm::Camellia128 |
                    SymmetricAlgorithm::Camellia192 |
                    SymmetricAlgorithm::Camellia256 => true,
                    _ => false,
                },
            AEADAlgorithm::OCB =>
                match algo {
                    SymmetricAlgorithm::AES128 |
                    SymmetricAlgorithm::AES192 |
                    SymmetricAlgorithm::AES256 |
                    SymmetricAlgorithm::Twofish |
                    SymmetricAlgorithm::Camellia128 |
                    SymmetricAlgorithm::Camellia192 |
                    SymmetricAlgorithm::Camellia256 => true,
                    _ => false,
                },
            _ => false
        }
    }
}
