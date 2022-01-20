//! Implementation of Sequoia crypto API using pure Rust cryptographic
//! libraries.

use crate::Result;
use crate::types::*;
use crate::crypto::SessionKey;

pub mod aead;
pub mod asymmetric;
pub mod ecdh;
pub mod hash;
pub mod symmetric;

/// Returns a short, human-readable description of the backend.
pub fn backend() -> String {
    // XXX: can we include features and the version?
    "RustCrypto".to_string()
}

/// Fills the given buffer with random data.
pub fn random(buf: &mut [u8]) {
    use rand07::rngs::OsRng;
    use rand07::RngCore;

    OsRng.fill_bytes(buf)
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
    use hkdf::Hkdf;
    use sha2::Sha256;

    Ok(Hkdf::<Sha256>::new(salt, &ikm).expand(info, okm)
       .map_err(|e| crate::Error::InvalidOperation(e.to_string()))?)
}

impl PublicKeyAlgorithm {
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match &self {
            RSAEncryptSign | RSAEncrypt | RSASign | ECDH | EdDSA | ECDSA
                => true,
            DSA
                => false,
            ElGamalEncrypt | ElGamalEncryptSign | Private(_) | Unknown(_)
                => false,
        }
    }
}

impl Curve {
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        use self::Curve::*;
        match &self {
            NistP256
                => true,
            NistP384 | NistP521
                => false,
            Ed25519 | Cv25519
                => true,
            BrainpoolP256 | BrainpoolP512 | Unknown(_)
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
        AEADAlgorithm::EAX
    }

    pub(crate) fn is_supported_by_backend(&self) -> bool {
        use self::AEADAlgorithm::*;
        match &self {
            EAX => true,
            OCB => false,
            GCM => false,
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
                    // XXX: Skipping Twofish until Twofish implements Clone
                    // SymmetricAlgorithm::Twofish |
                    SymmetricAlgorithm::Camellia128 |
                    SymmetricAlgorithm::Camellia192 |
                    SymmetricAlgorithm::Camellia256 => true,
                    _ => false,
                },
            _ => false
        }
    }
}
