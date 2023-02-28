//! Implementation of AEAD using Nettle cryptographic library.
use std::cmp::Ordering;

use nettle::{aead::{self, Aead as _}, cipher};

use crate::{Error, Result};

use crate::crypto::aead::{Aead, CipherOp};
use crate::crypto::mem::secure_cmp;
use crate::seal;
use crate::types::{AEADAlgorithm, SymmetricAlgorithm};

/// Disables authentication checks.
///
/// This is DANGEROUS, and is only useful for debugging problems with
/// malformed AEAD-encrypted messages.
const DANGER_DISABLE_AUTHENTICATION: bool = false;

impl<T: nettle::aead::Aead> seal::Sealed for T {}
impl<T: nettle::aead::Aead> Aead for T {
    fn encrypt_seal(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len(), src.len() + self.digest_size());
        self.encrypt(dst, src);
        self.digest(&mut dst[src.len()..]);
        Ok(())
    }
    fn decrypt_verify(&mut self, dst: &mut [u8], src: &[u8], digest: &[u8]) -> Result<()> {
        self.decrypt(dst, src);
        let mut chunk_digest = vec![0u8; self.digest_size()];

        self.digest(&mut chunk_digest);
        if secure_cmp(&chunk_digest[..], digest)
             != Ordering::Equal && ! DANGER_DISABLE_AUTHENTICATION
            {
                 return Err(Error::ManipulatedMessage.into());
            }
        Ok(())
    }
    fn digest_size(&self) -> usize {
        self.digest_size()
    }
}

impl AEADAlgorithm {
    pub(crate) fn context(
        &self,
        sym_algo: SymmetricAlgorithm,
        key: &[u8],
        aad: &[u8],
        nonce: &[u8],
        _op: CipherOp,
    ) -> Result<Box<dyn Aead>> {
        match self {
            AEADAlgorithm::EAX => match sym_algo {
                SymmetricAlgorithm::AES128 => {
                    let mut ctx =
                        aead::Eax::<cipher::Aes128>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::AES192 => {
                    let mut ctx =
                        aead::Eax::<cipher::Aes192>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::AES256 => {
                    let mut ctx =
                        aead::Eax::<cipher::Aes256>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::Twofish => {
                    let mut ctx =
                        aead::Eax::<cipher::Twofish>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::Camellia128 => {
                    let mut ctx =
                        aead::Eax::<cipher::Camellia128>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::Camellia192 => {
                    let mut ctx =
                        aead::Eax::<cipher::Camellia192>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::Camellia256 => {
                    let mut ctx =
                        aead::Eax::<cipher::Camellia256>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                _ => Err(Error::UnsupportedSymmetricAlgorithm(sym_algo).into()),
            },
            _ => Err(Error::UnsupportedAEADAlgorithm(*self).into()),
        }
    }
}
