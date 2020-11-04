//! Asymmetric crypto operations.

use async_trait::async_trait;

use crate::packet::{self, key, Key};
use crate::crypto::SessionKey;
use crate::crypto::mpi;
use crate::types::HashAlgorithm;

use crate::Result;

/// Creates a signature.
///
/// Used in the streaming [`Signer`], the methods binding components
/// to certificates (e.g. [`UserID::bind`]), [`SignatureBuilder`]'s
/// signing functions (e.g. [`SignatureBuilder::sign_standalone`]),
/// and likely many more places.
///
///   [`Signer`]: ../serialize/stream/struct.Signer.html
///   [`UserID::bind`]: ../packet/struct.UserID.html#method.bind
///   [`SignatureBuilder`]: ../packet/signature/struct.SignatureBuilder.html
///   [`SignatureBuilder::sign_standalone`]: ../packet/signature/struct.SignatureBuilder.html#method.sign_standalone
///
/// This is a low-level mechanism to produce an arbitrary OpenPGP
/// signature.  Using this trait allows Sequoia to perform all
/// operations involving signing to use a variety of secret key
/// storage mechanisms (e.g. smart cards).
///
/// A signer consists of the public key and a way of creating a
/// signature.  This crate implements `Signer` for [`KeyPair`], which
/// is a tuple containing the public and unencrypted secret key in
/// memory.  Other crates my provide their own implementations of
/// `Signer` to utilize keys stored in various places.  Currently, the
/// following implementations exist:
///
///   - [`KeyPair`]: In-memory keys.
///   - [`sequoia_rpc::gnupg::KeyPair`]: Connects to the `gpg-agent`.
///
///   [`KeyPair`]: struct.KeyPair.html
///   [`sequoia_rpc::gnupg::KeyPair`]: https://docs.sequoia-pgp.org/sequoia_ipc/gnupg/struct.KeyPair.html
#[async_trait(?Send)]
pub trait Signer {
    /// Returns a reference to the public key.
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole>;

    /// Creates a signature over the `digest` produced by `hash_algo`.
    async fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8])
            -> Result<mpi::Signature>;
}

//#[async_trait]
//impl Signer for Box<dyn Signer> {
//    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
//        self.as_ref().public()
//    }
//
//    async fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8])
//                  -> Result<mpi::Signature> {
//        unimplemented!()
//        //self.as_mut().await.sign(hash_algo, digest)
//    }
//}

/// Decrypts a message.
///
/// Used by [`PKESK::decrypt`] to decrypt session keys.
///
///   [`PKESK::decrypt`]: ../packet/enum.PKESK.html#method.decrypt
///
/// This is a low-level mechanism to decrypt an arbitrary OpenPGP
/// ciphertext.  Using this trait allows Sequoia to perform all
/// operations involving decryption to use a variety of secret key
/// storage mechanisms (e.g. smart cards).
///
/// A decryptor consists of the public key and a way of decrypting a
/// session key.  This crate implements `Decryptor` for [`KeyPair`],
/// which is a tuple containing the public and unencrypted secret key
/// in memory.  Other crates my provide their own implementations of
/// `Signer` to utilize keys stored in various places.  Currently, the
/// following implementations exist:
///
///   - [`KeyPair`]: In-memory keys.
///   - [`sequoia_rpc::gnupg::KeyPair`]: Connects to the `gpg-agent`.
///
///   [`KeyPair`]: struct.KeyPair.html
///   [`sequoia_rpc::gnupg::KeyPair`]: https://docs.sequoia-pgp.org/sequoia_ipc/gnupg/struct.KeyPair.html
pub trait Decryptor {
    /// Returns a reference to the public key.
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole>;

    /// Decrypts `ciphertext`, returning the plain session key.
    fn decrypt(&mut self, ciphertext: &mpi::Ciphertext,
               plaintext_len: Option<usize>)
               -> Result<SessionKey>;
}

/// A cryptographic key pair.
///
/// A `KeyPair` is a combination of public and secret key.  If both
/// are available in memory, a `KeyPair` is a convenient
/// implementation of [`Signer`] and [`Decryptor`].
///
/// [`Signer`]: trait.Signer.html
/// [`Decryptor`]: trait.Decryptor.html
///
/// # Examples
///
/// ```
/// # fn main() -> sequoia_openpgp::Result<()> {
/// use sequoia_openpgp as openpgp;
/// use openpgp::types::Curve;
/// use openpgp::cert::prelude::*;
/// use openpgp::packet::prelude::*;
///
/// // Conveniently create a KeyPair from a bare key:
/// let keypair =
///     Key4::<_, key::UnspecifiedRole>::generate_ecc(false, Curve::Cv25519)?
///         .into_keypair()?;
///
/// // Or from a query over a certificate:
/// let (cert, _) =
///     CertBuilder::general_purpose(None, Some("alice@example.org"))
///         .generate()?;
/// let keypair =
///     cert.keys().unencrypted_secret().nth(0).unwrap().key().clone()
///         .into_keypair()?;
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct KeyPair {
    public: Key<key::PublicParts, key::UnspecifiedRole>,
    secret: packet::key::Unencrypted,
}

impl KeyPair {
    /// Creates a new key pair.
    pub fn new(public: Key<key::PublicParts, key::UnspecifiedRole>,
               secret: packet::key::Unencrypted)
        -> Result<Self>
    {
        Ok(Self {
            public,
            secret,
        })
    }

    /// Returns a reference to the public key.
    pub fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        &self.public
    }

    /// Returns a reference to the secret key.
    pub fn secret(&self) -> &packet::key::Unencrypted {
        &self.secret
    }
}

impl From<KeyPair> for Key<key::SecretParts, key::UnspecifiedRole> {
    fn from(p: KeyPair) -> Self {
        let (key, secret) = (p.public, p.secret);
        key.add_secret(secret.into()).0
    }
}
