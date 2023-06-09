//! Holds the implementation of [`Signer`] and [`Decryptor`] for [`KeyPair`].
//!
//! [`Signer`]: ../../asymmetric/trait.Signer.html
//! [`Decryptor`]: ../../asymmetric/trait.Decryptor.html
//! [`KeyPair`]: ../../asymmetric/struct.KeyPair.html

use std::convert::TryFrom;
use std::time::SystemTime;

use x25519_dalek_ng as x25519_dalek;
use num_bigint_dig::{traits::ModInverse, BigUint};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{Pkcs1v15Encrypt, RsaPublicKey, RsaPrivateKey, Pkcs1v15Sign};

use crate::{Error, Result};
use crate::crypto::asymmetric::{KeyPair, Decryptor, Signer};
use crate::crypto::mem::Protected;
use crate::crypto::mpi::{self, MPI, ProtectedMPI};
use crate::crypto::SessionKey;
use crate::crypto::pad_truncating;
use crate::packet::{key, Key};
use crate::packet::key::{Key4, SecretParts};
use crate::types::{Curve, HashAlgorithm, PublicKeyAlgorithm};

use super::GenericArrayExt;

const CURVE25519_SIZE: usize = 32;

fn pkcs1_padding(hash_algo: HashAlgorithm) -> Result<Pkcs1v15Sign> {
    let hash = match hash_algo {
        HashAlgorithm::MD5 => Pkcs1v15Sign::new::<md5::Md5>(),
        HashAlgorithm::SHA1 => Pkcs1v15Sign::new::<sha1::Sha1>(),
        HashAlgorithm::SHA224 => Pkcs1v15Sign::new::<sha2::Sha224>(),
        HashAlgorithm::SHA256 => Pkcs1v15Sign::new::<sha2::Sha256>(),
        HashAlgorithm::SHA384 => Pkcs1v15Sign::new::<sha2::Sha384>(),
        HashAlgorithm::SHA512 => Pkcs1v15Sign::new::<sha2::Sha512>(),
        HashAlgorithm::RipeMD => Pkcs1v15Sign::new::<ripemd::Ripemd160>(),
        _ => return Err(Error::InvalidArgument(format!(
            "Algorithm {:?} not representable", hash_algo)).into()),
    };
    Ok(hash)
}

fn rsa_public_key(e: &MPI, n: &MPI) -> Result<RsaPublicKey> {
    let n = BigUint::from_bytes_be(n.value());
    let e = BigUint::from_bytes_be(e.value());
    Ok(RsaPublicKey::new(n, e)?)
}

#[allow(clippy::many_single_char_names)]
fn rsa_private_key(e: &MPI, n: &MPI, p: &ProtectedMPI, q: &ProtectedMPI, d: &ProtectedMPI)
    -> Result<RsaPrivateKey>
{
    let n = BigUint::from_bytes_be(n.value());
    let e = BigUint::from_bytes_be(e.value());
    let p = BigUint::from_bytes_be(p.value());
    let q = BigUint::from_bytes_be(q.value());
    let d = BigUint::from_bytes_be(d.value());
    Ok(RsaPrivateKey::from_components(n, e, d, vec![p, q])?)
}

impl Signer for KeyPair {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        KeyPair::public(self)
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8])
            -> Result<mpi::Signature>
    {
        use crate::PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        self.secret().map(|secret| match (self.public().pk_algo(), self.public().mpis(), secret) {
            (RSAEncryptSign,
             mpi::PublicKey::RSA { e, n },
             mpi::SecretKeyMaterial::RSA { p, q, d, .. }) |
            (RSASign,
             mpi::PublicKey::RSA { e, n },
             mpi::SecretKeyMaterial::RSA { p, q, d, .. }) => {
                let key = rsa_private_key(e, n, p, q, d)?;
                let padding = pkcs1_padding(hash_algo)?;
                let sig = key.sign(padding, digest)?;
                Ok(mpi::Signature::RSA {
                    s: mpi::MPI::new(&sig),
                })
            },

            (PublicKeyAlgorithm::DSA,
             mpi:: PublicKey::DSA { .. },
             mpi::SecretKeyMaterial::DSA { .. }) => {
                Err(Error::UnsupportedPublicKeyAlgorithm(PublicKeyAlgorithm::DSA).into())
            },

            (PublicKeyAlgorithm::ECDSA,
             mpi::PublicKey::ECDSA { curve, .. },
             mpi::SecretKeyMaterial::ECDSA { scalar }) => match curve
            {
                Curve::NistP256 => {
                    use p256::{
                        elliptic_curve::{
                            generic_array::GenericArray as GA,
                            ops::Reduce,
                        },
                        Scalar,
                    };
                    use ecdsa::{
                        hazmat::SignPrimitive,
                    };

                    const LEN: usize = 32;
                    let key = scalar.value_padded(LEN);
                    let key = Scalar::reduce_bytes(GA::try_from_slice(&key)?);
                    let dig = pad_truncating(digest, LEN);
                    let dig = GA::try_from_slice(&dig)?;

                    let sig = loop {
                        let mut k: Protected = vec![0; LEN].into();
                        crate::crypto::random(&mut k);
                        let k = Scalar::reduce_bytes(
                            GA::try_from_slice(&k)?);
                        if let Ok(s) = key.try_sign_prehashed(k, &dig) {
                            break s.0;
                        }
                    };

                    Ok(mpi::Signature::ECDSA {
                        r: MPI::new(&sig.r().to_bytes()),
                        s: MPI::new(&sig.s().to_bytes()),
                    })
                },
                _ => Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),
            },

            (EdDSA,
             mpi::PublicKey::EdDSA { curve, q },
             mpi::SecretKeyMaterial::EdDSA { scalar }) => match curve
            {
                Curve::Ed25519 => {
                    use ed25519_dalek::{Keypair, Signer};
                    use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};

                    let (public, ..) = q.decode_point(&Curve::Ed25519)?;
                    assert_eq!(public.len(), PUBLIC_KEY_LENGTH);

                    // It's expected for the private key to be exactly
                    // SECRET_KEY_LENGTH bytes long but OpenPGP allows leading
                    // zeros to be stripped.
                    // Padding has to be unconditional; otherwise we have a
                    // secret-dependent branch.
                    let mut keypair = Protected::from(
                        vec![0u8; SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH]
                    );
                    keypair.as_mut()[..SECRET_KEY_LENGTH]
                        .copy_from_slice(
                            &scalar.value_padded(SECRET_KEY_LENGTH));
                    keypair.as_mut()[SECRET_KEY_LENGTH..]
                        .copy_from_slice(public);
                    let pair = Keypair::from_bytes(&keypair)?;

                    let sig = pair.sign(digest).to_bytes();

                    // https://tools.ietf.org/html/rfc8032#section-5.1.6
                    let (r, s) = sig.split_at(sig.len() / 2);
                    Ok(mpi::Signature::EdDSA {
                        r: mpi::MPI::new(r),
                        s: mpi::MPI::new(s),
                    })
                },
                _ => Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),
            },

            (pk_algo, _, _) => {
                Err(Error::InvalidOperation(format!(
                    "unsupported combination of algorithm {:?}, key {:?}, \
                        and secret key {:?}",
                    pk_algo,
                    self.public(),
                    self.secret()
                )).into())
            }
        })
    }
}

impl Decryptor for KeyPair {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        KeyPair::public(self)
    }

    fn decrypt(&mut self, ciphertext: &mpi::Ciphertext,
               _plaintext_len: Option<usize>)
               -> Result<SessionKey>
    {
        use crate::PublicKeyAlgorithm::*;
        self.secret().map(|secret| match (self.public().mpis(), secret, ciphertext) {
            (mpi::PublicKey::RSA { e, n },
             mpi::SecretKeyMaterial::RSA { p, q, d, .. },
             mpi::Ciphertext::RSA { c }) => {
                let key = rsa_private_key(e, n, p, q, d)?;
                let decrypted = key.decrypt(Pkcs1v15Encrypt, c.value())?;
                Ok(SessionKey::from(decrypted))
            }

            (mpi::PublicKey::ElGamal { .. },
             mpi::SecretKeyMaterial::ElGamal { .. },
             mpi::Ciphertext::ElGamal { .. }) =>
                Err(Error::UnsupportedPublicKeyAlgorithm(ElGamalEncrypt).into()),

            (mpi::PublicKey::ECDH { .. },
             mpi::SecretKeyMaterial::ECDH { .. },
             mpi::Ciphertext::ECDH { .. }) =>
                crate::crypto::ecdh::decrypt(self.public(), secret, ciphertext),

            (public, secret, ciphertext) =>
                Err(Error::InvalidOperation(format!(
                    "unsupported combination of key pair {:?}/{:?} \
                     and ciphertext {:?}",
                    public, secret, ciphertext)).into()),
        })
    }
}


impl<P: key::KeyParts, R: key::KeyRole> Key<P, R> {
    /// Encrypts the given data with this key.
    pub fn encrypt(&self, data: &SessionKey) -> Result<mpi::Ciphertext> {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match self.pk_algo() {
            RSAEncryptSign | RSAEncrypt => match self.mpis() {
                mpi::PublicKey::RSA { e, n } => {
                    // The ciphertext has the length of the modulus.
                    let ciphertext_len = n.value().len();
                    if data.len() + 11 > ciphertext_len {
                        return Err(Error::InvalidArgument(
                            "Plaintext data too large".into()).into());
                    }
                    let key = rsa_public_key(e, n)?;
                    let ciphertext = key.encrypt(
                        &mut rsa::rand_core::OsRng,
                        Pkcs1v15Encrypt, data.as_ref())?;
                    Ok(mpi::Ciphertext::RSA {
                        c: mpi::MPI::new(&ciphertext)
                    })
                }
                pk => Err(Error::MalformedPacket(format!(
                    "Key: Expected RSA public key, got {:?}", pk)).into())
            }

            ECDH => crate::crypto::ecdh::encrypt(self.parts_as_public(), data),

            RSASign | DSA | ECDSA | EdDSA =>
                Err(Error::InvalidOperation(
                    format!("{} is not an encryption algorithm", self.pk_algo())
                ).into()),

            ElGamalEncrypt | ElGamalEncryptSign |
            Private(_) | Unknown(_) =>
                Err(Error::UnsupportedPublicKeyAlgorithm(self.pk_algo()).into()),
        }
    }

    /// Verifies the given signature.
    pub fn verify(&self, sig: &mpi::Signature, hash_algo: HashAlgorithm,
                  digest: &[u8]) -> Result<()>
    {
        fn bad(e: impl ToString) -> anyhow::Error {
            Error::BadSignature(e.to_string()).into()
        }
        match (self.mpis(), sig) {
            (mpi::PublicKey::RSA { e, n }, mpi::Signature::RSA { s }) => {
                let key = rsa_public_key(e, n)?;
                let padding = pkcs1_padding(hash_algo)?;
                // Originally, we had:
                //
                // key.verify(padding, digest, s.value())?;
                //
                // Since version 0.9.0 of the rsa crate, this no
                // longer works, because the verify function checks
                // that the signature length in bytes is the same as
                // the key length.  No other crypto backend appears
                // care (including older version of the rsa crate),
                // but would happily left pad it with zeros.  We now
                // do that manually:
                //
                // See
                // https://docs.rs/rsa/0.9.0/src/rsa/pkcs1v15.rs.html#212
                // and https://github.com/RustCrypto/RSA/issues/322.
                key.verify(padding, digest, &s.value_padded(key.size())?)?;
                Ok(())
            }
            (mpi::PublicKey::DSA { .. },
             mpi::Signature::DSA { .. }) => {
                Err(Error::UnsupportedPublicKeyAlgorithm(PublicKeyAlgorithm::DSA).into())
            },
            (mpi::PublicKey::ECDSA { curve, q },
             mpi::Signature::ECDSA { r, s }) => match curve
            {
                Curve::NistP256 => {
                    use p256::{
                        AffinePoint,
                        ecdsa::Signature,
                        elliptic_curve::{
                            generic_array::GenericArray as GA,
                            sec1::FromEncodedPoint,
                        },
                    };
                    use ecdsa::{
                        EncodedPoint,
                        hazmat::VerifyPrimitive,
                    };
                    const LEN: usize = 32;

                    let key = AffinePoint::from_encoded_point(
                        &EncodedPoint::<p256::NistP256>::from_bytes(q.value())?);
                    let key = if key.is_some().into() {
                        key.unwrap()
                    } else {
                        return Err(Error::InvalidKey(
                            "Point is not on the curve".into()).into());
                    };

                    let sig = Signature::from_scalars(
                        GA::try_clone_from_slice(
                            &r.value_padded(LEN).map_err(bad)?)?,
                        GA::try_clone_from_slice(
                            &s.value_padded(LEN).map_err(bad)?)?)
                        .map_err(bad)?;
                    let dig = pad_truncating(digest, LEN);
                    let dig = GA::try_from_slice(&dig)?;
                    key.verify_prehashed(&dig, &sig).map_err(bad)
                },
                _ => Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),
            },
            (mpi::PublicKey::EdDSA { curve, q },
             mpi::Signature::EdDSA { r, s }) => match curve {
                Curve::Ed25519 => {
                    use ed25519_dalek::{PublicKey, Signature, SIGNATURE_LENGTH};
                    use ed25519_dalek::{Verifier};

                    let (public, ..) = q.decode_point(&Curve::Ed25519)?;
                    assert_eq!(public.len(), 32);

                    let key = PublicKey::from_bytes(public).map_err(|e| {
                        Error::InvalidKey(e.to_string())
                    })?;

                    // OpenPGP encodes R and S separately, but our
                    // cryptographic library expects them to be
                    // concatenated.
                    let mut sig_bytes = [0u8; SIGNATURE_LENGTH];

                    // We need to zero-pad them at the front, because
                    // the MPI encoding drops leading zero bytes.
                    let half = SIGNATURE_LENGTH / 2;
                    sig_bytes[..half].copy_from_slice(
                        &r.value_padded(half).map_err(bad)?);
                    sig_bytes[half..].copy_from_slice(
                        &s.value_padded(half).map_err(bad)?);

                    let signature = Signature::from(sig_bytes);

                    key.verify(digest, &signature)
                        .map_err(|e| Error::BadSignature(e.to_string()))?;
                    Ok(())
                },
                _ => Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),
        },
            _ => Err(Error::MalformedPacket(format!(
                "unsupported combination of key {} and signature {:?}.",
                self.pk_algo(), sig)).into()),
        }
    }
}

impl<R> Key4<SecretParts, R>
    where R: key::KeyRole,
{
    pub(crate) fn derive_cv25519_public_key(private_key: &Protected) -> Result<[u8; 32]>
    {
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret = StaticSecret::from(<[u8; 32]>::try_from(&private_key[..])?);
        Ok(*PublicKey::from(&secret).as_bytes())
    }

    /// Creates a new OpenPGP secret key packet for an existing Ed25519 key.
    ///
    /// The ECDH key will use hash algorithm `hash` and symmetric
    /// algorithm `sym`.  If one or both are `None` secure defaults
    /// will be used.  The key will have it's creation date set to
    /// `ctime` or the current time if `None` is given.
    pub fn import_secret_ed25519<T>(private_key: &[u8], ctime: T)
        -> Result<Self> where T: Into<Option<SystemTime>>
    {
        use ed25519_dalek::{PublicKey, SecretKey};

        let private = SecretKey::from_bytes(private_key).map_err(|e| {
            Error::InvalidKey(e.to_string())
        })?;

        // Mark MPI as compressed point with 0x40 prefix. See
        // https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-07#section-13.2.
        let mut public = [0u8; 1 + CURVE25519_SIZE];
        public[0] = 0x40;
        public[1..].copy_from_slice(Into::<PublicKey>::into(&private).as_bytes());

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::EdDSA,
            mpi::PublicKey::EdDSA {
                curve: Curve::Ed25519,
                q: mpi::MPI::new(&public)
            },
            mpi::SecretKeyMaterial::EdDSA {
                scalar: private_key.into(),
            }.into()
        )
    }

    /// Creates a new OpenPGP public key packet for an existing RSA key.
    ///
    /// The RSA key will use public exponent `e` and modulo `n`. The key will
    /// have it's creation date set to `ctime` or the current time if `None`
    /// is given.
    #[allow(clippy::many_single_char_names)]
    pub fn import_secret_rsa<T>(d: &[u8], p: &[u8], q: &[u8], ctime: T)
        -> Result<Self> where T: Into<Option<SystemTime>>
    {
        // RFC 4880: `p < q`
        let (p, q) = if p < q { (p, q) } else { (q, p) };

        // RustCrypto can't compute the public key from the private one, so do it ourselves
        let big_p = BigUint::from_bytes_be(p);
        let big_q = BigUint::from_bytes_be(q);
        let n = big_p.clone() * big_q.clone();

        let big_d = BigUint::from_bytes_be(d);
        let big_phi = (big_p.clone() - 1u32) * (big_q.clone() - 1u32);
        let e = big_d.mod_inverse(big_phi) // e ≡ d⁻¹ (mod 𝜙)
            .and_then(|x| x.to_biguint())
            .ok_or_else(|| Error::MalformedMPI("RSA: `d` and `(p-1)(q-1)` aren't coprime".into()))?;

        let u: BigUint = big_p.mod_inverse(big_q) // RFC 4880: u ≡ p⁻¹ (mod q)
            .and_then(|x| x.to_biguint())
            .ok_or_else(|| Error::MalformedMPI("RSA: `p` and `q` aren't coprime".into()))?;

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::RSAEncryptSign,
            mpi::PublicKey::RSA {
                e: mpi::MPI::new(&e.to_bytes_be()),
                n: mpi::MPI::new(&n.to_bytes_be()),
            },
            mpi::SecretKeyMaterial::RSA {
                d: d.into(),
                p: p.into(),
                q: q.into(),
                u: u.to_bytes_be().into(),
            }.into()
        )
    }

    /// Generates a new RSA key with a public modulos of size `bits`.
    pub fn generate_rsa(bits: usize) -> Result<Self> {
        let key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits)?;
        let (p, q) = match key.primes() {
            [p, q] => (p, q),
            _ => panic!("RSA key generation resulted in wrong number of primes"),
        };
        let u = p.mod_inverse(q) // RFC 4880: u ≡ p⁻¹ (mod q)
            .and_then(|x| x.to_biguint())
            .expect("rsa crate did not generate coprime p and q");

        let public = mpi::PublicKey::RSA {
            e: mpi::MPI::new(&key.to_public_key().e().to_bytes_be()),
            n: mpi::MPI::new(&key.to_public_key().n().to_bytes_be()),
        };

        let private = mpi::SecretKeyMaterial::RSA {
            p: p.to_bytes_be().into(),
            q: q.to_bytes_be().into(),
            d: key.d().to_bytes_be().into(),
            u: u.to_bytes_be().into(),
        };

        Self::with_secret(
            crate::now(),
            PublicKeyAlgorithm::RSAEncryptSign,
            public,
            private.into(),
        )
    }

    /// Generates a new ECC key over `curve`.
    ///
    /// If `for_signing` is false a ECDH key, if it's true either a
    /// EdDSA or ECDSA key is generated.  Giving `for_signing == true` and
    /// `curve == Cv25519` will produce an error. Likewise
    /// `for_signing == false` and `curve == Ed25519` will produce an error.
    pub fn generate_ecc(for_signing: bool, curve: Curve) -> Result<Self> {
        let hash = crate::crypto::ecdh::default_ecdh_kdf_hash(&curve);
        let sym = crate::crypto::ecdh::default_ecdh_kek_cipher(&curve);

        let (algo, public, private) = match (&curve, for_signing) {
            (Curve::Ed25519, true) => {
                use ed25519_dalek::Keypair;

                // ed25519_dalek v1.0.1 doesn't reexport OsRng.  It
                // depends on 0.7.
                use rand07::rngs::OsRng as OsRng;

                let Keypair { public, secret }
                    = Keypair::generate(&mut OsRng);

                let secret: Protected = secret.as_bytes().as_ref().into();

                // Mark MPI as compressed point with 0x40 prefix. See
                // https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-07#section-13.2.
                let mut compressed_public = [0u8; 1 + CURVE25519_SIZE];
                compressed_public[0] = 0x40;
                compressed_public[1..].copy_from_slice(public.as_bytes());

                (
                    PublicKeyAlgorithm::EdDSA,
                    mpi::PublicKey::EdDSA { curve, q: mpi::MPI::new(&compressed_public) },
                    mpi::SecretKeyMaterial::EdDSA { scalar: secret.into() },
                )
            }

            (Curve::Cv25519, false) => {
                use x25519_dalek::{StaticSecret, PublicKey};

                // x25519_dalek v1.1 doesn't reexport OsRng.  It
                // depends on rand 0.8.
                use rand::rngs::OsRng;

                let private_key = StaticSecret::new(&mut OsRng);
                let public_key = PublicKey::from(&private_key);

                let mut private_key = Vec::from(private_key.to_bytes());
                private_key.reverse();

                let public_mpis = mpi::PublicKey::ECDH {
                    curve: Curve::Cv25519,
                    q: MPI::new_compressed_point(&*public_key.as_bytes()),
                    hash,
                    sym,
                };
                let private_mpis = mpi::SecretKeyMaterial::ECDH {
                    scalar: private_key.into(),
                };

                (PublicKeyAlgorithm::ECDH, public_mpis, private_mpis)
            }

            (Curve::NistP256, true) => {
                use p256::{EncodedPoint, SecretKey};

                let secret = SecretKey::random(
                    &mut p256::elliptic_curve::rand_core::OsRng);
                let public = EncodedPoint::from(secret.public_key());

                let public_mpis = mpi::PublicKey::ECDSA {
                    curve,
                    q: MPI::new(public.as_bytes()),
                };
                let private_mpis = mpi::SecretKeyMaterial::ECDSA {
                    scalar: Vec::from(secret.to_bytes().as_slice()).into(),
                };

                (PublicKeyAlgorithm::ECDSA, public_mpis, private_mpis)
            },

            (Curve::NistP256, false) => {
                use p256::{EncodedPoint, SecretKey};

                let secret = SecretKey::random(
                    &mut p256::elliptic_curve::rand_core::OsRng);
                let public = EncodedPoint::from(secret.public_key());

                let public_mpis = mpi::PublicKey::ECDH {
                    curve,
                    q: MPI::new(public.as_bytes()),
                    hash,
                    sym,
                };
                let private_mpis = mpi::SecretKeyMaterial::ECDH {
                    scalar: Vec::from(secret.to_bytes().as_slice()).into(),
                };

                (PublicKeyAlgorithm::ECDH, public_mpis, private_mpis)
            },

            _ => {
                return Err(Error::UnsupportedEllipticCurve(curve).into());
            }
        };
        Self::with_secret(crate::now(), algo, public, private.into())
    }
}

