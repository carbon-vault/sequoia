//! Implementation of Sequoia crypto API using the Nettle cryptographic library.

use nettle::random::{Random, Yarrow};

pub mod aead;
pub mod asymmetric;
pub mod ecdh;
pub mod hash;
pub mod symmetric;

/// Fills the given buffer with random data.
pub fn random<B: AsMut<[u8]>>(mut buf: B) {
    Yarrow::default().random(buf.as_mut());
}
