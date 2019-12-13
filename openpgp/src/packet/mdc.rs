use crate::crypto;
use crate::packet;
use crate::Packet;

/// Holds an MDC packet.
///
/// A modification detection code packet.  This packet appears after a
/// SEIP packet.  See [Section 5.14 of RFC 4880] for details.
///
/// [Section 5.14 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.14
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct MDC {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// Our SHA-1 hash.
    computed_digest: [u8; 20],
    /// A 20-octet SHA-1 hash of the preceding plaintext data.
    digest: [u8; 20],
}

impl MDC {
    /// Creates an MDC packet.
    pub fn new(digest: [u8; 20], computed_digest: [u8; 20]) -> Self {
        MDC {
            common: Default::default(),
            computed_digest,
            digest,
        }
    }

    /// Gets the packet's hash value.
    pub fn digest(&self) -> &[u8] {
        &self.digest[..]
    }

    /// Gets the computed hash value.
    pub fn computed_digest(&self) -> &[u8] {
        &self.computed_digest[..]
    }

    /// Returns whether the data protected by the MDC is valid.
    pub fn valid(&self) -> bool {
        if self.digest == [ 0; 20 ] {
            // If the computed_digest and digest are uninitialized, then
            // return false.
            false
        } else {
            self.computed_digest == self.digest
        }
    }
}

impl From<MDC> for Packet {
    fn from(s: MDC) -> Self {
        Packet::MDC(s)
    }
}

impl From<[u8; 20]> for MDC {
    fn from(digest: [u8; 20]) -> Self {
        MDC {
            common: Default::default(),
            // All 0s.
            computed_digest: Default::default(),
            digest,
        }
    }
}

impl From<crypto::hash::Context> for MDC {
    fn from(mut hash: crypto::hash::Context) -> Self {
        let mut value : [u8; 20] = Default::default();
        hash.digest(&mut value[..]);
        value.into()
    }
}
