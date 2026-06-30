use std::io;

/// Errors raised while decoding attacker-controlled bytes or running the data plane.
///
/// Every parse path returns one of these instead of panicking (SPEC §P7).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Not enough bytes remained to decode the next field.
    #[error("unexpected end of input: needed {needed}, had {had}")]
    Truncated { needed: usize, had: usize },

    /// A length / counter field overflowed while computing an offset.
    #[error("integer overflow while decoding")]
    Overflow,

    /// An address type byte did not map to a known family.
    #[error("unknown address type: {0}")]
    BadAddressType(u8),

    /// A domain field was empty or contained invalid characters.
    #[error("invalid domain name")]
    BadDomain,

    /// Protocol-level violation (bad magic, version, command, etc).
    #[error("protocol error: {0}")]
    Protocol(&'static str),

    /// Authentication failed (unknown user / bad MAC / replay).
    #[error("authentication failed")]
    Auth,

    /// Cryptographic operation failed (AEAD open, key schedule, etc).
    #[error("crypto error: {0}")]
    Crypto(&'static str),

    /// Configuration was rejected at build time.
    #[error("config error: {0}")]
    Config(String),

    /// A wrapped I/O error from the transport.
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Io(io) => io,
            other => io::Error::other(other),
        }
    }
}
