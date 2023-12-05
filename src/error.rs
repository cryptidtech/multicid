use thiserror::Error;

/// Errors created by this library
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// A multibase conversion error
    #[error(transparent)]
    Multibase(#[from] multibase::Error),
    /// A multicodec decoding error
    #[error(transparent)]
    Multicodec(#[from] multicodec::Error),
    /// A multihash error
    #[error(transparent)]
    Multihash(#[from] multihash::Error),
    /// A mulikey error
    #[error(transparent)]
    Multikey(#[from] multikey::Error),
    /// Multiutil error
    #[error(transparent)]
    Multiutil(#[from] multiutil::Error),
    /// Multitrait error
    #[error(transparent)]
    Multitrait(#[from] multitrait::Error),
    /// Cid error
    #[error(transparent)]
    Cid(#[from] CidError),
    /// Vlad error
    #[error(transparent)]
    Vlad(#[from] VladError),
}

/// Cid Errors created by this library
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CidError {
    /// Base58 encoding error
    #[error(transparent)]
    Base58(#[from] Base58EncodedError),
    /// Missing sigil 0x01, 0x02, or 0x03
    #[error("Missing Cid sigil")]
    MissingSigil,
    /// Missing target codec
    #[error("Missing target data encoding codec")]
    MissingTargetCodec,
    /// Missing hash data
    #[error("Missing hash data")]
    MissingHash,
    /// Error with the hash scheme
    #[error("Unsupported hash algorithm: {0}")]
    UnsupportedHash(multicodec::Codec),
    /// Trying to build a legacy Cid using the wrong function
    #[error("Building legacy Cid with the wrong function")]
    LegacyCid,
    /// Trying to build a modern Cid using the wrong function
    #[error("Building modern Cid with the wrong function")]
    ModernCid,
    /// Invalid Cid version
    #[error("Invalid Cid version")]
    InvalidVersion,
}

/// Base58 encoding errors created by this library
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum Base58EncodedError {
    /// Value decode faile
    #[error("Failed to decode the inner value")]
    ValueFailed,
    /// Base58 library error
    #[error("Base58 decoding failed {0}")]
    Base58(String),
}

/// Vlad Errors created by this library
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum VladError {
    /// Missing sigil 0x07
    #[error("Missing Vlad sigil")]
    MissingSigil,
    /// Missing nonce
    #[error("Missing nonce")]
    MissingNonce,
    /// Missing nonce
    #[error("Missing cid")]
    MissingCid,
}
