use crate::{error::VladError, Cid, Error};
use core::fmt;
use multibase::Base;
use multicodec::Codec;
use multikey::Nonce;
use multitrait::TryDecodeFrom;
use multiutil::{BaseEncoded, CodecInfo, EncodingInfo};

/// the Vlad multicodec sigil
pub const SIGIL: Codec = Codec::Vlad;

/// a multibase encoded Vlad
pub type EncodedVlad = BaseEncoded<Vlad>;

/// A verifiable long-lived address (VLAD) represents an identifier for loosely
/// coupled distributed systems that combines a random unique idenitfier (none)
/// with the content address of a verification function in executable format.
///
/// The goal is to avoid the anti-pattern of using public keys as identifiers.
/// Public keys are chosen because they are random and unique enough to be
/// useful identifiers and are also a cryptographic commitment to a validation
/// function--the public key signature validation function. Using public keys
/// as an identifer is an anti-pattern because using key material means that
/// the identifiers are subject to compromise and must be rotated often to
/// maintain security so their "shelf-life" is limited. Rotating and/or
/// abandoning keys due to compromise causes the identifier to become invalid.
/// Any system that stores these identifiers then possesses broken links to
/// the value the identifier is associated with.
///
/// The solution is to realize that we only need a random identifier and a
/// cryptographic commitment to a validation function to replace keys as
/// identifiers. VLADs meet those requirements.
#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Vlad {
    /// the random nonce for uniqueness
    pub(crate) nonce: Nonce,
    /// validation function content address
    pub(crate) cid: Cid,
}

impl CodecInfo for Vlad {
    /// Return that we are a Cid object
    fn preferred_codec() -> Codec {
        SIGIL
    }

    /// Return the codec for this object
    fn codec(&self) -> Codec {
        Self::preferred_codec()
    }
}

impl EncodingInfo for Vlad {
    fn preferred_encoding() -> Base {
        Base::Base32Lower
    }

    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl Into<Vec<u8>> for Vlad {
    fn into(self) -> Vec<u8> {
        let mut v = Vec::default();
        // add the sigil
        v.append(&mut SIGIL.into());
        // add the nonce
        v.append(&mut self.nonce.clone().into());
        // add the cid
        v.append(&mut self.cid.clone().into());
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for Vlad {
    type Error = Error;

    fn try_from(s: &'a [u8]) -> Result<Self, Self::Error> {
        let (mh, _) = Self::try_decode_from(s)?;
        Ok(mh)
    }
}

impl<'a> TryDecodeFrom<'a> for Vlad {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the sigil
        let (sigil, ptr) = Codec::try_decode_from(bytes)?;
        if sigil != SIGIL {
            return Err(VladError::MissingSigil.into());
        }
        // decode the none
        let (nonce, ptr) = Nonce::try_decode_from(ptr)?;
        // decode the cid
        let (cid, ptr) = Cid::try_decode_from(ptr)?;
        Ok((Self { nonce, cid }, ptr))
    }
}

impl fmt::Debug for Vlad {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} - {:?} - {:?}", SIGIL, self.nonce, self.cid)
    }
}

/// Hash builder that takes the codec and the data and produces a Multihash
#[derive(Clone, Debug, Default)]
pub struct Builder {
    nonce: Option<Nonce>,
    cid: Option<Cid>,
    base_encoding: Option<Base>,
}

impl Builder {
    /// set the nonce
    pub fn with_nonce(mut self, nonce: &Nonce) -> Self {
        self.nonce = Some(nonce.clone());
        self
    }

    /// set cid
    pub fn with_cid(mut self, cid: &Cid) -> Self {
        self.cid = Some(cid.clone());
        self
    }

    /// set the base encoding codec
    pub fn with_base_encoding(mut self, base: Base) -> Self {
        self.base_encoding = Some(base);
        self
    }

    /// build a base encoded vlad
    pub fn try_build_encoded(&self) -> Result<EncodedVlad, Error> {
        Ok(EncodedVlad::new(
            self.base_encoding
                .unwrap_or_else(|| Vlad::preferred_encoding()),
            self.try_build()?,
        ))
    }

    /// build the vlad
    pub fn try_build(&self) -> Result<Vlad, Error> {
        Ok(Vlad {
            nonce: self.nonce.clone().ok_or(VladError::MissingNonce)?,
            cid: self.cid.clone().ok_or(VladError::MissingCid)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid;
    use multihash::mh;
    use multikey::nonce;

    #[test]
    fn test_default() {
        // build a nonce
        let mut rng = rand::rngs::OsRng::default();
        let nonce = nonce::Builder::new_from_random_bytes(32, &mut rng)
            .try_build()
            .unwrap();

        // build a cid
        let cid = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let vlad = Builder::default()
            .with_nonce(&nonce)
            .with_cid(&cid)
            .try_build()
            .unwrap();

        assert_eq!(Codec::Vlad, vlad.codec());
    }

    #[test]
    fn test_binary_roundtrip() {
        // build a nonce
        let mut rng = rand::rngs::OsRng::default();
        let nonce = nonce::Builder::new_from_random_bytes(32, &mut rng)
            .try_build()
            .unwrap();

        // build a cid
        let cid = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let vlad = Builder::default()
            .with_nonce(&nonce)
            .with_cid(&cid)
            .try_build()
            .unwrap();

        let v: Vec<u8> = vlad.clone().into();
        assert_eq!(vlad, Vlad::try_from(v.as_ref()).unwrap());
    }

    #[test]
    fn test_encoded_roundtrip() {
        // build a nonce
        let mut rng = rand::rngs::OsRng::default();
        let nonce = nonce::Builder::new_from_random_bytes(32, &mut rng)
            .try_build()
            .unwrap();

        // build a cid
        let cid = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let vlad = Builder::default()
            .with_nonce(&nonce)
            .with_cid(&cid)
            .try_build_encoded()
            .unwrap();

        let s = vlad.to_string();
        assert_eq!(vlad, EncodedVlad::try_from(s.as_str()).unwrap());
    }
}
