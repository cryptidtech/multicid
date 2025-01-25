// SPDX-License-Idnetifier: Apache-2.0
use crate::{error::VladError, Cid, Error};
use core::fmt;
use multibase::Base;
use multicodec::Codec;
use multikey::{nonce, Multikey, Nonce, Views};
use multisig::Multisig;
use multitrait::{Null, TryDecodeFrom};
use multiutil::{BaseEncoded, CodecInfo, DetectedEncoder, EncodingInfo};

/// The Vlad multicodec sigil
pub const SIGIL: Codec = Codec::Vlad;

/// A multibase encoded Vlad.
///
/// Can decode from any number of encodings but always encodes to
/// Vlad's preferred Base32Lower multibase encoding (i.e. liberal in what we except, strict in what
/// we generate)
pub type EncodedVlad = BaseEncoded<Vlad, DetectedEncoder>;

/// A verifiable long-lived address (VLAD).
///
/// A VLAD represents an identifier for loosely coupled distributed
/// systems that combines a random unique idenitfier (nonce) with the content address of a
/// verification function in executable format.
///
/// The goal is to avoid the anti-pattern of using public keys as identifiers. Public keys are
/// chosen because they are random and unique enough to be useful identifiers and are also a
/// cryptographic commitment to a validation function--the public key signature validation
/// function. Using public keys as an identifer is an anti-pattern because using key material means
/// that the identifiers are subject to compromise and must be rotated often to maintain security
/// so their "shelf-life" is limited. Rotating and/or abandoning keys due to compromise causes the
/// identifier to become invalid. Any system that stores these identifiers then possesses broken
/// links to the value the identifier is associated with.
///
/// The solution is to realize that we only need a random identifier and a cryptographic commitment
/// to a validation function to replace keys as identifiers. VLADs meet those requirements.
#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Vlad {
    /// the random nonce for uniqueness
    pub(crate) nonce: Nonce,
    /// validation function content address
    pub(crate) cid: Cid,
}

impl Vlad {
    /// Verify a Vlad whose nonce is a digital signature over the Cid
    pub fn verify(&self, mk: &Multikey) -> Result<(), Error> {
        let vv = mk.verify_view()?;
        let cidv: Vec<u8> = self.cid.clone().into();
        let ms = Multisig::try_from(self.nonce.as_ref())?;
        vv.verify(&ms, Some(&cidv))?;
        Ok(())
    }
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

impl From<Vlad> for Vec<u8> {
    fn from(vlad: Vlad) -> Vec<u8> {
        let mut v = Vec::default();
        // add the sigil
        v.append(&mut SIGIL.into());
        // add the nonce
        v.append(&mut vlad.nonce.into());
        // add the cid
        v.append(&mut vlad.cid.into());
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

impl Null for Vlad {
    fn null() -> Self {
        Self {
            nonce: Nonce::null(),
            cid: Cid::null(),
        }
    }

    fn is_null(&self) -> bool {
        *self == Self::null()
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
    mk: Option<Multikey>,
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

    /// set the signing key to generate a signature nonce
    pub fn with_signing_key(mut self, mk: &Multikey) -> Self {
        self.mk = Some(mk.clone());
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
            self.base_encoding.unwrap_or_else(Vlad::preferred_encoding),
            self.try_build()?,
        ))
    }

    /// build the vlad
    pub fn try_build(&self) -> Result<Vlad, Error> {
        let cid = self.cid.clone().ok_or(VladError::MissingCid)?;
        match &self.nonce {
            Some(nonce) => Ok(Vlad {
                nonce: nonce.clone(),
                cid,
            }),
            None => match &self.mk {
                Some(mk) => {
                    let sv = mk.sign_view()?;
                    let cidv: Vec<u8> = cid.clone().into();
                    let ms = sv.sign(&cidv, false, None)?;
                    let msv: Vec<u8> = ms.clone().into();
                    let nonce = nonce::Builder::new_from_bytes(&msv).try_build()?;
                    Ok(Vlad { nonce, cid })
                }
                None => Err(VladError::MissingNonce.into()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid;
    use multihash::mh;
    use multikey::EncodedMultikey;
    use multiutil::{base_name, BaseIter};

    #[test]
    fn test_default() {
        // build a nonce
        let mut rng = rand::rngs::OsRng;
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
        let mut rng = rand::rngs::OsRng;
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
        //println!("byte len: {}", v.len());
        assert_eq!(vlad, Vlad::try_from(v.as_ref()).unwrap());
    }

    #[test]
    fn test_encoded_roundtrip() {
        // build a nonce
        let mut rng = rand::rngs::OsRng;
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
        //println!("({}) {}", s.len(), s);
        assert_eq!(vlad, EncodedVlad::try_from(s.as_str()).unwrap());
    }

    #[test]
    fn test_encodings_roundtrip() {
        // build a nonce
        let mut rng = rand::rngs::OsRng;
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

        // start at Identity so we skip it
        let itr: BaseIter = Base::Identity.into();

        for encoding in itr {
            //print!("{}...", base_name(encoding));
            let vlad = Builder::default()
                .with_nonce(&nonce)
                .with_cid(&cid)
                .with_base_encoding(encoding)
                .try_build_encoded()
                .unwrap();

            let s = vlad.to_string();
            println!("{}: ({}) {}", base_name(encoding), s.len(), s);
            //println!("worked!");
            assert_eq!(vlad, EncodedVlad::try_from(s.as_str()).unwrap());
        }
    }

    #[test]
    fn test_naked_encodings() {
        let naked_encoded = vec![
            (Base::Base2, "0100001110010010010111011001001000010000010101011111101010101001010111011011010101100111011110001011001010000011011111110011110101111000001110010110111101101010001100011010111111110100101011000010111000010011101101111000001111111100011100000001011001011101000101111111111001001001110010010001000000000000101110001000101000100000001010111100100101101101011011001011000001000010110110110000001110110101110001110010011100110001110110101011110001100100100001101000000110011011010111100101010101101111011110100111100100100011100000100110111111000011001100001010010010101001001101010000111100110110100100011111110001001111000100001100010101101001111110110000101110010101001111110001001101110011011100011011110100011110111101010011100101000111001011111001000110010111001000001011010010110101011010010100001101011110011001010100100100000000110111110"),
            (Base::Base8, "74162227311020253752512733254736131203376365701626755214327764530270235570177434013135057771116221000056105040127445553313010266601665616234616653614441500633274525573647444340467703141222511520746644376117041425517660562517611563343364367523450713710627101322653224153631244400676"),
            (Base::Base10, "93870361154591786056205491493019802388883700996012441049219964638855824516737171088563397435615501486404979067615946505439444354740858725022007675555169022360610124101489649907289941930351813344284767475896642016737913366109253497871106880676932034363838"),
            (Base::Base16Lower, "f8724bb2420abf552bb6acef16506fe7af072ded4635fe9585c276f07f8e02cba2ffc939220017114405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be"),
            (Base::Base16Upper, "F8724BB2420ABF552BB6ACEF16506FE7AF072DED4635FE9585C276F07F8E02CBA2FFC939220017114405792DAD96085B6076B8E4E63B578C90D0336BCAADEF4F24704DF866149526A1E6D23F89E218AD3F6172A7E26E6E37A3DEA728E5F232E41696AD286BCCA9201BE"),
            (Base::Base32Lower, "bq4slwjbavp2vfo3kz3ywkbx6plyhfxwumnp6swc4e5xqp6hafs5c77etsiqac4iuiblzfwwzmcc3mb3lrzhghnlyzegqgnv4vlppj4shatpymykjkjvb43jd7cpcdcwt6ylsu7rg43rxuppkokhf6izoifuwvuugxtfjean6"),
            (Base::Base32Upper, "BQ4SLWJBAVP2VFO3KZ3YWKBX6PLYHFXWUMNP6SWC4E5XQP6HAFS5C77ETSIQAC4IUIBLZFWWZMCC3MB3LRZHGHNLYZEGQGNV4VLPPJ4SHATPYMYKJKJVB43JD7CPCDCWT6YLSU7RG43RXUPPKOKHF6IZOIFUWVUUGXTFJEAN6"),
            (Base::Base32HexLower, "vgsibm910lfql5eraproma1nufbo75nmkcdfuim2s4tngfu705it2vv4ji8g02s8k81bp5mmpc22rc1rbhp767dbop46g6dlslbff9si70jfocoa9a9l1sr93v2f232mjuobikvh6srhnkffaea75u8pe85kmlkk6nj5940du"),
            (Base::Base32HexUpper, "VGSIBM910LFQL5ERAPROMA1NUFBO75NMKCDFUIM2S4TNGFU705IT2VV4JI8G02S8K81BP5MMPC22RC1RBHP767DBOP46G6DLSLBFF9SI70JFOCOA9A9L1SR93V2F232MJUOBIKVH6SRHNKFFAEA75U8PE85KMLKK6NJ5940DU"),
            (Base::Base32Z, "hoh1msjbyix4ifq5k35askbz6xma8fzswcpx61snhr7zox68yf17n99ru1eoynhewebm3fss3cnn5cb5mt38g8pma3rgogpihimxxjh18yuxacakjkjibh5jd9nxndnsu6am1w9tgh5tzwxxkqk8f6e3qefwsiwwgzufjryp6"),
            (Base::Base36Lower, "k2xg7x2wm1ycnm2wxuc7edrtm3dz5t7pdojs7qbocom1bg2pzd8vicjuqe8e245npjpvvxtfxfn6qbhvtvkjyxxjccnr6kvnwwa225l8cvyvlv4p8qimjro6awa592cwywrg3ul3lg8orcamiff1jvvi25t4g7698ipq"),
            (Base::Base36Upper, "K2XG7X2WM1YCNM2WXUC7EDRTM3DZ5T7PDOJS7QBOCOM1BG2PZD8VICJUQE8E245NPJPVVXTFXFN6QBHVTVKJYXXJCCNR6KVNWWA225L8CVYVLV4P8QIMJRO6AWA592CWYWRG3UL3LG8ORCAMIFF1JVVI25T4G7698IPQ"),
            (Base::Base58Flickr, "Z3BGq28L4k5syJ5FyzPmBM7pCAYPMKeU1mmgAJcCUSZyBgzMinFA9hxFcDZ65C966no9uGF4C9UqsCmU975d8Bt95XGfZrNTgrWuwPycYHsGn5jyrnaWJtCryzzZErsaffckdav4C42g9bnzy"),
            (Base::Base58Btc, "z3chR28m4L5TZj5gZapMcn7QdbypnkEu1MMGbjCduszZcGanJNgb9HYgCez65d966NP9Vhg4d9uRTdMu975D8cU95xhFzSotGSwVXpZCyiThN5KZSNAwjUdSZaazfSTAFFCLDAW4d42G9BNaZ"),
            (Base::Base64, "mhyS7JCCr9VK7as7xZQb+evBy3tRjX+lYXCdvB/jgLLov/JOSIAFxFEBXktrZYIW2B2uOTmO1eMkNAza8qt708kcE34ZhSVJqHm0j+J4hitP2Fyp+Jubjej3qco5fIy5BaWrShrzKkgG+"),
            (Base::Base64Url, "uhyS7JCCr9VK7as7xZQb-evBy3tRjX-lYXCdvB_jgLLov_JOSIAFxFEBXktrZYIW2B2uOTmO1eMkNAza8qt708kcE34ZhSVJqHm0j-J4hitP2Fyp-Jubjej3qco5fIy5BaWrShrzKkgG-"),
            (Base::Base256Emoji, "🚀🙊🥰😙🥰😅🤨🤐❣😙😬😟💩✋🌒📣💐💡🥺🐷📌💃🥳💣💥😡💙😓🌓🥵💧💪🤓👌👼😫🌼😅🪐✅💾😋😑🌼😗🍒😥🖕🤬🌓🙃🤞👇💃💨😣🦋🌍🛰🤦💟😰🐷👻👐🤩🌌☎💝🤤😀❣😬😘🌷🔥🥵🐶👏💫🤧🤮❤😆😠💖🍑👆💐😌🐸🥺🤞🥳🔥☺💗🌟😬🤠💝💟😷🌼🪐😖")
        ];

        for naked in naked_encoded {
            print!("{}...", base_name(naked.0));
            let vlad = EncodedVlad::try_from(naked.1).unwrap();
            assert_eq!(naked.0, vlad.encoding());
            println!("worked!!");
        }
    }

    #[test]
    fn test_signed_vlad() {
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

        let s = "fba2480260874657374206b657901012064e58adf88f85cbec6a0448a0803f9d28cf9231a7141be413f83cf6aa883cd04";
        let mk = EncodedMultikey::try_from(s).unwrap();

        let vlad = Builder::default()
            .with_signing_key(&mk)
            .with_cid(&cid)
            .with_base_encoding(Base::Base32Z)
            .try_build_encoded()
            .unwrap();

        // make sure the signature checks out
        assert!(vlad.verify(&mk).is_ok());
        let s = vlad.to_string();
        //println!("BASE32Z ({}) {}", s.len(), s);
        let de = EncodedVlad::try_from(s.as_str()).unwrap();
        assert_eq!(vlad, de);
        assert_eq!(Base::Base32Z, de.encoding());
        let vlad = vlad.to_inner();
        let v: Vec<u8> = vlad.clone().into();
        //println!("BLAH: {}", hex::encode(&v));
        assert_eq!(vlad, Vlad::try_from(v.as_ref()).unwrap());
    }

    #[test]
    fn test_null() {
        let v1 = Vlad::null();
        assert!(v1.is_null());
        let v2 = Vlad::default();
        assert!(v1 != v2);
        assert!(!v2.is_null());
    }
}
