// SPDX-License-Idnetifier: Apache-2.0
use crate::{error::VladError, Cid, Error};
use core::fmt;
use multibase::Base;
use multicodec::Codec;
use multikey::{nonce, Multikey, Nonce, Views};
use multisig::Multisig;
use multitrait::{Null, TryDecodeFrom};
use multiutil::{BaseEncoded, CodecInfo, DetectedEncoder, EncodingInfo};

/// the Vlad multicodec sigil
pub const SIGIL: Codec = Codec::Vlad;

/// a multibase encoded Vlad that can decode from any number of encoding but always encodes to
/// Vlad's preferred Base32Lower multibase encoding (i.e. liberal in what we except, strict in what
/// we generate)
pub type EncodedVlad = BaseEncoded<Vlad, DetectedEncoder>;

/// A verifiable long-lived address (VLAD) represents an identifier for loosely coupled distributed
/// systems that combines a random unique idenitfier (none) with the content address of a
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
    /// verify a Vlad whose nonce is a digital signature over the Cid
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
            self.base_encoding
                .unwrap_or_else(|| Vlad::preferred_encoding()),
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
        //println!("byte len: {}", v.len());
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
        //println!("({}) {}", s.len(), s);
        assert_eq!(vlad, EncodedVlad::try_from(s.as_str()).unwrap());
    }

    #[test]
    fn test_encodings_roundtrip() {
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

        // start at Identity so we skip it
        let mut itr: BaseIter = Base::Identity.into();

        while let Some(encoding) = itr.next() {
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
            (Base::Base2, "00000111001110110010000010101101010101110101001111101110010011000000100001110101101011100000010100101011011011000100111111010001010010010001010001110100010110001100000001110101110010001001010101101101000111101001001110110100101011010011000111001010111000110100101011100010111001100000000101110001000101000100000001010111100100101101101011011001011000001000010110110110000001110110101110001110010011100110001110110101011110001100100100001101000000110011011010111100101010101101111011110100111100100100011100000100110111111000011001100001010010010101001001101010000111100110110100100011111110001001111000100001100010101101001111110110000101110010101001111110001001101110011011100011011110100011110111101010011100101000111001011111001000110010111001000001011010010110101011010010100001101011110011001010100100100000000110111110"),
            (Base::Base8, "01635440532535237344601035327005126661176424442435054300353442253321722355126461625615127056300134212100257113326626020555403553434471435527431103201466571253367517110701157606302445223241715510774236103053237541345237423346706750757247121627621456202645526450327462511001574"),
            (Base::Base10, "3159896538572941552300237467498239240230991094809220818669996208403756627333440284950116478852282558426450173929503136577705156387666971927483177444527629374454471997041770248911157995781224129392264907918430937825252959411085792202002484276887998"),
            (Base::Base16Lower, "073b203e9e75230920469f4f2fb703447fb6451b66eef3c7bf2f376bc05d9fd147ae60017114405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be"),
            (Base::Base16Upper, "073B20BFA0561070F9B1963193361880319E93E80267D904BB19C9BBD1E64141A01351017114405792DAD96085B6076B8E4E63B578C90D0336BCAADEF4F24704DF866149526A1E6D23F89E218AD3F6172A7E26E6E37A3DEA728E5F232E41696AD286BCCA9201BE"),
            (Base::Base32Lower, "a45sapu6ourqsicgt5hs7nydir73mri3m3xphr57f43wxqc5t7iupltaafyriqcxslnnsyefwydwxdsomo2xrsinam3lzkw66tzeobg7qzqusutkdzwsh6e6egfnh5qxfj7cnzxdpi66u4uol4rs4qljnljinpgksia34"),
            (Base::Base32Upper, "A45SAPU6OURQSICGT5HS7NYDIR73MRI3M3XPHR57F43WXQC5T7IUPLTAAFYRIQCXSLNNSYEFWYDWXDSOMO2XRSINAM3LZKW66TZEOBG7QZQUSUTKDZWSH6E6EGFNH5QXFJ7CNZXDPI66U4UOL4RS4QLJNLJINPGKSIA34"),
            (Base::Base32HexLower, "0sti0fkuekhgi826jt7ivdo38hvrch8rcrnf7htv5srmng2tjv8kfbj005oh8g2nibddio45mo3mn3ieceqnhi8d0crbpamuujp4e16vgpgkikja3pmi7u4u465d7tgn59v2dpn3f8uukskebshisgb9db98df6ai80rs"),
            (Base::Base32HexUpper, "0STI0FKUEKHGI826JT7IVDO38HVRCH8RCRNF7HTV5SRMNG2TJV8KFBJ005OH8G2NIBDDIO45MO3MN3IECEQNHI8D0CRBPAMUUJP4E16VGPGKIKJA3PMI7U4U465D7TGN59V2DPN3F8UUKSKEBSHISGB9DB98DF6AI80RS"),
            (Base::Base32Z, "yh71yxw6qwto1engu7819padet95cte5c5zx8t79fh5szon7u9ewxmuyyfateonz1mpp1arfsadszd1qcq4zt1epyc5m3ks66u3rqbg9o3ow1wukd3s186r6rgfp87ozfj9np3zdxe66whwqmht1homjpmjepxgk1ey5h"),
            (Base::Base36Lower, "40lqkyrdflt5v9goe8qxj6v8om6uxyo6iybtcvwxzwmvla5jsgml8cgwg6a3xa7njoxzp468s6m0y8p6ao34ju25n0pq4ufqgta4mnzdndn1lfrfu2oznv4ahta8bsg2oqalj92no7qvtscymndyc9u2rtuacvy"),
            (Base::Base36Upper, "40LQR8EHJ6ME58F065O9TNCQ3T2ZWFYGCRG6L8O8A1EJI7FS8GEKPH2FMBOMIZQS37C38GAUL9H647S6AYUPCMDQFPQSEX5HDAPQGCE2FHI11GPD5KO0TSJ2H99M2RNEOC2LY0UV77A2G7HNELBDU4XWODJJZJY"),
            (Base::Base58Flickr, "qay7kq5wDXCsRyvdbDwvtZYGNjcuSYuTsyaCQpjkHt9subP7qmVoBLMfbhr4vDFhBDR98bZVWDQ8ZLT4zakLhCRwhzH2FRNxRtXV57X5pEaWF447Ea2NUZnsSCk5bQqz4xrkufEogbbs"),
            (Base::Base58Btc, "RAZ7SAQ7ePhs1oGoUSnwJgdHSY4SVaKtBHd4Z7LgYihSJ14FAGHMi331doB5Sz8pK5kdLWokERTFqJd1gYjt56z5WkxZ86FXwcd5PbqdRqfvWgyimXRThMfLfFw9H7yPLLyrUE3TyHU1"),
            (Base::Base64, "BzsgPp51IwkgRp9PL7cDRH+2RRtm7vPHvy83a8Bdn9FHrmABcRRAV5La2WCFtgdrjk5jtXjJDQM2vKre9PJHBN+GYUlSah5tI/ieIYrT9hcqfibm43o96nKOXyMuQWlq0oa8ypIBvg"),
            (Base::Base64Url, "BzsgPp51IwkgRp9PL7cDRH-2RRtm7vPHvy83a8Bdn9FHrmABcRRAV5La2WCFtgdrjk5jtXjJDQM2vKre9PJHBN-GYUlSah5tI_ieIYrT9hcqfibm43o96nKOXyMuQWlq0oa8ypIBvg"),
            (Base::Base256Emoji, "🌓🤷😅🌞🤩🦋😄🤘😟😏👶🌚✋👈🙂💣🌟🏆🎊💘⚡💕😚👉⚠✅😉🎵🤝🌹😬🤤⚠⚽🙊🪐✅💾😋😑🌼😗🍒😥🖕🤬🌓🙃🤞👇💃💨😣🦋🌍🛰🤦💟😰🐷👻👐🤩🌌☎💝🤤😀❣😬😘🌷🔥🥵🐶👏💫🤧🤮❤😆😠💖🍑👆💐😌🐸🥺🤞🥳🔥☺💗🌟😬🤠💝💟😷🌼🪐😖")
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

        let s = "bhkasmcdumvzxiidlmv4qcaja42hlepmnedftr7ibzzo56qaswo6jvdmypljivo3b3imhjxqfnsvq";
        let mk = EncodedMultikey::try_from(s).unwrap();

        let vlad = Builder::default()
            .with_signing_key(&mk)
            .with_cid(&cid)
            .with_base_encoding(Base::Base32Z)
            .try_build_encoded()
            .unwrap();

        // make sure the signature checks out
        assert_eq!((), vlad.verify(&mk).unwrap());
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
