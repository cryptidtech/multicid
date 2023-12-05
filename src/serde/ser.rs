use crate::{vlad, Cid, Vlad};
use multicodec::Codec;
use multihash::{EncodedMultihash, Multihash};
use multiutil::{Base58Encoder, BaseEncoded, CodecInfo, EncodingInfo};
use serde::ser::{self, SerializeStruct};

/// Serialize instance of [`crate::Cid`]
impl ser::Serialize for Cid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            let mut ss = serializer.serialize_struct("cid", 3)?;
            ss.serialize_field("version", &self.codec)?;
            ss.serialize_field("encoding", &self.target_codec)?;
            if self.codec() == Codec::Identity {
                ss.serialize_field(
                    "hash",
                    &BaseEncoded::<Multihash, Base58Encoder>::new(
                        self.encoding(),
                        self.hash.clone(),
                    ),
                )?;
            } else {
                ss.serialize_field(
                    "hash",
                    &EncodedMultihash::new(self.encoding(), self.hash.clone()),
                )?;
            }
            ss.end()
        } else {
            (self.codec, self.target_codec, self.hash.clone()).serialize(serializer)
        }
    }
}

/// Serialize instance of [`crate::Vlad`]
impl ser::Serialize for Vlad {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            let mut ss = serializer.serialize_struct(vlad::SIGIL.as_str(), 2)?;
            ss.serialize_field("nonce", &self.nonce)?;
            ss.serialize_field("cid", &self.cid)?;
            ss.end()
        } else {
            (vlad::SIGIL, self.nonce.clone(), self.cid.clone()).serialize(serializer)
        }
    }
}
