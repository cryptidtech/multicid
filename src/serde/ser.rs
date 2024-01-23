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
            ss.serialize_field("version", &self.codec.code())?;
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
            #[cfg(feature = "dag_cbor")]
            {
                // build the byte string for DAG-CBOR according to the spec
                // https://github.com/ipld/specs/blob/master/block-layer/codecs/dag-cbor.md#links
                let mut v = Vec::new();
                // start with the Identity codec (0x00)
                v.append(&mut Codec::Identity.into());
                // add in the binary serialized CID
                v.append(&mut self.clone().into());
                // annotate the bytes
                let bytes = serde_cbor::value::Value::Bytes(v);
                // wrap it as a tagged object with tag 42
                let tagged = serde_cbor::tags::Tagged::new(Some(42_u64), bytes);
                // serialize the tagged data
                tagged.serialize(serializer)
            }

            #[cfg(not(feature = "dag_cbor"))]
            {
                let v: Vec<u8> = self.clone().into();
                serializer.serialize_bytes(v.as_slice())
            }
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
