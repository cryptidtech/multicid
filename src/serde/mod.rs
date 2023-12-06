//! Serde (de)serialization for [`crate::Cid`] and [`crate::Vlad`]
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::{cid, vlad};
    use multicodec::Codec;
    use multihash::mh;
    use multikey::nonce;
    use serde_test::{assert_tokens, Configure, Token};

    #[test]
    fn test_cidv0_serde_compact() {
        let v0 = cid::Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        assert_tokens(
            &v0.compact(),
            &[
                Token::Tuple { len: 3 },
                Token::BorrowedBytes(&[0]),
                Token::BorrowedBytes(&[112]),
                Token::Tuple { len: 3 },
                Token::BorrowedBytes(&[49]),
                Token::BorrowedBytes(&[18]),
                Token::BorrowedBytes(&[
                    32, 226, 140, 122, 235, 58, 135, 107, 37, 237, 130, 36, 114, 228, 122, 105,
                    111, 226, 82, 20, 193, 103, 47, 9, 114, 25, 95, 155, 100, 238, 164, 30, 126,
                ]),
                Token::TupleEnd,
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_cidv0_serde_encoded_string() {
        let v0 = cid::Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build_legacy_encoded()
            .unwrap();

        assert_tokens(
            &v0.readable(),
            &[Token::BorrowedStr(
                "Qmdb16CztyugMSs5anEPrJ6bLeo39bTGcM13zNPqjqUidT",
            )],
        );
    }

    #[test]
    fn test_cidv0_serde_readable() {
        let v0 = cid::Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        assert_tokens(
            &v0.readable(),
            &[
                Token::Struct {
                    name: "cid",
                    len: 3,
                },
                Token::BorrowedStr("version"),
                Token::U64(0),
                Token::BorrowedStr("encoding"),
                Token::BorrowedStr("dag-pb"),
                Token::BorrowedStr("hash"),
                Token::BorrowedStr("Qmdb16CztyugMSs5anEPrJ6bLeo39bTGcM13zNPqjqUidT"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_cidv0_serde_json() {
        let v0 = cid::Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let s = serde_json::to_string(&v0).unwrap();
        assert_eq!(s, "{\"version\":0,\"encoding\":\"dag-pb\",\"hash\":\"Qmdb16CztyugMSs5anEPrJ6bLeo39bTGcM13zNPqjqUidT\"}");
        assert_eq!(v0, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_cidv0_serde_cbor() {
        let v0 = cid::Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let v = serde_cbor::to_vec(&v0).unwrap();
        //println!("{}", hex::encode(&v));
        assert_eq!(v, hex::decode("83410041708341314112582120e28c7aeb3a876b25ed822472e47a696fe25214c1672f0972195f9b64eea41e7e").unwrap());
        assert_eq!(v0, serde_cbor::from_slice(&v).unwrap());
    }

    #[test]
    fn test_cidv1_serde_compact() {
        let v1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        assert_tokens(
            &v1.compact(),
            &[
                Token::Tuple { len: 3 },
                Token::BorrowedBytes(&[1]),
                Token::BorrowedBytes(&[113]),
                Token::Tuple { len: 3 },
                Token::BorrowedBytes(&[49]),
                Token::BorrowedBytes(&[20]),
                Token::BorrowedBytes(&[
                    64, 87, 146, 218, 217, 96, 133, 182, 7, 107, 142, 78, 99, 181, 120, 201, 13, 3,
                    54, 188, 170, 222, 244, 242, 71, 4, 223, 134, 97, 73, 82, 106, 30, 109, 35,
                    248, 158, 33, 138, 211, 246, 23, 42, 126, 38, 230, 227, 122, 61, 234, 114, 142,
                    95, 35, 46, 65, 105, 106, 210, 134, 188, 202, 146, 1, 190,
                ]),
                Token::TupleEnd,
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_cidv1_serde_encoded_string() {
        let v1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build_encoded()
            .unwrap();

        assert_tokens(
            &v1.readable(),
            &[Token::BorrowedStr(
                "zBwWX6osYqv4RE9txKLpnJsiQ9kKAdRhhkmeBvsQtFVw69VXwfhxiBxstMsNXbuhsCqKoppSS3GPKQBW3tWB4CtUNUTo3"
            )],
        );
    }

    #[test]
    fn test_cidv1_serde_readable() {
        let v1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        assert_tokens(
            &v1.readable(),
            &[
                Token::Struct {
                    name: "cid",
                    len: 3,
                },
                Token::BorrowedStr("version"),
                Token::U64(1),
                Token::BorrowedStr("encoding"),
                Token::BorrowedStr("dag-cbor"),
                Token::BorrowedStr("hash"),
                Token::BorrowedStr("z8tVp1WM84GvufkEFRWou2NMv87nvNd8hqvDGeoD2Y4y1qiQYXDyAQqKQbb5KnJBignW6W8JHaWHKnSTuN95XoZgddo"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_vlad_serde_compact() {
        let bytes = hex::decode("d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832")
            .unwrap();
        let nonce = nonce::Builder::new_from_bytes(&bytes).try_build().unwrap();

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

        let vlad = vlad::Builder::default()
            .with_nonce(&nonce)
            .with_cid(&cid)
            .try_build()
            .unwrap();

        assert_tokens(
            &vlad.compact(),
            &[
                Token::Tuple { len: 3 },
                Token::BorrowedBytes(&[7]),
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[59]),
                Token::BorrowedBytes(&[
                    32, 209, 92, 79, 178, 145, 26, 225, 51, 127, 16, 43, 202, 244, 192, 8, 141, 54,
                    52, 91, 136, 178, 67, 150, 142, 131, 76, 95, 250, 23, 144, 120, 50,
                ]),
                Token::TupleEnd,
                Token::Tuple { len: 3 },
                Token::BorrowedBytes(&[1]),
                Token::BorrowedBytes(&[113]),
                Token::Tuple { len: 3 },
                Token::BorrowedBytes(&[49]),
                Token::BorrowedBytes(&[20]),
                Token::BorrowedBytes(&[
                    64, 87, 146, 218, 217, 96, 133, 182, 7, 107, 142, 78, 99, 181, 120, 201, 13, 3,
                    54, 188, 170, 222, 244, 242, 71, 4, 223, 134, 97, 73, 82, 106, 30, 109, 35,
                    248, 158, 33, 138, 211, 246, 23, 42, 126, 38, 230, 227, 122, 61, 234, 114, 142,
                    95, 35, 46, 65, 105, 106, 210, 134, 188, 202, 146, 1, 190,
                ]),
                Token::TupleEnd,
                Token::TupleEnd,
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_vlad_serde_encoded_string() {
        let bytes = hex::decode("d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832")
            .unwrap();
        let nonce = nonce::Builder::new_from_bytes(&bytes).try_build().unwrap();

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

        let vlad = vlad::Builder::default()
            .with_nonce(&nonce)
            .with_cid(&cid)
            .try_build_encoded()
            .unwrap();

        assert_tokens(
            &vlad.readable(),
            &[Token::BorrowedStr("f073b20d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832017114405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be")
            ],
        );
    }

    #[test]
    fn test_vlad_serde_readable() {
        let bytes = hex::decode("d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832")
            .unwrap();
        let nonce = nonce::Builder::new_from_bytes(&bytes).try_build().unwrap();

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

        let vlad = vlad::Builder::default()
            .with_nonce(&nonce)
            .with_cid(&cid)
            .try_build()
            .unwrap();

        assert_tokens(
            &vlad.readable(),
            &[
                Token::Struct {
                    name: "vlad",
                    len: 2,
                },
                Token::BorrowedStr("nonce"),
                Token::Struct {
                    name: "nonce",
                    len: 1,
                },
                Token::BorrowedStr("nonce"),
                Token::BorrowedStr(
                    "f20d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832",
                ),
                Token::StructEnd,
                Token::BorrowedStr("cid"),
                Token::Struct {
                    name: "cid",
                    len: 3,
                },
                Token::BorrowedStr("version"),
                Token::U64(1),
                Token::BorrowedStr("encoding"),
                Token::BorrowedStr("dag-cbor"),
                Token::BorrowedStr("hash"),
                Token::BorrowedStr("z8tVp1WM84GvufkEFRWou2NMv87nvNd8hqvDGeoD2Y4y1qiQYXDyAQqKQbb5KnJBignW6W8JHaWHKnSTuN95XoZgddo"),
                Token::StructEnd,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_vlad_serde_json() {
        let bytes = hex::decode("d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832")
            .unwrap();
        let nonce = nonce::Builder::new_from_bytes(&bytes).try_build().unwrap();

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

        let vlad = vlad::Builder::default()
            .with_nonce(&nonce)
            .with_cid(&cid)
            .try_build()
            .unwrap();

        let s = serde_json::to_string(&vlad).unwrap();
        assert_eq!(s, "{\"nonce\":{\"nonce\":\"f20d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832\"},\"cid\":{\"version\":1,\"encoding\":\"dag-cbor\",\"hash\":\"z8tVp1WM84GvufkEFRWou2NMv87nvNd8hqvDGeoD2Y4y1qiQYXDyAQqKQbb5KnJBignW6W8JHaWHKnSTuN95XoZgddo\"}}");
        assert_eq!(vlad, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_vlad_serde_cbor() {
        let bytes = hex::decode("d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832")
            .unwrap();
        let nonce = nonce::Builder::new_from_bytes(&bytes).try_build().unwrap();

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

        let vlad = vlad::Builder::default()
            .with_nonce(&nonce)
            .with_cid(&cid)
            .try_build()
            .unwrap();

        let v = serde_cbor::to_vec(&vlad).unwrap();
        assert_eq!(v, hex::decode("83410782413b582120d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832834101417183413141145841405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be").unwrap());
        assert_eq!(vlad, serde_cbor::from_slice(&v).unwrap());
    }
}
