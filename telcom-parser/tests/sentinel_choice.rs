use asn1_codecs::{PerCodecData, uper::UperCodec};
use asn1_codecs_derive::UperCodec;

#[derive(Debug, PartialEq, UperCodec)]
#[asn(type = "INTEGER", lb = "0", ub = "255")]
struct Byte(u8);

#[derive(Debug, PartialEq, UperCodec)]
#[asn(type = "CHOICE", lb = "0", ub = "1", extensible = true)]
enum Choice {
    #[asn(key = 0, extended = false)]
    Root0(Byte),
    #[asn(key = 1, extended = false)]
    Root1(Byte),
    #[asn(key = 0, extended = true)]
    Extension0(Byte),
    #[asn(key = 1, extended = true)]
    Extension1(Byte),
}

#[test]
fn independent_x691_root_and_extension_vectors() {
    // Root: extension bit 0, root index, eight value bits.
    // Extension: bit 1, normally-small index (0 + 6 bits), length octet, value.
    for (bytes, expected) in [
        (vec![0x2a, 0x80], Choice::Root0(Byte(0xaa))),
        (vec![0x6a, 0x80], Choice::Root1(Byte(0xaa))),
        (vec![0x80, 0x01, 0xaa], Choice::Extension0(Byte(0xaa))),
        (vec![0x81, 0x01, 0xaa], Choice::Extension1(Byte(0xaa))),
    ] {
        let mut data = PerCodecData::from_slice_uper(&bytes);
        assert_eq!(Choice::uper_decode(&mut data).unwrap(), expected);
        let mut encoded = PerCodecData::new_uper();
        if matches!(expected, Choice::Root0(_) | Choice::Root1(_)) {
            expected.uper_encode(&mut encoded).unwrap();
            assert_eq!(encoded.into_bytes(), bytes);
        }
    }
}

#[test]
fn extension_open_type_cannot_consume_following_field() {
    let mut data = PerCodecData::from_slice_uper(&[0x81, 0x01, 0xaa, 0x55]);
    assert_eq!(
        Choice::uper_decode(&mut data).unwrap(),
        Choice::Extension1(Byte(0xaa))
    );
    assert_eq!(Byte::uper_decode(&mut data).unwrap(), Byte(0x55));
}

#[test]
fn truncated_unknown_empty_and_short_extensions_fail() {
    for bytes in [
        vec![0x81],
        vec![0x81, 1],
        vec![0x82, 1, 0xaa],
        vec![0x81, 0],
    ] {
        assert!(Choice::uper_decode(&mut PerCodecData::from_slice_uper(&bytes)).is_err());
    }
}

#[test]
fn extension_octets_at_unaligned_offset() {
    let mut encoded = PerCodecData::new_uper();
    asn1_codecs::uper::encode::encode_bool(&mut encoded, true).unwrap();
    // Independent extension wire encoding; upstream extension encoding is unsupported.
    Byte(0x81).uper_encode(&mut encoded).unwrap();
    Byte(1).uper_encode(&mut encoded).unwrap();
    Byte(0x37).uper_encode(&mut encoded).unwrap();
    Byte(0xa5).uper_encode(&mut encoded).unwrap();
    let mut data = PerCodecData::from_slice_uper(&encoded.into_bytes());
    assert!(asn1_codecs::uper::decode::decode_bool(&mut data).unwrap());
    assert_eq!(
        Choice::uper_decode(&mut data).unwrap(),
        Choice::Extension1(Byte(0x37))
    );
    assert_eq!(Byte::uper_decode(&mut data).unwrap(), Byte(0xa5));
}
