"""Prepare checksum-pinned decoder corrections without republishing dependency source."""

import argparse
import hashlib
import io
from pathlib import Path
import tarfile
import urllib.request

DERIVE_SHA256 = "129a9f02b40e743766102dbbb93464b5868fb5e264a02a10d87fb45c472dd4b7"
NAS_REVISION = "9e72e40bee9c3c09205ad871cf681628b443de7c"
NAS_SHA256 = "a155d5f9fd9b7f277da34839a6d7e738e5a76155dbc71387a00c6c856bb382f9"


def replace_once(path, old, new):
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise ValueError(f"Expected exactly one correction anchor in {path}")
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


def extract(path, url, checksum, destination):
    content = path.read_bytes() if path else urllib.request.urlopen(url, timeout=60).read()
    if hashlib.sha256(content).hexdigest() != checksum:
        raise ValueError(f"Source checksum mismatch for {url}")
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
        archive.extractall(destination, filter="data")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--derive-crate", type=Path)
    parser.add_argument("--nas-archive", type=Path)
    args = parser.parse_args()
    vendor = Path(__file__).resolve().parents[1] / "sentinel-vendor"
    if vendor.exists():
        raise ValueError("Decoder directory already exists; use a fresh checkout to prepare dependencies")
    vendor.mkdir()
    extract(args.derive_crate,
            "https://static.crates.io/crates/asn1_codecs_derive/asn1_codecs_derive-0.7.1.crate",
            DERIVE_SHA256, vendor)
    extract(args.nas_archive, f"https://codeload.github.com/EFForg/pycrate-rs/tar.gz/{NAS_REVISION}",
            NAS_SHA256, vendor)
    choice = vendor / "asn1_codecs_derive-0.7.1/src/per/choice.rs"
    replace_once(choice, "    let lb = params.lb", """    let (open_decode, inner_from) = if aligned {
        (quote!(asn1_codecs::aper::decode::decode_octetstring),
         quote!(asn1_codecs::PerCodecData::from_slice_aper))
    } else {
        (quote!(asn1_codecs::uper::decode::decode_octetstring),
         quote!(asn1_codecs::PerCodecData::from_slice_uper))
    };
    let lb = params.lb""")
    replace_once(choice, """                if !extended {
                    match idx {""", """                let mut open_data;
                let data = if extended {
                    let bytes = #open_decode(data, None, None, false)?;
                    if bytes.is_empty() || bytes.len() > 65535 {
                        return Err(asn1_codecs::PerCodecError::new(
                            asn1_codecs::PerCodecErrorCause::Generic,
                            "Invalid CHOICE extension open-type length"));
                    }
                    open_data = #inner_from(&bytes);
                    &mut open_data
                } else { data };
                    match (idx, extended) {""")
    replace_once(choice, """                    }
                } else {
                    Err(asn1_codecs::PerCodecError::new(
                            asn1_codecs::PerCodecErrorCause::EncodeNotSupported,
                            "CHOICE Additions not supported yet."))
                }""", "                    }")
    replace_once(choice, "#key => Ok(Self::#variant_ident(#ty::#codec_decode_fn(data)?)),",
                 "(#key, #extended) => Ok(Self::#variant_ident(#ty::#codec_decode_fn(data)?)),")
    replace_once(vendor / f"pycrate-rs-{NAS_REVISION}/src/nas/generated/esm/esmpdn_disconnect_request.rs",
                 '#[deku(pad_bits_before = "4")] pub linked_eps_bearer_id: Type1V<u8>,',
                 '#[deku(pad_bits_before = "4", bits = "4")] pub linked_eps_bearer_id: u8,')
    print("Prepared the two pinned decoder corrections; original dependency manifests retained.")


if __name__ == "__main__":
    main()
