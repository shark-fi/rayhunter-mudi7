# Rayhunter — GL.iNet GL-E5800 (Mudi 7) port

This is a **fork of [EFForg/rayhunter](https://github.com/EFForg/rayhunter)** that adds
support for the **GL.iNet GL-E5800 (Mudi 7)** 5G travel router, packaged as an
installable OpenWrt `.ipk`.

> Not affiliated with or endorsed by the EFF. Rayhunter is the EFF's project; this
> repo only adds a device port. Please support the upstream project.

## Why a port was needed

Rayhunter reads Qualcomm **DIAG** to capture cellular signaling. On most supported
devices it opens `/dev/diag` (the `diagchar` driver) and configures logging with
ioctls. The Mudi 7's RG650 modem is **MHI/PCIe-attached and has no `/dev/diag`** —
its DIAG stream is owned by GL.iNet's `diag-router` userspace daemon.

This fork adds a **socket DIAG transport**: rayhunter listens on `127.0.0.1:25011`
and Qualcomm's `diag_socket_log` (already on the device) taps `diag-router` and
forwards the raw HDLC-framed DIAG stream to it. No `/dev/diag`, no diagchar kernel
module, no ioctls — the existing HDLC parser handles the frames unchanged.

### What's changed vs. upstream

| File | Change |
|---|---|
| `lib/src/lib.rs` | New `Device::GlE5800` (`device = "gle5800"`) |
| `lib/src/diag_device.rs` | New `DiagTransport::Socket` variant (TCP listener, bare-HDLC I/O, no ioctls, enlarged `SO_RCVBUF`) |
| `daemon/src/diag.rs` | Reconnect loop: on a bridge drop, rebuild the device and resume the same recording |
| `daemon/src/main.rs` | Headless UI arm for the Mudi 7 (its screen is GL's closed LVGL stack) |
| `daemon/src/battery/gl_e5800.rs` | Battery level + charge state from the cw221X fuel gauge (sysfs) |
| `mudi7/` | OpenWrt packaging: config, init service, diag bridge, GPS feed (modem GNSS → `/api/gps`), `.ipk` builder |

The LTE decoding changes below also adapt parsing to the Mudi's modem output.
Analyzer heuristics, QMDL format and web UI remain upstream code.

### Draft LTE decoding corrections

The RG650 emits HDLC-framed Qualcomm `0x98` multi-radio wrappers and LTE RRC
header version 30. This branch verifies CRC before bounded wrapper unwrapping,
preserves subscription metadata and parses the version-30 layout/channel mapping.
Segmented version-30 messages are reassembled before live/offline analysis and
PCAP conversion. Assemblies are isolated by subscription, bearer, channel and
radio/header metadata, with limits of eight streams, 65,491 bytes and five seconds.
Observed gaps, duplicate/invalid fragments, corruption and stream boundaries
produce explicit errors rather than analyzing partial RRC messages.

Two locked dependency corrections are also required: ASN.1 CHOICE extension
open-type decoding (separate root/extension index namespaces) and a four-bit
linked bearer field in NAS PDN Disconnect Request. The preparation tool downloads
checksum-pinned dependency archives into an ignored directory and applies only
these corrections. Full dependency sources are not republished in this branch.
Maintainers should review dependency provenance/licensing and decide whether to
use upstream releases or dedicated dependency forks before merging.

Prepare the dependencies before any Cargo command:

```sh
python3 tools/prepare-lte-decoders.py
```

This requires Python 3.12 or newer. Offline archives can be supplied with
`--derive-crate` and `--nas-archive`. The source pins are:

- `asn1_codecs_derive` 0.7.1: SHA-256
  `129a9f02b40e743766102dbbb93464b5868fb5e264a02a10d87fb45c472dd4b7`.
- `EFForg/pycrate-rs` commit `9e72e40bee9c3c09205ad871cf681628b443de7c`:
  codeload archive SHA-256
  `a155d5f9fd9b7f277da34839a6d7e738e5a76155dbc71387a00c6c856bb382f9`.

After building the web assets, run:

```sh
cargo test -p rayhunter -p telcom-parser -p rayhunter-daemon \
  --features tokio/net --locked
```

Seven acceptance tests exercise all eight configured LTE analyzers through
HDLC/CRC-wrapped DIAG packets. They cover 19 independently encoded synthetic
positive/negative scenarios, fragmented Low/High events, interleaved subscriptions,
corruption/boundaries, disabled analyzers and valid/truncated PDN Disconnect requests.
The checked-in JSON needs no Python package for ordinary Rust tests.
Regenerate it with `tools/generate-lte-acceptance.py <ASN-spec-directory> <output-json>`
in an environment containing `asn1tools`.

A private completed capture was replayed locally without overwriting its report:
**21 RRC and three NAS decoding failures became zero**, preserving three Low
Test Analyzer events. A rebuilt daemon on GL firmware 4.10.0 also produced a
fresh real SIB1 event delivered to an Android companion notification. No private
capture, subscriber/tower identifiers, credentials or device configuration is
included here. The read-only `sentinel_validate_capture` example prints counts,
not identifiers.

These results do **not** guarantee zero errors for every modem message, every
attack heuristic, false-positive rates or comprehensive 5G detection. Real
fragmented modem captures have not yet validated the segment semantics.
Terminal ID 7 carries no total fragment count; a lost trailing intermediate
fragment can resemble a legitimate shorter sequence. Unknown CHOICE alternatives
still fail; extension encoding is not added. This remains a draft pending
maintainer review, representative field validation and dependency integration.

## Install (LuCI)

1. Download `mudi7/dist/rayhunter-mudi7_0.11.2-4_aarch64_cortex-a53.ipk`
   (or grab it from the repo's Releases).
2. In the router UI go to **System → Software** (LuCI), click **Upload Package…**,
   choose the `.ipk`, and install.
3. Open **`http://192.168.8.1:8088`** for the Rayhunter dashboard.

The package enables and starts the service on install (survives reboot).

### Install (CLI)

```sh
scp rayhunter-mudi7_0.11.2-4_aarch64_cortex-a53.ipk root@192.168.8.1:/tmp/
ssh root@192.168.8.1 'opkg install /tmp/rayhunter-mudi7_0.11.2-4_aarch64_cortex-a53.ipk'
```

Manage it with `/etc/init.d/rayhunter {start,stop,enable,disable}`. Config lives at
`/etc/rayhunter/config.toml`; recordings at `/data/rayhunter/qmdl`.

> **DIAG is exclusive.** `diag_socket_log` is a single tap on `diag-router`, so
> Rayhunter cannot run at the same time as another DIAG consumer (e.g. a SCAT
> walk-test bridge). Run one at a time.

## Build from source

Prerequisites: Rust with the `aarch64-unknown-linux-musl` target, and Node (for the
web frontend). No C cross-compiler needed (rust-lld linker, rustcrypto TLS).

```sh
# 1. Frontend assets (embedded via include_bytes!)
cd daemon/web && npm install && npm run build && cd ../..

# 2. Prepare the draft decoder dependencies
python3 tools/prepare-lte-decoders.py

# 3. Cross-compile the daemon
cargo build -p rayhunter-daemon --bin rayhunter-daemon \
    --target aarch64-unknown-linux-musl --profile firmware-devel

# 4. Package the .ipk (output lands in mudi7/dist/)
python3 mudi7/build-ipk.py \
    --binary target/aarch64-unknown-linux-musl/firmware-devel/rayhunter-daemon
```

See [`mudi7/README.md`](mudi7/README.md) for packaging details.

## License & attribution

GPL-3.0, same as upstream (see [`LICENSE`](LICENSE)). Forked from
[EFForg/rayhunter](https://github.com/EFForg/rayhunter) at commit
[`97e7e7c`](https://github.com/EFForg/rayhunter/commit/97e7e7c3d08ebf05ab2cd3fa42d6d957996ec923).
Corresponding source for the distributed `.ipk` is this repository.

---

# Rayhunter (upstream)

![Tests](https://github.com/EFForg/rayhunter/actions/workflows/main.yml/badge.svg)

![Rayhunter Logo - An Orca taking a bite out of a cellular signal bar](https://www.eff.org/files/styles/media_browser_preview/public/banner_library/rayhunter-banner.png)

Rayhunter is a project for detecting IMSI catchers, also known as cell-site simulators or stingrays. It was first designed to run on a cheap mobile hotspot called the Orbic RC400L, but thanks to community efforts, it can [support some other devices as well](https://efforg.github.io/rayhunter/supported-devices.html).
It's also designed to be as easy to install and use as possible, regardless of your level of technical skills, and to minimize false positives. 

&rarr;  Check out the [installation guide](https://efforg.github.io/rayhunter/installation.html) to get started.

&rarr; To learn more about the aim of the project, and about IMSI catchers in general, please check out our [introductory blog post](https://www.eff.org/deeplinks/2025/03/meet-rayhunter-new-open-source-tool-eff-detect-cellular-spying). 

&rarr; For discussion, help, or to join the mattermost channel and get involved with the project and community check out the [many ways listed here](https://efforg.github.io/rayhunter/support-feedback-community.html)!

&rarr; To learn more about the project in general check out the [Rayhunter Book](https://efforg.github.io/rayhunter/).

**LEGAL DISCLAIMER:** Use this program at your own risk. We believe running this program does not currently violate any laws or regulations in the United States. However, we are not responsible for civil or criminal liability resulting from the use of this software. If you are located outside of the US please consult with an attorney in your country to help you assess the legal risks of running this program.

*Good Hunting!*
