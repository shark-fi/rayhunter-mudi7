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
| `lib/src/diag_device.rs` | New `DiagTransport::Socket` variant (TCP listener, bare-HDLC I/O, no ioctls) |
| `daemon/src/main.rs` | Headless UI arm for the Mudi 7 (its screen is GL's closed LVGL stack) |
| `mudi7/` | OpenWrt packaging: config, init service, diag bridge, `.ipk` builder |

Everything downstream of the transport (parsing, analyzers, QMDL, web UI) is upstream code.

## Install (LuCI)

1. Download `mudi7/dist/rayhunter-mudi7_0.11.2-1_aarch64_cortex-a53.ipk`
   (or grab it from the repo's Releases).
2. In the router UI go to **System → Software** (LuCI), click **Upload Package…**,
   choose the `.ipk`, and install.
3. Open **`http://192.168.8.1:8088`** for the Rayhunter dashboard.

The package enables and starts the service on install (survives reboot).

### Install (CLI)

```sh
scp rayhunter-mudi7_0.11.2-1_aarch64_cortex-a53.ipk root@192.168.8.1:/tmp/
ssh root@192.168.8.1 'opkg install /tmp/rayhunter-mudi7_0.11.2-1_aarch64_cortex-a53.ipk'
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

# 2. Cross-compile the daemon
cargo build -p rayhunter-daemon --bin rayhunter-daemon \
    --target aarch64-unknown-linux-musl --profile firmware-devel

# 3. Package the .ipk (output lands in mudi7/dist/)
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
