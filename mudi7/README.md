# Mudi 7 packaging

OpenWrt `.ipk` packaging for the Rayhunter GL-E5800 (Mudi 7) port.

## Files

| File | Installed to | Purpose |
|---|---|---|
| `config.toml` | `/etc/rayhunter/config.toml` (conffile) | `device = "gle5800"`, web port 8088, qmdl store `/data/rayhunter/qmdl` |
| `rayhunter.init` | `/etc/init.d/rayhunter` | procd service: daemon + diag bridge instances |
| `rayhunter-diag-bridge` | `/usr/bin/rayhunter-diag-bridge` | runs `diag_socket_log` → rayhunter's `127.0.0.1:25011` listener |
| `postinst` / `prerm` | (maintainer scripts) | enable+start on install; stop+disable on remove |
| `conffiles` | (metadata) | marks `config.toml` so upgrades don't clobber edits |
| `build-ipk.py` | — | builds the `.ipk` from a pre-built daemon binary + these files |

The 17 MB `rayhunter-daemon` binary is installed to `/usr/bin/rayhunter-daemon`.

## Package format note

The `.ipk` outer container is a **gzipped tar** of `debian-binary`, `control.tar.gz`,
and `data.tar.gz` — **not** a Debian-style `ar` archive. GL.iNet's opkg (OpenWrt
23.05) rejects the `ar` form with `pkg_init_from_file: Malformed package file`;
the tar.gz form installs cleanly. `build-ipk.py` emits the tar.gz form.

## DIAG data path

```
RG650 modem (MHI) → diag-router → diag_socket_log -a 127.0.0.1 -p 25011
                                      → TCP → rayhunter-daemon (device=gle5800)
```

Architecture: `aarch64_cortex-a53`. Web UI: port 8088 (8080 is GL's uhttpd).
