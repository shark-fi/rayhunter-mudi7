#!/usr/bin/env python3
"""Build an OpenWrt .ipk for the Rayhunter GL-E5800 (Mudi 7) port.

No OpenWrt SDK required: this constructs control.tar.gz + data.tar.gz (root-owned,
correct modes) and wraps them in a gzipped-tar outer archive. Run after building
the aarch64-musl daemon binary.

NOTE: the outer container is a gzipped tar (debian-binary, control.tar.gz,
data.tar.gz), NOT a Debian-style `ar` archive. GL.iNet's opkg (OpenWrt 23.05)
rejects the `ar` form as "Malformed package file"; the tar.gz form installs cleanly.

Usage:
    python3 build-ipk.py \
        --binary ../target/aarch64-unknown-linux-musl/firmware-devel/rayhunter-daemon \
        --outdir ../../dist
"""
import argparse
import io
import os
import tarfile

PKG = "rayhunter-mudi7"
VERSION = "0.11.2-3"
ARCH = "aarch64_cortex-a53"
MTIME = 1609459200  # fixed for reproducible archives

HERE = os.path.dirname(os.path.abspath(__file__))


def _tarinfo(name, size, mode, is_dir=False):
    ti = tarfile.TarInfo(name)
    ti.size = size
    ti.mode = mode
    ti.mtime = MTIME
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = "root"
    ti.type = tarfile.DIRTYPE if is_dir else tarfile.REGTYPE
    return ti


def build_tar_gz(entries, dirs):
    """entries: list of (arcname, bytes, mode). dirs: list of arcname."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.GNU_FORMAT) as tar:
        for d in dirs:
            tar.addfile(_tarinfo(d, 0, 0o755, is_dir=True))
        for arcname, data, mode in entries:
            tar.addfile(_tarinfo(arcname, len(data), mode), io.BytesIO(data))
    return buf.getvalue()


def build_outer_ipk(members):
    """Wrap the .ipk members in a gzipped tar. `members`: list of (name, bytes).
    Order matters: debian-binary must come first."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.GNU_FORMAT) as tar:
        for name, data in members:
            tar.addfile(_tarinfo(name, len(data), 0o644), io.BytesIO(data))
    return buf.getvalue()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True, help="path to rayhunter-daemon (aarch64)")
    ap.add_argument("--outdir", default=os.path.join(HERE, "dist"))
    args = ap.parse_args()

    with open(args.binary, "rb") as f:
        binary = f.read()
    bridge = open(os.path.join(HERE, "rayhunter-diag-bridge"), "rb").read()
    initsc = open(os.path.join(HERE, "rayhunter.init"), "rb").read()
    config = open(os.path.join(HERE, "config.toml"), "rb").read()

    # --- data.tar.gz: the installed filesystem tree ---
    data_dirs = ["./", "./usr/", "./usr/bin/", "./etc/", "./etc/init.d/", "./etc/rayhunter/"]
    data_entries = [
        ("./usr/bin/rayhunter-daemon", binary, 0o755),
        ("./usr/bin/rayhunter-diag-bridge", bridge, 0o755),
        ("./etc/init.d/rayhunter", initsc, 0o755),
        ("./etc/rayhunter/config.toml", config, 0o644),
    ]
    data_tar = build_tar_gz(data_entries, data_dirs)
    installed_size = sum(len(d) for _, d, _ in data_entries)

    # --- control.tar.gz: metadata + maintainer scripts ---
    control = (
        f"Package: {PKG}\n"
        f"Version: {VERSION}\n"
        f"Architecture: {ARCH}\n"
        "Maintainer: SharkFi <shark-fi@users.noreply.github.com>\n"
        "Section: net\n"
        "Priority: optional\n"
        f"Installed-Size: {installed_size}\n"
        "Source: https://github.com/EFForg/rayhunter\n"
        "Description: EFF Rayhunter IMSI-catcher detector, ported to the GL.iNet\n"
        " GL-E5800 (Mudi 7). The RG650 modem is MHI-attached and its DIAG is owned\n"
        " by diag-router (no /dev/diag), so this build consumes DIAG over a local\n"
        " TCP socket fed by Qualcomm's diag_socket_log. Web UI on port 8088.\n"
    ).encode("ascii")
    postinst = open(os.path.join(HERE, "postinst"), "rb").read()
    prerm = open(os.path.join(HERE, "prerm"), "rb").read()
    conffiles = open(os.path.join(HERE, "conffiles"), "rb").read()
    control_entries = [
        ("./control", control, 0o644),
        ("./postinst", postinst, 0o755),
        ("./prerm", prerm, 0o755),
        ("./conffiles", conffiles, 0o644),
    ]
    control_tar = build_tar_gz(control_entries, ["./"])

    # --- outer archive (.ipk): gzipped tar, debian-binary first ---
    ipk = build_outer_ipk([
        ("debian-binary", b"2.0\n"),
        ("control.tar.gz", control_tar),
        ("data.tar.gz", data_tar),
    ])

    os.makedirs(args.outdir, exist_ok=True)
    out = os.path.join(args.outdir, f"{PKG}_{VERSION}_{ARCH}.ipk")
    with open(out, "wb") as f:
        f.write(ipk)
    print(f"wrote {out} ({len(ipk)} bytes, installed-size {installed_size} bytes)")


if __name__ == "__main__":
    main()
