#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地秒级复现：任意 APK → 构造与 dexonly 产物同构的假产物 → multiplex → v2_sign → 逐 entry 验证。
用法: cd signature-killer && python3 _debug_multiplex.py /path/to/input.apk
输出里第一个 "bad entry" 就是根因。
"""
import argparse, os, struct, subprocess, sys, tempfile, zipfile, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import data_multiplexing as dm


def run(cmd):
    print("+", " ".join(cmd), flush=True)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.stdout: print(r.stdout, end="")
    if r.stderr: print(r.stderr, end="")
    if r.returncode != 0:
        raise SystemExit("FAIL: " + cmd[0])
    return r


def build_fake_processed(orig_apk, out_path):
    data = open(orig_apk, "rb").read()
    eocd = dm.find_eocd(data)
    if eocd < 0:
        raise SystemExit("bad apk: no EOCD")
    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
    cd_size = struct.unpack_from("<I", data, eocd + 12)[0]
    entries = dm.parse_entries(data, cd_off, cd_size)

    buf = bytearray()
    centrals = []
    seen = set()
    for e in entries:
        ns = e["name_str"]
        if ns in seen:
            continue
        seen.add(ns)
        comp = dm.read_entry_data(data, e)
        if comp is None:
            raise SystemExit("bad entry: " + ns)
        if ns == "classes.dex":
            payload = comp
            crc = zlib.crc32(payload) & 0xffffffff
            off = len(buf)
            buf += dm.build_local(e["name"], 0, crc, len(payload), len(payload), off, True) + payload
            centrals.append(dm.build_central(e["name"], 0, crc, len(payload), len(payload), off))
        else:
            lh = dm.build_local(e["name"], e["method"], e["crc"], e["comp_size"],
                                e["uncomp_size"], len(buf), True, e["flags"] & ~8)
            off = len(buf)
            buf += lh + comp
            centrals.append(dm.central_from_old(data, e, off))

    orig_bytes = data
    name_b = b"assets/SignedByRS/input.apk"
    crc = zlib.crc32(orig_bytes) & 0xffffffff
    off = len(buf)
    buf += dm.build_local(name_b, 0, crc, len(orig_bytes), len(orig_bytes), off, True) + orig_bytes
    centrals.append(dm.build_central(name_b, 0, crc, len(orig_bytes), len(orig_bytes), off))

    lib_b = b"FAKELIB" * 100
    name_b = b"lib/arm64-v8a/libDebugFake.so"
    crc = zlib.crc32(lib_b) & 0xffffffff
    off = len(buf)
    buf += dm.build_local(name_b, 0, crc, len(lib_b), len(lib_b), off, True) + lib_b
    centrals.append(dm.build_central(name_b, 0, crc, len(lib_b), len(lib_b), off))

    cd_new = len(buf)
    cd = b"".join(centrals)
    buf += cd
    buf += dm.build_eocd(cd_new, len(cd), len(centrals))
    with open(out_path, "wb") as f:
        f.write(buf)
    print("[ok] fake processed: %d bytes (%d entries)" % (len(buf), len(centrals)))


def verify(apk_path, label):
    import zipcheck
    _, bad = zipcheck.verify_zip_file(apk_path, label)
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("apk", help="任意原始 APK（如 action 里用的 app-release.apk）")
    a = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="dmtest_")
    fake = os.path.join(tmp, "fake.apk")
    opt = os.path.join(tmp, "opt.apk")
    v2 = os.path.join(tmp, "v2tmp.apk")

    verify(a.apk, "original apk (control)")
    build_fake_processed(a.apk, fake)
    verify(fake, "fake processed")

    tmp2 = tempfile.mkdtemp(prefix="dmkeys_")
    key = os.path.join(tmp2, "key.pem")
    cert_pem = os.path.join(tmp2, "cert.pem")
    cert_der = os.path.join(tmp2, "cert.der")
    pk8 = os.path.join(tmp2, "pk8.der")
    pub_pem = os.path.join(tmp2, "pub.pem")
    pub_der = os.path.join(tmp2, "pub.der")
    for cmd in (
        ["openssl", "genrsa", "-out", key, "2048"],
        ["openssl", "req", "-new", "-x509", "-key", key, "-out", cert_pem, "-days", "1", "-subj", "/CN=K"],
        ["openssl", "x509", "-in", cert_pem, "-outform", "DER", "-out", cert_der],
        ["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", key, "-outform", "DER", "-out", pk8],
        ["openssl", "x509", "-in", cert_pem, "-pubkey", "-noout", "-out", pub_pem],
        ["openssl", "pkey", "-pubin", "-outform", "DER", "-in", pub_pem, "-out", pub_der],
    ):
        subprocess.run(cmd, check=True, capture_output=True)

    run(["python3", os.path.join(HERE, "data_multiplexing.py"),
         "--input", fake, "--output", opt])
    verify(opt, "opt (multiplexed)")

    run(["python3", os.path.join(HERE, "v2_sign.py"),
         "--input", opt, "--output", v2,
         "--key", key, "--cert", cert_der, "--pub", pub_der])
    bad = verify(v2, "v2tmp (re-signed)")
    if bad:
        print("[hint] 第一个 bad entry 就是根因；把完整输出贴回来。")
        sys.exit(1)
    # 真实验签：apksigner verify（只验 V2）
    apksigner_bin = os.popen("command -v apksigner").read().strip()
    if apksigner_bin:
        r = subprocess.run(
            [apksigner_bin, "verify", "--min-sdk-version", "24", v2],
            capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout, end="")
            print(r.stderr, end="")
            print("[FAIL] apksigner V2 verify failed")
            sys.exit(1)
        print("[ok] apksigner V2 verify passed")
    else:
        print("[warn] apksigner not found, skip V2 verify")
    print("[ALL OK] 当前代码在你的 input.apk 上本地验证通过")


if __name__ == "__main__":
    main()
