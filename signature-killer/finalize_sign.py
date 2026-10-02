#!/usr/bin/env python3
"""Final signing stage: inject original V1 trio -> zipalign -> apksig V2-only.
--multiplex 时：data_multiplexing（MT式复用）-> v2_sign（不重排 V2 重签）-> 逐 entry 自检。
"""
import argparse, base64, hashlib, os, re, shutil, struct, subprocess, sys, tempfile, zipfile, zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

KEY_DIR = "work_killer"

def run(cmd):
    print("+", " ".join(cmd), flush=True)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout[-3000:])
        print(r.stderr[-3000:])
        sys.exit(f"FAIL: {cmd[0]}")
    return r

def find_zipalign():
    h = os.environ.get("ANDROID_HOME", "")
    if h:
        bt = os.path.join(h, "build-tools")
        if os.path.isdir(bt):
            for v in sorted(os.listdir(bt), reverse=True):
                p = os.path.join(bt, v, "zipalign")
                if os.path.isfile(p):
                    return p
    return shutil.which("zipalign")

def find_apksig_jar():
    candidates = []
    h = os.environ.get("ANDROID_HOME", "")
    if h:
        bt = os.path.join(h, "build-tools")
        if os.path.isdir(bt):
            for v in sorted(os.listdir(bt), reverse=True):
                candidates.append(os.path.join(bt, v, "lib", "apksigner.jar"))
    candidates.append("/data/data/com.termux/files/usr/share/java/apksigner.jar")
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None

def ensure_keys():
    os.makedirs(KEY_DIR, exist_ok=True)
    key = os.path.join(KEY_DIR, "v2_key.pem")
    cert_pem = os.path.join(KEY_DIR, "v2_cert.pem")
    cert_der = os.path.join(KEY_DIR, "v2_cert.der")
    pk8 = os.path.join(KEY_DIR, "v2_key_pk8.der")
    if not (os.path.isfile(key) and os.path.isfile(cert_pem) and os.path.isfile(cert_der) and os.path.isfile(pk8)):
        run(["openssl", "genrsa", "-out", key, "2048"])
        run(["openssl", "req", "-new", "-x509", "-key", key, "-out", cert_pem,
             "-days", "10950", "-subj", "/CN=K"])
        run(["openssl", "x509", "-in", cert_pem, "-outform", "DER", "-out", cert_der])
        run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", key,
             "-outform", "DER", "-out", pk8])
    pub_pem = os.path.join(KEY_DIR, "v2_pub.pem")
    pub_der = os.path.join(KEY_DIR, "v2_pub.der")
    if not (os.path.isfile(pub_pem) and os.path.isfile(pub_der)):
        run(["openssl", "x509", "-in", cert_pem, "-pubkey", "-noout", "-out", pub_pem])
        run(["openssl", "pkey", "-pubin", "-outform", "DER", "-in", pub_pem, "-out", pub_der])
    return key, pk8, cert_der, pub_der

# ---------- ZIP 字节级工具（保留原压缩字节，供数据复用） ----------

def _find_eocd(data):
    for i in range(len(data) - 22, max(0, len(data) - 65557) - 1, -1):
        if data[i:i + 4] == b"PK\x05\x06":
            return i
    return -1

def _parse_central(data, cd_off, cd_size):
    entries = []
    off = cd_off
    end = cd_off + cd_size
    while off + 46 <= end:
        if data[off:off + 4] != b"PK\x01\x02":
            break
        method = struct.unpack_from("<H", data, off + 10)[0]
        flags = struct.unpack_from("<H", data, off + 8)[0]
        crc = struct.unpack_from("<I", data, off + 16)[0]
        comp = struct.unpack_from("<I", data, off + 20)[0]
        uncomp = struct.unpack_from("<I", data, off + 24)[0]
        nl = struct.unpack_from("<H", data, off + 28)[0]
        el = struct.unpack_from("<H", data, off + 30)[0]
        cl = struct.unpack_from("<H", data, off + 32)[0]
        lho = struct.unpack_from("<I", data, off + 42)[0]
        name = data[off + 46:off + 46 + nl]
        entries.append({
            "name": name,
            "name_str": name.decode("utf-8", "replace"),
            "method": method, "flags": flags, "crc": crc,
            "comp": comp, "uncomp": uncomp,
            "nl": nl, "el": el, "cl": cl, "lho": lho,
        })
        off += 46 + nl + el + cl
    return entries

def _local_len(data, lho):
    nl = struct.unpack_from("<H", data, lho + 26)[0]
    el = struct.unpack_from("<H", data, lho + 28)[0]
    return 30 + nl + el

def _make_local(name_b, method, flags, crc, comp, uncomp):
    lh = bytearray(30 + len(name_b))
    lh[0:4] = b"PK\x03\x04"
    struct.pack_into("<H", lh, 4, 20)
    struct.pack_into("<H", lh, 6, flags)
    struct.pack_into("<H", lh, 8, method)
    struct.pack_into("<I", lh, 14, crc)
    struct.pack_into("<I", lh, 18, comp)
    struct.pack_into("<I", lh, 22, uncomp)
    struct.pack_into("<H", lh, 26, len(name_b))
    struct.pack_into("<H", lh, 28, 0)
    lh[30:30 + len(name_b)] = name_b
    return bytes(lh)

def _make_central(name_b, method, flags, crc, comp, uncomp, offset):
    ce = bytearray(46 + len(name_b))
    ce[0:4] = b"PK\x01\x02"
    struct.pack_into("<H", ce, 4, 20)
    struct.pack_into("<H", ce, 6, 20)
    struct.pack_into("<H", ce, 8, flags)
    struct.pack_into("<H", ce, 10, method)
    struct.pack_into("<I", ce, 16, crc)
    struct.pack_into("<I", ce, 20, comp)
    struct.pack_into("<I", ce, 24, uncomp)
    struct.pack_into("<H", ce, 28, len(name_b))
    struct.pack_into("<I", ce, 42, offset)
    ce[46:] = name_b
    return bytes(ce)

def _make_eocd(cd_off, cd_size, total):
    e = bytearray(22)
    e[0:4] = b"PK\x05\x06"
    struct.pack_into("<H", e, 8, total)
    struct.pack_into("<H", e, 10, total)
    struct.pack_into("<I", e, 12, cd_size)
    struct.pack_into("<I", e, 16, cd_off)
    return bytes(e)

def _extract_cert_from_v2(apk_path):
    try:
        with open(apk_path, "rb") as f:
            data = f.read()
        if len(data) < 32: return None
        eocd = _find_eocd(data)
        if eocd < 0: return None
        cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
        footer_pos = cd_offset - 24
        if footer_pos < 0 or data[footer_pos+8:footer_pos+24] != b"APK Sig Block 42": return None
        block_size = struct.unpack_from("<Q", data, footer_pos)[0]
        off = cd_offset - block_size
        end = cd_offset - 24
        while off + 12 <= end:
            pair_len = struct.unpack_from("<Q", data, off)[0]
            pair_id = struct.unpack_from("<I", data, off + 8)[0]
            off += 12
            if pair_id in (0x7109871a, 0xf05368c0):
                val = data[off:off + pair_len - 4]
                s_len = struct.unpack_from("<I", val, 0)[0]
                signer = val[4:4 + s_len]
                sd_len = struct.unpack_from("<I", signer, 0)[0]
                sd = signer[4:4 + sd_len]
                for i in range(len(sd) - 4):
                    if sd[i] == 0x30 and sd[i+1] == 0x82:
                        c_len = (sd[i+2] << 8) | sd[i+3]
                        if i + 4 + c_len <= len(sd) and c_len > 40:
                            return sd[i:i + 4 + c_len]
            off += int(pair_len - 4)
    except Exception:
        pass
    return None

def inject_v1(input_apk, orig_apk):
    """字节保留式注入原版 V1 三件套：自适应匹配 ANDROIDC.RSA 或从 V2 提取证书。"""
    with zipfile.ZipFile(orig_apk) as z:
        trio = {}
        for n in z.namelist():
            if re.match(r"^META-INF/(MANIFEST\.MF|.*\.(SF|RSA|DSA|EC))$", n, re.I):
                trio[n] = z.read(n)

        rsa_keys = [k for k in trio.keys() if re.search(r"\.(RSA|DSA|EC)$", k, re.I)]
        if rsa_keys and "META-INF/CERT.RSA" not in trio:
            trio["META-INF/CERT.RSA"] = trio[rsa_keys[0]]

        if not rsa_keys:
            cert_der = _extract_cert_from_v2(orig_apk)
            if cert_der:
                trio["META-INF/CERT.RSA"] = cert_der
                if "META-INF/CERT.SF" not in trio:
                    trio["META-INF/CERT.SF"] = b"Signature-Version: 1.0\r\nCreated-By: 1.0 (Android)\r\n\r\n"

        if not trio:
            print("[warn] original has no V1 trio")
            return

    with open(input_apk, "rb") as f:
        data = f.read()
    eocd = _find_eocd(data)
    if eocd < 0:
        raise SystemExit("bad zip in inject_v1")
    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
    cd_size = struct.unpack_from("<I", data, eocd + 12)[0]
    entries = _parse_central(data, cd_off, cd_size)
    skip = set(trio.keys())
    out = bytearray()
    centrals = []
    seen = set()
    for e in entries:
        ns = e["name_str"]
        if ns in seen:
            continue
        seen.add(ns)
        if ns in skip:
            continue
        seg_start = e["lho"]
        seg_len = _local_len(data, seg_start) + e["comp"]
        seg = bytearray(data[seg_start:seg_start + seg_len])
        if struct.unpack_from("<H", seg, 6)[0] & 0x0008:
            struct.pack_into("<H", seg, 6, e["flags"] & ~0x0008)
            struct.pack_into("<H", seg, 8, e["method"])
            struct.pack_into("<I", seg, 14, e["crc"])
            struct.pack_into("<I", seg, 18, e["comp"])
            struct.pack_into("<I", seg, 22, e["uncomp"])
        centrals.append(_make_central(e["name"], e["method"], e["flags"] & ~0x0008,
                                      e["crc"], e["comp"], e["uncomp"], len(out)))
        out += seg
    for name, payload in trio.items():
        name_b = name.encode("utf-8")
        crc = zlib.crc32(payload) & 0xffffffff
        off = len(out)
        out += _make_local(name_b, 0, 0, crc, len(payload), len(payload)) + payload
        centrals.append(_make_central(name_b, 0, 0, crc, len(payload), len(payload), off))
    cd_off_new = len(out)
    cd_bytes = b"".join(centrals)
    out += cd_bytes
    out += _make_eocd(cd_off_new, len(cd_bytes), len(centrals))
    with open(input_apk, "wb") as f:
        f.write(out)
    print("[ok] V1 trio injected (byte-preserving):", list(trio.keys()))

def verify_zip_entries(path, label):
    """逐条目手动验证 ZIP 结构（不检测 overlap，MT 复用合法）。"""
    import zipcheck
    return zipcheck.verify_zip_file(path, label)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--orig", required=True)
    ap.add_argument("--multiplex", action="store_true",
                    help="MT 式数据复用优化 + 不重排 V2 重签（dedup 模式）")
    a = ap.parse_args()

    # 保证输出路径父目录存在（防止相对路径在子目录执行时找不到）
    out_dir = os.path.dirname(os.path.abspath(a.output))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    zipalign = find_zipalign()
    if not zipalign:
        sys.exit("zipalign not found")
    apksig_jar = find_apksig_jar()
    if not apksig_jar:
        sys.exit("apksig jar not found")

    inject_v1(a.input, a.orig)

    aligned = a.input + ".aligned"
    run([zipalign, "-f", "4", a.input, aligned])

    key, pk8, cert_der, pub_der = ensure_keys()

    src_dir = os.path.dirname(os.path.abspath(__file__))
    classes_dir = os.path.join(KEY_DIR, "classes")
    os.makedirs(classes_dir, exist_ok=True)
    java_src = os.path.join(src_dir, "KeepV1Signer.java")
    run(["javac", "-cp", apksig_jar, "-d", classes_dir, java_src])

    run(["java", "-cp", apksig_jar + os.pathsep + classes_dir,
         "KeepV1Signer", aligned, a.output, pk8, cert_der])
    print("[ok] apksig V2 signed (V1 preserved)")

    if a.multiplex:
        # 1) MT 式数据复用
        opt = a.output + ".opt"
        r = subprocess.run(
            ["python3", os.path.join(src_dir, "data_multiplexing.py"),
             "--input", a.output, "--output", opt],
            capture_output=True, text=True)
        if r.stdout: print(r.stdout, end="", flush=True)
        if r.stderr: print(r.stderr, end="", flush=True)
        if r.returncode != 0:
            shutil.copy2(opt, opt + ".debug") if os.path.exists(opt) else None
            raise SystemExit("data_multiplexing failed")

        # 2) 复用产物自检（不重排 V2 重签前）
        verify_zip_entries(opt, "opt (multiplexed)")

        # 3) 不重排 V2 重签
        v2_out = a.output + ".v2tmp"
        r = subprocess.run(
            ["python3", os.path.join(src_dir, "v2_sign.py"),
             "--input", opt, "--output", v2_out,
             "--key", key, "--cert", cert_der, "--pub", pub_der],
            capture_output=True, text=True)
        if r.stdout: print(r.stdout, end="", flush=True)
        if r.stderr: print(r.stderr, end="", flush=True)
        if r.returncode != 0:
            shutil.copy2(opt, opt + ".debug") if os.path.exists(opt) else None
            shutil.copy2(v2_out, v2_out + ".debug") if os.path.exists(v2_out) else None
            raise SystemExit("v2_sign failed")

        # 4) 产物逐 entry 自检
        _, bad = verify_zip_entries(v2_out, "v2tmp (re-signed)")
        if bad:
            shutil.copy2(opt, opt + ".debug")
            shutil.copy2(v2_out, v2_out + ".debug")
            print("[debug] 已保留 %s 与 %s 供排查" % (opt + ".debug", v2_out + ".debug"), flush=True)
            raise SystemExit("v2 resign output invalid")

        os.replace(v2_out, a.output)

        # 真实验签：apksigner verify --min-sdk-version 24
        apksigner_bin = os.path.join(os.path.dirname(zipalign), "apksigner")
        if os.path.isfile(apksigner_bin):
            rv = subprocess.run(
                [apksigner_bin, "verify", "--verbose", "--min-sdk-version", "24",
                 a.output],
                capture_output=True, text=True)
            if rv.returncode != 0:
                print(rv.stdout[-3000:], flush=True)
                print(rv.stderr[-3000:], flush=True)
                raise SystemExit("apksigner V2 verify failed (final output)")
            print("[ok] apksigner V2 verify passed", flush=True)
        else:
            print("[warn] apksigner not found, skip verify (action 有 build-tools 不受影响)", flush=True)

        print("[ok] data multiplexing + V2 re-sign done")

    if os.path.isfile(aligned):
        try: os.remove(aligned)
        except Exception: pass

    print("[ok] final signed (V2 valid, V1 preserved)")

if __name__ == "__main__":
    main()
