#!/usr/bin/env python3
"""Final signing stage: inject original V1 trio -> zipalign -> apksig V2-only (preserve V1)."""
import argparse, base64, hashlib, os, re, shutil, struct, subprocess, sys, tempfile, zipfile

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
                if os.path.isfile(p): return p
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
        if os.path.isfile(c): return c
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
    return key, pk8, cert_der

def inject_v1(input_apk, orig_apk):
    """Copy original META-INF/MANIFEST.MF, CERT.SF, CERT.RSA into unsigned APK."""
    with zipfile.ZipFile(orig_apk) as z:
        trio = {}
        for n in z.namelist():
            if re.match(r"META-INF/(MANIFEST\.MF|CERT\.SF|CERT\.RSA)$", n, re.I):
                trio[n] = z.read(n)
        if not trio:
            print("[warn] original has no V1 trio")
            return
    tmp = input_apk + ".tmp"
    with zipfile.ZipFile(input_apk, "r") as zin, zipfile.ZipFile(tmp, "w") as zout:
        for it in zin.infolist():
            if re.match(r"META-INF/(MANIFEST\.MF|CERT\.SF|CERT\.RSA)$", it.filename, re.I):
                continue
            zout.writestr(it, zin.read(it.filename))
        for name, data in trio.items():
            zi = zipfile.ZipInfo(name)
            zi.external_attr = 0o644 << 16
            zout.writestr(zi, data)
    os.replace(tmp, input_apk)
    print("[ok] V1 trio injected:", list(trio.keys()))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--orig", required=True)
    a = ap.parse_args()

    zipalign = find_zipalign()
    if not zipalign:
        sys.exit("zipalign not found")
    apksig_jar = find_apksig_jar()
    if not apksig_jar:
        sys.exit("apksig jar not found")

    inject_v1(a.input, a.orig)

    aligned = a.input + ".aligned"
    run([zipalign, "-f", "4", a.input, aligned])

    key, pk8, cert_der = ensure_keys()

    # compile KeepV1Signer
    src_dir = os.path.dirname(os.path.abspath(__file__))
    classes_dir = os.path.join(KEY_DIR, "classes")
    os.makedirs(classes_dir, exist_ok=True)
    java_src = os.path.join(src_dir, "KeepV1Signer.java")
    run(["javac", "-cp", apksig_jar, "-d", classes_dir, java_src])

    run(["java", "-cp", apksig_jar + os.pathsep + classes_dir,
         "KeepV1Signer", aligned, a.output, pk8, cert_der])
    print("[ok] final signed (V2 valid, V1 preserved)")

    prepend_original_v2_pair(a.output, a.orig)



def find_eocd(data):
    for i in range(len(data) - 22, max(0, len(data) - 65557) - 1, -1):
        if data[i:i + 4] == b"PK\x05\x06":
            return i
    return -1


def extract_first_v2_pair(apk_path):
    """返回原 APK 首个 v2/v3 signer 完整 block pair（size+id+value）。"""
    with open(apk_path, "rb") as f:
        data = f.read()
    if len(data) < 32:
        return None
    eocd = find_eocd(data)
    if eocd < 0:
        return None
    cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    if cd_offset < 32 or cd_offset > len(data):
        return None
    footer_pos = cd_offset - 24
    if footer_pos < 0 or footer_pos + 24 > len(data):
        return None
    if data[footer_pos + 8:footer_pos + 24] != b"APK Sig Block 42":
        return None
    block_size = struct.unpack_from("<Q", data, footer_pos)[0]
    if block_size < 24 or block_size > 100 * 1024 * 1024:
        return None
    pairs_size = block_size - 24
    block_start = cd_offset - block_size
    if pairs_size <= 0 or block_start < 0 or block_start + pairs_size > len(data):
        return None
    off = block_start
    end = block_start + pairs_size
    while off + 12 <= end:
        pair_len = struct.unpack_from("<Q", data, off)[0]
        pair_id = struct.unpack_from("<I", data, off + 8)[0]
        if pair_len < 4 or off + pair_len - 4 > end:
            break
        if pair_id in (0x7109871a, 0xf05368c0):
            return data[off:off + 12 + (pair_len - 4)]
        off += int(pair_len - 4)
    return None


def prepend_original_v2_pair(signed_apk, orig_apk):
    """把原 APK 的原始 v2/v3 signer block 前置到产物 signing block 最前面。"""
    orig_pair = extract_first_v2_pair(orig_apk)
    if orig_pair is None:
        print("[warn] orig has no v2/v3 block, skip prepend")
        return
    with open(signed_apk, "rb") as f:
        data = bytearray(f.read())
    if len(data) < 32:
        return
    eocd = find_eocd(bytes(data))
    if eocd < 0:
        return
    cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    if cd_offset < 32 or cd_offset > len(data):
        return
    footer_pos = cd_offset - 24
    if footer_pos < 0 or footer_pos + 24 > len(data):
        return
    if data[footer_pos + 8:footer_pos + 24] != b"APK Sig Block 42":
        return
    old_block_size = struct.unpack_from("<Q", data, footer_pos)[0]
    if old_block_size < 24 or old_block_size > 100 * 1024 * 1024:
        return
    pairs_size = old_block_size - 24
    block_start = cd_offset - old_block_size
    if pairs_size <= 0 or block_start < 0 or block_start + pairs_size > len(data):
        return

    old_pairs = bytes(data[block_start:block_start + pairs_size])
    old_block_len = len(old_pairs) + 8 + 16
    new_size = len(orig_pair) + len(old_pairs) + 8 + 16
    new_block = (struct.pack("<Q", new_size) + orig_pair + old_pairs
                 + struct.pack("<Q", new_size) + b"APK Sig Block 42")
    delta = len(new_block) - old_block_len
    struct.pack_into("<I", data, eocd + 16, cd_offset + delta)
    out = bytes(data[:block_start]) + new_block + bytes(data[block_start + old_block_len:])
    with open(signed_apk, "wb") as f:
        f.write(out)
    print("[ok] prepended original v2 signer block to signing block")


if __name__ == "__main__":
    main()

