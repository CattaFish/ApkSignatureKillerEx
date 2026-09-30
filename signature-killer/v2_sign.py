#!/usr/bin/env python3
"""Custom APK V2 signer. Keeps V1 (JAR) signature files untouched.
Produces valid V2 while V1 files remain stale -> v1 check fails, v2 passes."""
import argparse, hashlib, os, struct, subprocess, sys, tempfile

CHUNK_SIZE = 1 << 20
V2_BLOCK_ID = 0x7109871A
MAGIC = b"APK Sig Block 42"
SIG_V2_ALG_SHA256 = 0x0103
DIGEST_INFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")

def find_eocd(data):
    for i in range(len(data) - 22, max(0, len(data) - 65557) - 1, -1):
        if data[i:i+4] == b"PK\x05\x06":
            return i
    return -1

def compute_digest(data):
    chunks = []
    pos = 0
    while pos < len(data):
        n = min(CHUNK_SIZE, len(data) - pos)
        chunks.append(hashlib.sha256(b"\xa5" + data[pos:pos+n]).digest())
        pos += n
    h = hashlib.sha256(b"\x5a")
    for c in chunks:
        h.update(c)
    return h.digest()

def lp(segments):
    out = b""
    for s in segments:
        out += len(s).to_bytes(4, "little") + s
    return out

def build_signed_data(digest, cert_der, min_sdk=24, max_sdk=0x7fffffff):
    digest_value = (SIG_V2_ALG_SHA256.to_bytes(4,"little")
                    + len(digest).to_bytes(4,"little") + digest)
    digests_bytes = len(digest_value).to_bytes(4,"little") + digest_value
    certs_bytes = len(cert_der).to_bytes(4,"little") + cert_der
    attrs_bytes = (0).to_bytes(4,"little")
    return (lp([digests_bytes, certs_bytes, attrs_bytes])
            + min_sdk.to_bytes(4,"little")
            + max_sdk.to_bytes(4,"little"))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--pub", required=True)
    a = ap.parse_args()

    data = open(a.input, "rb").read()
    eocd = find_eocd(data)
    assert eocd >= 0, "EOCD not found"
    cd_off = int.from_bytes(data[eocd+16:eocd+20], "little")
    cd_size = int.from_bytes(data[eocd+12:eocd+16], "little")
    assert cd_off + cd_size <= eocd

    digest = compute_digest(data[:cd_off])
    cert_der = open(a.cert, "rb").read()
    pub_der = open(a.pub, "rb").read()

    signed_data = build_signed_data(digest, cert_der)

    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(DIGEST_INFO_SHA256 + digest)
        di_name = tf.name
    sig_path = di_name + ".sig"
    r = subprocess.run(["openssl", "pkeyutl", "-sign",
                        "-inkey", a.key,
                        "-pkeyopt", "rsa_padding_mode:pkcs1",
                        "-in", di_name, "-out", sig_path],
                       capture_output=True, text=True)
    os.unlink(di_name)
    if r.returncode != 0:
        print(r.stderr[-1500:]); sys.exit(1)
    sig = open(sig_path, "rb").read()
    os.unlink(sig_path)

    # signer: signed_data | signatures | public_key (length-prefixed)
    signed_lp = len(signed_data).to_bytes(4,"little") + signed_data
    sig_value = (SIG_V2_ALG_SHA256.to_bytes(4,"little")
                 + len(sig).to_bytes(4,"little") + sig)
    sigs_bytes = len(sig_value).to_bytes(4,"little") + sig_value
    pub_lp = len(pub_der).to_bytes(4,"little") + pub_der
    signer = lp([signed_lp, sigs_bytes, pub_lp])

    # v2 block: signer sequence (no count)
    v2_value = len(signer).to_bytes(4,"little") + signer
    v2_pair = (len(v2_value)+8).to_bytes(8,"little") + V2_BLOCK_ID.to_bytes(4,"little") + v2_value

    block_size = len(v2_pair) + 8
    sign_block = (block_size.to_bytes(8,"little") + v2_pair
                  + block_size.to_bytes(8,"little") + MAGIC)

    out = data[:cd_off] + sign_block + data[cd_off:]
    patch_at = eocd + len(sign_block)
    out = out[:patch_at] + (cd_off + len(sign_block)).to_bytes(4,"little") + out[patch_at+4:]
    open(a.output, "wb").write(out)
    print(f"[v2sign] OK {a.output}")

if __name__ == "__main__":
    main()
