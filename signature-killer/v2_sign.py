#!/usr/bin/env python3
"""Custom APK V2 signer. Keeps all ZIP entries (incl. V1 shell files) intact.
Implements APK Signature Scheme v2:
  - SHA-256 with RSA (PKCS#1 v1.5)
  - 1,000,000 byte content chunks (0xA5 prefix, 0x5A total)
  - signatures over full signed_data bytes (not DigestInfo+digest)
  - signing block size = len(pairs) + 24
"""
import argparse
import hashlib
import os
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import zipcheck

CHUNK_SIZE = 1_000_000
V2_BLOCK_ID = 0x7109871A
MAGIC = b"APK Sig Block 42"
ALG_SHA256_RSA = 0x0103
MIN_SDK = 24
MAX_SDK = 0x7FFFFFFF


def find_eocd(data):
    for i in range(len(data) - 22, max(0, len(data) - 65557) - 1, -1):
        if data[i:i + 4] == b"PK\x05\x06":
            return i
    return -1


def content_digest(data):
    chunks = []
    pos = 0
    while pos < len(data):
        chunk = data[pos:pos + CHUNK_SIZE]
        chunks.append(hashlib.sha256(b"\xA5" + chunk).digest())
        pos += len(chunk)
    h = hashlib.sha256(b"\x5A")
    for c in chunks:
        h.update(c)
    return h.digest()


def u32(n):
    return struct.pack("<I", n)


def u64(n):
    return struct.pack("<Q", n)


def length_prefixed(blob):
    return u32(len(blob)) + blob


def build_digests(digest):
    # digest record = uint32 alg + length-prefixed digest，整个 record 再 length-prefixed
    elem = length_prefixed(u32(ALG_SHA256_RSA) + length_prefixed(digest))
    return length_prefixed(elem)


def build_certificates(cert_der):
    return length_prefixed(length_prefixed(cert_der))


def build_signed_data(digest, cert_der):
    digests = build_digests(digest)
    certs = build_certificates(cert_der)
    attrs = length_prefixed(b"")
    return digests + certs + attrs + u32(MIN_SDK) + u32(MAX_SDK)


def sign_bytes(private_key_pem, payload):
    fd1, in_path = tempfile.mkstemp()
    os.close(fd1)
    fd2, out_path = tempfile.mkstemp()
    os.close(fd2)
    try:
        with open(in_path, "wb") as f:
            f.write(payload)
        r = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", private_key_pem,
             "-out", out_path, in_path],
            capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stderr[-2000:])
            return None
        with open(out_path, "rb") as f:
            return f.read()
    finally:
        os.unlink(in_path)
        os.unlink(out_path)


def build_signatures(signed_data, private_key_pem):
    signature = sign_bytes(private_key_pem, signed_data)
    if not signature:
        raise RuntimeError("RSA signature failed")
    # signature record = uint32 alg + length-prefixed signature，整个 record 再 length-prefixed
    rec = length_prefixed(u32(ALG_SHA256_RSA) + length_prefixed(signature))
    return length_prefixed(rec)


def build_block(signer):
    # 0x7109871a 的 value = length-prefixed signer（无 count 字段）
    pair_value = length_prefixed(signer)
    # pair size 字段 = 自身 8 + id 4 + value
    pair = u64(len(pair_value) + 12) + u32(V2_BLOCK_ID) + pair_value
    size = len(pair) + 8 + 16
    return u64(size) + pair + u64(size) + MAGIC


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--pub", required=True)
    a = ap.parse_args()

    with open(a.input, "rb") as f:
        data = f.read()

    # 自检：手动逐条目验证输入 ZIP 结构（不检测 overlap，MT 复用合法）
    _t, _b = zipcheck.verify_zip_bytes(data, "v2_sign input", report=True)
    if _b:
        print("FATAL: input zip invalid at %s" % a.input)
        sys.exit(1)

    eocd = find_eocd(data)
    if eocd < 0:
        print("bad apk: EOCD not found")
        sys.exit(1)
    cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    cd_size = struct.unpack_from("<I", data, eocd + 12)[0]
    if cd_offset + cd_size > eocd:
        print("bad apk: central dir range")
        sys.exit(1)

    protected = data[:cd_offset]
    digest = content_digest(protected)

    with open(a.cert, "rb") as f:
        cert_der = f.read()
    with open(a.pub, "rb") as f:
        pub_der = f.read()

    signed_data = build_signed_data(digest, cert_der)
    signatures = build_signatures(signed_data, a.key)
    signer = length_prefixed(
        length_prefixed(signed_data)
        + length_prefixed(signatures)
        + length_prefixed(pub_der)
    )
    block = build_block(signer)

    # 4 字节对齐：在 pairs 尾部追加 padding pair（未知 ID，解析器会忽略）
    while len(block) % 4 != 0:
        old_size = struct.unpack_from("<Q", block, 0)[0]
        pairs = block[8:8 + old_size - 24]
        pad_len = 4 - (len(block) % 4)
        pad_pair = struct.pack("<Q", 8 + pad_len) + struct.pack("<I", 0x42726577) + b"\x00" * pad_len
        new_pairs = pairs + pad_pair
        new_size = len(new_pairs) + 24
        block = struct.pack("<Q", new_size) + new_pairs + struct.pack("<Q", new_size) + MAGIC

    # 注意：插入签名块不会移动"内容区"（local headers + data），
    # 因此中央目录里各 entry 的 local header offset 保持不变！
    # 只有 EOCD 的 cd_offset 需要 += len(block)（中央目录整体后移）。
    tail = bytearray(data[cd_offset:])
    eocd_rel = eocd - cd_offset
    old_cd_off = struct.unpack_from("<I", tail, eocd_rel + 16)[0]
    struct.pack_into("<I", tail, eocd_rel + 16, old_cd_off + len(block))

    # 拼接：保护区 + 新签名块 + 修正后的中央目录/EOCD
    out = protected + block + bytes(tail)

    with open(a.output, "wb") as f:
        f.write(out)

    # 自检：手动逐条目验证输出 ZIP 结构
    _t, _b = zipcheck.verify_zip_file(a.output, "v2_sign output", report=True)
    if _b:
        print("FATAL: v2sign output invalid")
        sys.exit(1)
    print(f"[v2sign] OK {a.output} (block={len(block)}, entries={_t})")


if __name__ == "__main__":
    main()
