#!/usr/bin/env python3
"""APK Signature Scheme v2 signer — 严格对齐 apksig 解析结构。

value        = LP( LP(signer) )
signer       = LP(sd_body) + LP(signatures_records) + LP(pub)
signed_data  = LP( digests + certs + attrs + minSdk + maxSdk )
digests      = LP( LP( alg + LP(digest) ) )
signatures   = LP( LP( alg + LP(sig) ) )
摘要块        = SHA256(0xa5 + uint32块长 + 块内容)，顶级 = SHA256(0x5a + uint32块数 + 块摘要)
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


def u32(n):
    return struct.pack("<I", n)


def u64(n):
    return struct.pack("<Q", n)


def length_prefixed(blob):
    return u32(len(blob)) + blob


def find_eocd(data):
    for i in range(len(data) - 22, max(0, len(data) - 65557) - 1, -1):
        if data[i:i + 4] == b"PK\x05\x06":
            return i
    return -1


def content_digest(parts):
    """apksig ApkSigningBlockUtils.computeOneMbChunkContentDigests:
    - 三个分区（内容区/中央目录/EOCD）各自独立切块，块大小 1MB = 1024*1024
    - 空段不产生块
    - 块摘要 = SHA256(0xa5 + uint32块长(LE) + 块内容)
    - 最终   = SHA256(0x5a + uint32块总数(LE) + 全部块摘要按序串联)
    """
    chunks = []
    for part in parts:
        pos = 0
        while pos < len(part):
            block = part[pos:pos + 1024 * 1024]
            chunks.append(
                hashlib.sha256(b"\xA5" + struct.pack("<I", len(block)) + block).digest())
            pos += len(block)
    h = hashlib.sha256(b"\x5A" + struct.pack("<I", len(chunks)))
    for c in chunks:
        h.update(c)
    return h.digest()


def u32(n):
    return struct.pack("<I", n)


def u64(n):
    return struct.pack("<Q", n)


def length_prefixed(blob):
    return u32(len(blob)) + blob


def find_eocd(data):
    for i in range(len(data) - 22, max(0, len(data) - 65557) - 1, -1):
        if data[i:i + 4] == b"PK\x05\x06":
            return i
    return -1


def build_digests(digest):
    # digests 字段 = LP( LP( alg + LP(digest) ) )
    return length_prefixed(length_prefixed(u32(ALG_SHA256_RSA) + length_prefixed(digest)))


def build_certificates(cert_der):
    # certificates 字段 = LP( LP(cert) )
    return length_prefixed(length_prefixed(cert_der))


def build_signatures(sd_body, private_key_pem):
    # signatures 字段 = LP( LP( alg + LP(sig) ) )，签名覆盖 sd_body（不含 LP）
    signature = sign_bytes(private_key_pem, sd_body)
    if not signature:
        raise RuntimeError("RSA signature failed")
    return length_prefixed(length_prefixed(u32(ALG_SHA256_RSA) + length_prefixed(signature)))


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


def build_signed_data(digest, cert_der):
    digests = build_digests(digest)
    certs = build_certificates(cert_der)
    attrs = length_prefixed(b"")
    # 返回 sd_body（签名覆盖的字节，不含外层 LP）
    return digests + certs + attrs + u32(MIN_SDK) + u32(MAX_SDK)


def build_block(signer_bytes):
    # value = LP( LP(signer) )；pair size = 4 + len(value)
    pair_value = length_prefixed(length_prefixed(signer_bytes))
    pair = u64(len(pair_value) + 4) + u32(V2_BLOCK_ID) + pair_value
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

    with open(a.cert, "rb") as f:
        cert_der = f.read()
    with open(a.pub, "rb") as f:
        pub_der = f.read()

    # block 长度只依赖固定字段（digest 恒 32B、证书、公钥、签名），
    # 先用占位 digest 构建一次，确定精确的 block 长度（含 padding）。
    dummy_sd = build_signed_data(b"\x00" * 32, cert_der)
    dummy_sig = build_signatures(dummy_sd, a.key)
    dummy_signer = (length_prefixed(dummy_sd)
                    + dummy_sig
                    + length_prefixed(pub_der))
    block = build_block(dummy_signer)
    block_len = len(block)

    # 按 apksig 源码：digest 的三个分区 = 内容区 / 中央目录 / EOCD
    # EOCD 参与摘要前，需把 cd_offset 字段改成"签名块起始偏移"（=原cd_offset，
    # 因为签名块就插在中央目录前，原cd_offset 正好是内容区长度=签名块起始）。
    # EOCD 参与摘要时，cd_offset 字段应指向"签名块起始偏移"（= 原 cd_offset）
    eocd_part = bytearray(data[eocd:])
    struct.pack_into("<I", eocd_part, 16, cd_offset)  # EOCD 内偏移 16 就是 cd_offset 字段
    digest = content_digest([data[:cd_offset], data[cd_offset:eocd], bytes(eocd_part)])

    sd_body = build_signed_data(digest, cert_der)
    signatures = build_signatures(sd_body, a.key)

    signer_bytes = (length_prefixed(sd_body)
                    + signatures
                    + length_prefixed(pub_der))
    block = build_block(signer_bytes)

    # 4 字节对齐：追加 padding pair（size 字段 = 4 + pad_len）
    while len(block) % 4 != 0:
        old_size = struct.unpack_from("<Q", block, 0)[0]
        pairs = block[8:8 + old_size - 24]
        pad_len = 4 - (len(block) % 4)
        pad_pair = (struct.pack("<Q", 4 + pad_len)
                    + struct.pack("<I", 0x42726577)
                    + b"\x00" * pad_len)
        new_pairs = pairs + pad_pair
        new_size = len(new_pairs) + 24
        block = (struct.pack("<Q", new_size) + new_pairs
                 + struct.pack("<Q", new_size) + MAGIC)

    # 内容区（local headers + data）不移动，中央目录各 entry offset 保持；
    # 仅 EOCD 的 cd_offset += len(block)（digest 里 taile_fixed 已同样修正）。
    tail = bytearray(data[cd_offset:])
    eocd_rel = eocd - cd_offset
    old_cd_off = struct.unpack_from("<I", tail, eocd_rel + 16)[0]
    struct.pack_into("<I", tail, eocd_rel + 16, old_cd_off + len(block))

    out = data[:cd_offset] + block + bytes(tail)
    with open(a.output, "wb") as f:
        f.write(out)

    _t, _b = zipcheck.verify_zip_file(a.output, "v2_sign output", report=True)
    if _b:
        print("FATAL: v2sign output invalid")
        sys.exit(1)
    print(f"[v2sign] OK {a.output} (block={len(block)}, entries={_t})")


if __name__ == "__main__":
    main()
