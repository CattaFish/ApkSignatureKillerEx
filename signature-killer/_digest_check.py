#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import hashlib, os, struct, subprocess, sys, tempfile

CHUNK_SIZE = 1_000_000

def u32(n): return struct.pack("<I", n)
def u64(n): return struct.pack("<Q", n)

def find_eocd(d):
    for i in range(len(d)-22, max(0,len(d)-65557)-1, -1):
        if d[i:i+4]==b"PK\x05\x06": return i
    return -1

def content_digest(d):
    chunks=[]
    pos=0
    while pos<len(d):
        chunk=d[pos:pos+CHUNK_SIZE]
        chunks.append(hashlib.sha256(b"\xA5"+u32(len(chunk))+chunk).digest())
        pos+=len(chunk)
    h=hashlib.sha256(b"\x5A"+u32(len(chunks)))
    for c in chunks: h.update(c)
    return h.digest()

def parse_v2_digest(ob):
    eocd=find_eocd(ob)
    cd_off=struct.unpack_from("<I", ob, eocd+16)[0]
    footer=cd_off-24
    size=struct.unpack_from("<Q", ob, footer)[0]
    start=cd_off-size
    pos=start
    end=footer-8
    while pos+12<=end:
        psize=struct.unpack_from("<Q", ob, pos)[0]
        pid=struct.unpack_from("<I", ob, pos+8)[0]
        if pid==0x7109871a:
            val=ob[pos+12:pos+12+psize-4]
            # value = LP(signer_seq)
            seq_len=struct.unpack_from("<I", val,0)[0]
            seq=val[4:4+seq_len]
            signer_len=struct.unpack_from("<I", seq,0)[0]
            signer=seq[4:4+signer_len]
            sd_len=struct.unpack_from("<I", signer,0)[0]
            sd=signer[4:4+sd_len]
            dseq_len=struct.unpack_from("<I", sd,0)[0]
            dseq=sd[4:4+dseq_len]
            rec_len=struct.unpack_from("<I", dseq,0)[0]
            rec=dseq[4:4+rec_len]
            alg=struct.unpack_from("<I", rec,0)[0]
            dl=struct.unpack_from("<I", rec,4)[0]
            return alg, rec[8:8+dl]
        pos+=12+psize-4 if psize>=4 else 0
    return None,None

src = os.path.expanduser("~/test.apk")
tmp = tempfile.mkdtemp(prefix="dg_")
out = os.path.join(tmp, "official.apk")
subprocess.run(["apksigner","sign","--ks",os.path.expanduser("~/test.jks"),
                "--ks-key-alias","key0","--ks-pass","pass:123456","--key-pass","pass:123456",
                "--v1-signing-enabled","false","--v2-signing-enabled","true",
                "--v3-signing-enabled","false","--min-sdk-version","24",
                "--out",out,src], check=True, capture_output=True)
base=open(src,"rb").read()
ob=open(out,"rb").read()
alg, stored=parse_v2_digest(ob)
print("official alg:", hex(alg) if alg else None)
print("stored digest:", stored.hex()[:64])

# 候选
cd_off=struct.unpack_from("<I", base, find_eocd(base)+16)[0]
c1=content_digest(base)                      # 整个原始 APK
c2=content_digest(base[:cd_off])             # 仅内容区(不含CD/EOCD)
# 从官方包去掉签名块 = 内容+CD+EOCD(带签名后cd_offset)
eocd=find_eocd(ob)
ocd=struct.unpack_from("<I", ob, eocd+16)[0]
footer=ocd-24
bsize=struct.unpack_from("<Q", ob, footer)[0]
bstart=ocd-bsize
removed=ob[:bstart]+ob[ocd:]
c3=content_digest(removed)                   # EOCD cd_offset 未恢复
# 恢复 EOCD cd_offset 为签名块起始(即原cd_off)
rem2=bytearray(removed)
re_eocd=find_eocd(rem2)
struct.pack_into("<I", rem2, re_eocd+16, bstart)
c4=content_digest(bytes(rem2))               # 恢复为原cd_offset
# 简单 "content + CD + EOCD(原值)" = base，即c1

names=["whole_orig","content_only","removed_shifted","removed_restored"]
vals=[c1,c2,c3,c4]
for n,v in zip(names,vals):
    print(f"{n}: {v.hex()[:64]}  {'<<< MATCH' if v==stored else ''}")

print("removed size:", len(removed), "base size:", len(base))
