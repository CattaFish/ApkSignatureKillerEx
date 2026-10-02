#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MT 式数据复用优化。

把产物 APK 中与 assets/SignedByRS/input.apk（原包）完全相同
（文件名/压缩方式/压缩字节都一致）的文件，在中央目录里把数据偏移
直接指向原包内部对应数据段，并删除产物中重复的数据段。

流程：先有完整签名产物（V2 有效、V1 壳），再对本文件输出做一次
不重排 V2 重签（v2_sign.py），否则优化会失效。
"""

import argparse
import struct
import sys
import zlib

INPUT_APK = "assets/SignedByRS/input.apk"


def find_eocd(data):
    for i in range(len(data) - 22, max(0, len(data) - 65557) - 1, -1):
        if data[i:i + 4] == b"PK\x05\x06":
            return i
    return -1


def parse_entries(data, cd_offset, cd_size):
    entries = []
    off = cd_offset
    end = cd_offset + cd_size
    while off + 46 <= end:
        if data[off:off + 4] != b"PK\x01\x02":
            break
        method = struct.unpack_from("<H", data, off + 10)[0]
        crc = struct.unpack_from("<I", data, off + 16)[0]
        comp_size = struct.unpack_from("<I", data, off + 20)[0]
        uncomp_size = struct.unpack_from("<I", data, off + 24)[0]
        name_len = struct.unpack_from("<H", data, off + 28)[0]
        extra_len = struct.unpack_from("<H", data, off + 30)[0]
        comment_len = struct.unpack_from("<H", data, off + 32)[0]
        local_offset = struct.unpack_from("<I", data, off + 42)[0]
        name = data[off + 46:off + 46 + name_len]
        entries.append({
            "name": name,
            "name_str": name.decode("utf-8", "replace"),
            "method": method,
            "crc": crc,
            "comp_size": comp_size,
            "uncomp_size": uncomp_size,
            "local_offset": local_offset,
            "central_offset": off,
            "central_len": 46 + name_len + extra_len + comment_len,
        })
        off += 46 + name_len + extra_len + comment_len
    return entries


def read_entry_data(data, e):
    lho = e["local_offset"]
    if data[lho:lho + 4] != b"PK\x03\x04":
        return None
    name_len = struct.unpack_from("<H", data, lho + 26)[0]
    extra_len = struct.unpack_from("<H", data, lho + 28)[0]
    start = lho + 30 + name_len + extra_len
    return data[start:start + e["comp_size"]]


def build_local(name_bytes, method, crc, comp_size, uncomp_size,
                start_offset, align_data, flags=0):
    name_len = len(name_bytes)
    extra_len = 0
    if align_data and method == 0:
        need = (start_offset + 30 + name_len) % 4
        if need:
            extra_len = 4 - need
    lh = bytearray(30 + name_len + extra_len)
    lh[0:4] = b"PK\x03\x04"
    struct.pack_into("<H", lh, 4, 20)
    struct.pack_into("<H", lh, 6, flags)
    struct.pack_into("<H", lh, 8, method)
    struct.pack_into("<I", lh, 14, crc)
    struct.pack_into("<I", lh, 18, comp_size)
    struct.pack_into("<I", lh, 22, uncomp_size)
    struct.pack_into("<H", lh, 26, name_len)
    struct.pack_into("<H", lh, 28, extra_len)
    lh[30:30 + name_len] = name_bytes
    return bytes(lh)


def central_from_old(data, e, new_offset, clear_bit3=True):
    ce = bytearray(data[e["central_offset"]:e["central_offset"] + e["central_len"]])
    struct.pack_into("<I", ce, 42, new_offset)
    if clear_bit3:
        flags = struct.unpack_from("<H", ce, 8)[0]
        flags &= ~0x0008
        struct.pack_into("<H", ce, 8, flags)
    return bytes(ce)


def build_central(name_bytes, method, crc, comp_size, uncomp_size, offset):
    name_len = len(name_bytes)
    ce = bytearray(46 + name_len)
    ce[0:4] = b"PK\x01\x02"
    struct.pack_into("<H", ce, 4, 20)
    struct.pack_into("<H", ce, 6, 20)
    struct.pack_into("<H", ce, 8, 0)
    struct.pack_into("<H", ce, 10, method)
    struct.pack_into("<I", ce, 16, crc)
    struct.pack_into("<I", ce, 20, comp_size)
    struct.pack_into("<I", ce, 24, uncomp_size)
    struct.pack_into("<H", ce, 28, name_len)
    struct.pack_into("<I", ce, 42, offset)
    ce[46:46 + name_len] = name_bytes
    return bytes(ce)


def build_eocd(cd_offset, cd_size, total):
    eocd = bytearray(22)
    eocd[0:4] = b"PK\x05\x06"
    struct.pack_into("<H", eocd, 8, total)
    struct.pack_into("<H", eocd, 10, total)
    struct.pack_into("<I", eocd, 12, cd_size)
    struct.pack_into("<I", eocd, 16, cd_offset)
    return bytes(eocd)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()

    with open(a.input, "rb") as f:
        data = f.read()

    eocd = find_eocd(data)
    if eocd < 0:
        sys.exit("bad apk: EOCD not found")
    cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    cd_size = struct.unpack_from("<I", data, eocd + 12)[0]
    entries = parse_entries(data, cd_offset, cd_size)

    inner_e = None
    for e in entries:
        if e["name_str"] == INPUT_APK:
            inner_e = e
            break
    if inner_e is None:
        sys.exit("missing " + INPUT_APK)

    # 解出原包（要求存储/可解压，解压后以 STORE 写入产物）
    inner_comp = read_entry_data(data, inner_e)
    if inner_comp is None:
        sys.exit("bad inner apk entry")
    if inner_e["method"] == 0:
        inner_data = inner_comp
    elif inner_e["method"] == 8:
        inner_data = zlib.decompress(inner_comp, -15)
    else:
        sys.exit("unsupported inner method %d" % inner_e["method"])
    print("[info] inner apk size=%d (was method %d)" % (len(inner_data), inner_e["method"]))

    ieocd = find_eocd(inner_data)
    if ieocd < 0:
        sys.exit("bad inner apk: EOCD not found")
    icd_offset = struct.unpack_from("<I", inner_data, ieocd + 16)[0]
    icd_size = struct.unpack_from("<I", inner_data, ieocd + 12)[0]
    inner_entries = parse_entries(inner_data, icd_offset, icd_size)
    inner_map = {}
    for ie in inner_entries:
        if ie["name_str"] not in inner_map:
            inner_map[ie["name_str"]] = ie
    print("[info] outer=%d entries, inner=%d entries" % (len(entries), len(inner_entries)))

    # 标记可复用：名字/压缩方式/CRC/压缩大小一致且压缩字节完全一致
    reused = set()
    for e in entries:
        if e["name_str"] == INPUT_APK:
            continue
        ie = inner_map.get(e["name_str"])
        if ie is None:
            continue
        if e["method"] != ie["method"] or e["comp_size"] != ie["comp_size"] or e["crc"] != ie["crc"]:
            continue
        if not e["name_str"].endswith("/") and read_entry_data(data, e) == read_entry_data(inner_data, ie):
            reused.add(e["name_str"])
    print("[ok] reused entries: %d / %d" % (len(reused), len(entries) - 1))

    out = bytearray()
    centrals = []

    # 1) 先写原包数据段（STORE，data 4 字节对齐，供复用指向）
    inner_lh = build_local(inner_e["name"], 0, inner_e["crc"],
                           len(inner_data), len(inner_data), len(out), True)
    inner_data_offset = len(out)
    out += inner_lh + inner_data
    centrals.append(build_central(inner_e["name"], 0, inner_e["crc"],
                                  len(inner_data), len(inner_data), inner_data_offset))

    # 2) 其余 entry
    for e in entries:
        if e["name_str"] == INPUT_APK:
            continue
        if e["name_str"] in reused:
            ie = inner_map[e["name_str"]]
            target = inner_data_offset + ie["local_offset"]
            # 复用条目的 central 记录必须来自 inner（与 inner local header 完全自洽），
            # 保留原始 flags（含 bit3 原样），只改 offset。
            centrals.append(central_from_old(inner_data, ie, target, clear_bit3=False))
            continue
        comp = read_entry_data(data, e)
        if comp is None:
            sys.exit("bad entry data: " + e["name_str"])
        lflags = struct.unpack_from("<H", data, e["local_offset"] + 6)[0] & ~0x0008
        lh = build_local(e["name"], e["method"], e["crc"], e["comp_size"],
                         e["uncomp_size"], len(out), True, lflags)
        local_offset = len(out)
        out += lh + comp
        centrals.append(central_from_old(data, e, local_offset))

    new_cd_offset = len(out)
    cd_bytes = b"".join(centrals)
    out += cd_bytes
    out += build_eocd(new_cd_offset, len(cd_bytes), len(centrals))

    with open(a.output, "wb") as f:
        f.write(out)
    print("[ok] multiplex: %d -> %d bytes (-%d%%)" % (
        len(data), len(out), (1 - len(out) / max(1, len(data))) * 100))


if __name__ == "__main__":
    main()
