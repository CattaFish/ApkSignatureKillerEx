#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import struct
import sys
import zlib

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
        flags = struct.unpack_from("<H", data, off + 8)[0]
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
            "flags": flags,
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
    if lho < 0 or lho + 4 > len(data):
        return None
    if data[lho:lho + 4] != b"PK\x03\x04":
        return None
    name_len = struct.unpack_from("<H", data, lho + 26)[0]
    extra_len = struct.unpack_from("<H", data, lho + 28)[0]
    start = lho + 30 + name_len + extra_len
    end = start + e["comp_size"]
    if end > len(data):
        return None
    return data[start:end]

def is_origin_apk_payload(data, e):
    if e["uncomp_size"] < 500 * 1024 or e["method"] != 0:
        return False
    comp = read_entry_data(data, e)
    if not comp or len(comp) < 30:
        return False
    return comp[:4] == b"PK\x03\x04" and b"AndroidManifest.xml" in comp

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
        if e["name_str"].startswith("assets/") and is_origin_apk_payload(data, e):
            inner_e = e
            break

    if inner_e is None:
        for e in entries:
            if e["name_str"] == "assets/Zcraft/input.apk":
                inner_e = e
                break

    if inner_e is None:
        sys.exit("bad apk: 未能在 assets/ 下找到内嵌的原包条目")

    input_apk_name = inner_e["name_str"]
    print(f"[info] 自动匹配内嵌原包条目: {input_apk_name}")

    inner_comp = read_entry_data(data, inner_e)
    if inner_comp is None:
        sys.exit("bad inner apk entry")
    if inner_e["method"] == 0:
        inner_data = inner_comp
    elif inner_e["method"] == 8:
        inner_data = zlib.decompress(inner_comp, -15)
    else:
        sys.exit("unsupported inner method %d" % inner_e["method"])

    ieocd = find_eocd(inner_data)
    if ieocd < 0:
        sys.exit("bad inner apk: EOCD not found")
    icd_offset = struct.unpack_from("<I", inner_data, ieocd + 16)[0]
    icd_size = struct.unpack_from("<I", inner_data, ieocd + 12)[0]
    inner_entries = parse_entries(inner_data, icd_offset, icd_size)
    inner_map = {ie["name_str"]: ie for ie in inner_entries}

    stats = {"same_name": 0, "method_diff": 0, "size_crc_diff": 0, "byte_diff": 0, "bit3": 0}
    reused = set()
    for e in entries:
        if e["name_str"] == input_apk_name or e["name_str"].endswith("/"):
            continue
        ie = inner_map.get(e["name_str"])
        if ie is None:
            continue
        stats["same_name"] += 1
        if e["method"] != ie["method"]:
            stats["method_diff"] += 1
            continue
        if (e["flags"] & 0x0008) or (ie["flags"] & 0x0008):
            stats["bit3"] += 1
            continue
        if e["crc"] != ie["crc"] or e["comp_size"] != ie["comp_size"] or e["uncomp_size"] != ie["uncomp_size"]:
            stats["size_crc_diff"] += 1
            continue
        if read_entry_data(data, e) == read_entry_data(inner_data, ie):
            reused.add(e["name_str"])
        else:
            stats["byte_diff"] += 1

    print("[info] match stats: %s" % (stats,))
    print("[ok] reused entries: %d / %d" % (len(reused), len(entries) - 1))

    out = bytearray()
    centrals = []

    inner_lh = build_local(inner_e["name"], 0, inner_e["crc"],
                           len(inner_data), len(inner_data), len(out), True)
    inner_lh_offset = len(out)
    inner_data_start = len(out) + len(inner_lh)
    out += inner_lh + inner_data
    centrals.append(build_central(inner_e["name"], 0, inner_e["crc"],
                                  len(inner_data), len(inner_data), inner_lh_offset))

    for e in entries:
        if e["name_str"] == input_apk_name:
            continue
        if e["name_str"] in reused:
            ie = inner_map[e["name_str"]]
            target = inner_data_start + ie["local_offset"]
            centrals.append(central_from_old(data, e, target, clear_bit3=True))
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
