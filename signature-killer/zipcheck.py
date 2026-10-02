#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""逐条目手动 ZIP 结构校验。

MT 数据复用会让多个 central 条目指向同一块数据段（原包数据），
zipfile 会把这种合法结构误判为 "Overlapped entries (zip bomb)"。
因此这里不依赖 zipfile，手动解析：
  - EOCD / central directory
  - 每个 central 指向的 local header 魔数 PK\x03\x04
  - 名称 / CRC / 压缩方式 / 大小 与 central 一致
  - 数据范围不越界
不检查 overlap。
"""
import struct


def find_eocd(data):
    for i in range(len(data) - 22, max(0, len(data) - 65557) - 1, -1):
        if data[i:i + 4] == b"PK\x05\x06":
            return i
    return -1


def verify_zip_bytes(data, label, report=True):
    bad = []
    total = 0
    if len(data) < 22:
        bad.append(("<too-small>", -1, "len=%d" % len(data)))
        if report:
            print("[FAIL] %s: file too small" % label)
        return 0, bad

    eocd = find_eocd(data)
    if eocd < 0:
        bad.append(("<eocd>", -1, "EOCD not found"))
        if report:
            print("[FAIL] %s: EOCD not found" % label)
        return 0, bad

    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
    cd_size = struct.unpack_from("<I", data, eocd + 12)[0]
    if cd_off + cd_size > len(data):
        bad.append(("<cd>", cd_off, "central dir out of bounds"))
        if report:
            print("[FAIL] %s: central dir out of bounds" % label)
        return 0, bad

    off = cd_off
    end = cd_off + cd_size
    while off + 46 <= end:
        if data[off:off + 4] != b"PK\x01\x02":
            break
        method = struct.unpack_from("<H", data, off + 10)[0]
        crc = struct.unpack_from("<I", data, off + 16)[0]
        comp = struct.unpack_from("<I", data, off + 20)[0]
        uncomp = struct.unpack_from("<I", data, off + 24)[0]
        nl = struct.unpack_from("<H", data, off + 28)[0]
        el = struct.unpack_from("<H", data, off + 30)[0]
        cl = struct.unpack_from("<H", data, off + 32)[0]
        lho = struct.unpack_from("<I", data, off + 42)[0]
        name = data[off + 46:off + 46 + nl].decode("utf-8", "replace")
        total += 1

        # 本地头魔数
        if lho < 0 or lho + 4 > len(data) or data[lho:lho + 4] != b"PK\x03\x04":
            bad.append((name, lho, "local header magic mismatch"))
        else:
            l_nl = struct.unpack_from("<H", data, lho + 26)[0]
            l_el = struct.unpack_from("<H", data, lho + 28)[0]
            data_start = lho + 30 + l_nl + l_el
            if data_start + comp > len(data):
                bad.append((name, lho, "entry data out of bounds"))
            try:
                l_name = data[lho + 30:lho + 30 + l_nl].decode("utf-8", "replace")
                l_crc = struct.unpack_from("<I", data, lho + 14)[0]
                l_comp = struct.unpack_from("<I", data, lho + 18)[0]
                l_uncomp = struct.unpack_from("<I", data, lho + 22)[0]
                l_method = struct.unpack_from("<H", data, lho + 8)[0]
                if l_name != name:
                    bad.append((name, lho, "name mismatch local=%r" % l_name))
                if l_crc != crc or l_comp != comp or l_uncomp != uncomp or l_method != method:
                    bad.append((name, lho,
                                "field mismatch crc=%d/%d comp=%d/%d uncomp=%d/%d method=%d/%d"
                                % (l_crc, crc, l_comp, comp, l_uncomp, uncomp, l_method, method)))
            except Exception as e:
                bad.append((name, lho, "local parse err %r" % (e,)))
        off += 46 + nl + el + cl

    if total == 0:
        bad.append(("<empty>", cd_off, "no central entries"))

    if report:
        if bad:
            print("[FAIL] %s: %d bad entries of %d" % (label, len(bad), total))
            for name, lho, err in bad[:20]:
                print("   bad entry %s (offset=%d): %s" % (name, lho, err))
        else:
            print("[ok] %s: all %d entries OK" % (label, total))
    return total, bad


def verify_zip_file(path, label, report=True):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        if report:
            print("[FAIL] %s: open failed: %r" % (label, e))
        return 0, [("<open>", -1, repr(e))]
    return verify_zip_bytes(data, label, report)
