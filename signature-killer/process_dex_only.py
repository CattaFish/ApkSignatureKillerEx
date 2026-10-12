#!/usr/bin/env python3
"""Dex-only pipeline: baksmali patch Activity <clinit> -> 基于原包字节增量重建
（未修改 entry 原段拷贝，压缩字节不变，供 data multiplexing 复用）-> finalize_sign。
"""
import argparse, datetime, os, re, shutil, subprocess, sys, zipfile, zlib, struct

WORK = "work_out"
DEX_WORK = os.path.join(WORK, "dexwork")
KILLER_LIB = "work_killer/lib"
ABIS = ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]
THIS_DIR = os.path.dirname(os.path.abspath(__file__))


def run(cmd):
    print("+", " ".join(cmd), flush=True)
    r = subprocess.run(cmd, capture_output=True, text=True)
    try:
        os.makedirs(WORK, exist_ok=True)
        with open(os.path.join(WORK, "pipeline.log"), "a", encoding="utf-8") as lf:
            lf.write("+ " + " ".join(cmd) + "\n" + r.stdout[-4000:] + "\n" + r.stderr[-4000:] + "\n")
    except Exception:
        pass
    if r.returncode != 0:
        print(r.stdout[-3000:])
        print(r.stderr[-3000:])
        print(f"FAIL: {cmd[0]}")
        sys.exit(1)
    return r


def get_activity(apk, apktool):
    man_dir = os.path.join(DEX_WORK, "manifest_text")
    shutil.rmtree(DEX_WORK, ignore_errors=True)
    os.makedirs(DEX_WORK, exist_ok=True)
    run(["java", "-jar", apktool, "d", "-f", "-s", "-o", man_dir, apk])
    _man_path = os.path.join(man_dir, "AndroidManifest.xml")
    man = open(_man_path, encoding="utf-8", errors="replace").read()
    if "<manifest" not in man:
        print("[warn] AndroidManifest.xml 非文本，尝试 binary fallback")
        import re as _re
        blob = open(_man_path, "rb").read()
        cand = _re.findall(rb'[a-zA-Z_][a-zA-Z0-9_.]{10,120}\.activity\.[a-zA-Z0-9_.]+', blob)
        if cand:
            cls = cand[-1].decode(errors="replace")
            print("[info] binary activity:", cls)
            return cls
        man = open(_man_path, encoding="utf-8", errors="replace").read()
    m = re.search(r'<activity\b[^>]*\bandroid:name="([^"]+)"', man)
    if not m:
        print("FAIL: no activity android:name")
        sys.exit(1)
    return m.group(1)


def patch_clinit(smali_path):
    s = open(smali_path, encoding="utf-8").read()
    marker = "invoke-static {}, Lr/s/sign/KillerApplication;->onLoaded()V"
    if marker in s:
        return False
    pat = re.compile(r'(\.method static constructor <clinit>\(\)V\n(?:\s*\.registers \d+\n)?)')
    mm = pat.search(s)
    if mm:
        s = s[:mm.end()] + "\n    " + marker + "\n" + s[mm.end():]
    else:
        clinit = ("\n# injected by SignatureKiller\n"
                  ".method static constructor <clinit>()V\n"
                  "    .registers 0\n\n"
                  "    " + marker + "\n\n"
                  "    return-void\n"
                  ".end method\n")
        idx = s.find("\n.method ")
        if idx < 0: idx = len(s)
        s = s[:idx] + clinit + s[idx:]
    open(smali_path, "w", encoding="utf-8").write(s)
    return True


def find_and_patch(apk_dir, dex_files, rel_path, baksmali, smali):
    for dex in dex_files:
        out_smali = os.path.join(DEX_WORK, "smali_" + os.path.basename(dex))
        run(["java", "-jar", baksmali, "d", os.path.join(apk_dir, dex), "-o", out_smali])
        target = os.path.join(out_smali, rel_path)
        if not os.path.isfile(target):
            print(f"[info] {dex} 无 {rel_path}，跳过")
            shutil.rmtree(out_smali, ignore_errors=True)
            continue
        print(f"[ok] 在 {dex} 找到 {rel_path}")
        patch_clinit(target)
        out_dex = os.path.join(DEX_WORK, "patched_" + dex)
        run(["java", "-jar", smali, "a", out_smali, "-o", out_dex])
        shutil.copy2(out_dex, os.path.join(apk_dir, dex))
        print(f"[ok] 已替换 {dex}")
        shutil.rmtree(out_smali, ignore_errors=True)
        return True
    return False


# ---------- ZIP 字节级工具（保留原压缩字节） ----------

def find_eocd(data):
    for i in range(len(data) - 22, max(0, len(data) - 65557) - 1, -1):
        if data[i:i + 4] == b"PK\x05\x06":
            return i
    return -1


def parse_central(data, cd_off, cd_size):
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


def local_len(data, lho):
    nl = struct.unpack_from("<H", data, lho + 26)[0]
    el = struct.unpack_from("<H", data, lho + 28)[0]
    return 30 + nl + el


def make_local(name_b, method, flags, crc, comp, uncomp, extra=b""):
    lh = bytearray(30 + len(name_b) + len(extra))
    lh[0:4] = b"PK\x03\x04"
    struct.pack_into("<H", lh, 4, 20)
    struct.pack_into("<H", lh, 6, flags)
    struct.pack_into("<H", lh, 8, method)
    struct.pack_into("<I", lh, 14, crc)
    struct.pack_into("<I", lh, 18, comp)
    struct.pack_into("<I", lh, 22, uncomp)
    struct.pack_into("<H", lh, 26, len(name_b))
    struct.pack_into("<H", lh, 28, len(extra))
    lh[30:30 + len(name_b)] = name_b
    if extra:
        lh[30 + len(name_b):30 + len(name_b) + len(extra)] = extra
    return bytes(lh)


def make_central(name_b, method, flags, crc, comp, uncomp, offset):
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


def make_eocd(cd_off, cd_size, total):
    e = bytearray(22)
    e[0:4] = b"PK\x05\x06"
    struct.pack_into("<H", e, 8, total)
    struct.pack_into("<H", e, 10, total)
    struct.pack_into("<I", e, 12, cd_size)
    struct.pack_into("<I", e, 16, cd_off)
    return bytes(e)


def build_unsigned(orig, out, replaced=None, additions=None):
    """基于原包字节增量重建：未修改 entry 原段拷贝（压缩字节不变），
    使 data_multiplexing 能把它们指向 assets/Zcraft/input.apk 内部。"""
    replaced = dict(replaced or {})
    additions = dict(additions or {})
    with open(orig, "rb") as f:
        data = f.read()
    eocd = find_eocd(data)
    if eocd < 0:
        raise SystemExit("bad orig zip: EOCD not found")
    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
    cd_size = struct.unpack_from("<I", data, eocd + 12)[0]
    entries = parse_central(data, cd_off, cd_size)
    print(f"[info] build_unsigned: orig={len(data)} bytes, orig_entries={len(entries)}, "
          f"replaced={len(replaced)}, additions={len(additions)}")

    out_buf = bytearray()
    centrals = []
    seen = set()

    for e in entries:
        ns = e["name_str"]
        if ns in seen:
            continue
        seen.add(ns)
        name_b = e["name"]

        if ns in replaced:
            payload = replaced.pop(ns)
            crc = zlib.crc32(payload) & 0xffffffff
            off = len(out_buf)
            out_buf += make_local(name_b, 0, 0, crc, len(payload), len(payload)) + payload
            centrals.append(make_central(name_b, 0, 0, crc, len(payload), len(payload), off))
            continue

        if ns in additions:
            payload = additions.pop(ns)
            crc = zlib.crc32(payload) & 0xffffffff
            off = len(out_buf)
            out_buf += make_local(name_b, 0, 0, crc, len(payload), len(payload)) + payload
            centrals.append(make_central(name_b, 0, 0, crc, len(payload), len(payload), off))
            continue

        # 未修改 entry：原段拷贝
        seg_start = e["lho"]
        llen = local_len(data, seg_start)
        if seg_start + llen + e["comp"] > len(data):
            raise SystemExit("bad local segment: " + ns)
        seg = bytearray(data[seg_start:seg_start + llen + e["comp"]])
        if struct.unpack_from("<H", seg, 6)[0] & 0x0008:
            struct.pack_into("<H", seg, 6, e["flags"] & ~0x0008)
            struct.pack_into("<H", seg, 8, e["method"])
            struct.pack_into("<I", seg, 14, e["crc"])
            struct.pack_into("<I", seg, 18, e["comp"])
            struct.pack_into("<I", seg, 22, e["uncomp"])
        off = len(out_buf)
        out_buf += seg
        centrals.append(make_central(name_b, e["method"], e["flags"] & ~0x0008,
                                     e["crc"], e["comp"], e["uncomp"], off))

    for ns, payload in list(replaced.items()) + list(additions.items()):
        if ns in seen:
            continue
        seen.add(ns)
        name_b = ns.encode("utf-8")
        crc = zlib.crc32(payload) & 0xffffffff
        off = len(out_buf)
        out_buf += make_local(name_b, 0, 0, crc, len(payload), len(payload)) + payload
        centrals.append(make_central(name_b, 0, 0, crc, len(payload), len(payload), off))

    cd_off_new = len(out_buf)
    cd_bytes = b"".join(centrals)
    out_buf += cd_bytes
    out_buf += make_eocd(cd_off_new, len(cd_bytes), len(centrals))
    with open(out, "wb") as f:
        f.write(out_buf)
    print(f"[ok] unsigned built: {len(out_buf)} bytes ({len(centrals)} entries), "
          f"input_apk={any(k.startswith('assets/') and k.endswith('.apk') for k in seen)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", required=True)
    ap.add_argument("--apktool", required=True)
    ap.add_argument("--baksmali", required=True)
    ap.add_argument("--smali", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--dedup", action="store_true", help="MT 式数据复用优化（workflow 默认勾选）")
    a = ap.parse_args()

    activity = get_activity(a.apk, a.apktool)
    print("[info] Activity:", activity)
    rel = activity.replace(".", "/") + ".smali"

    unz = os.path.join(DEX_WORK, "unzipped")
    os.makedirs(unz, exist_ok=True)

    dex_files = []
    with zipfile.ZipFile(a.apk) as z:
        for n in z.namelist():
            if re.fullmatch(r"classes\d*\.dex", n):
                dex_files.append(n)
                z.extract(n, unz)
    dex_files.sort()
    print("[info] dex files:", len(dex_files))
    if not find_and_patch(unz, dex_files, rel, a.baksmali, a.smali):
        print("FAIL: 未在任何 dex 找到 Activity")
        sys.exit(1)

    replaced = {}
    with zipfile.ZipFile(a.apk) as z:
        for dex in dex_files:
            orig_bytes = z.read(dex)
            new_bytes = open(os.path.join(unz, dex), "rb").read()
            if new_bytes != orig_bytes:
                replaced[dex] = new_bytes
                print(f"[ok] replaced {dex} -> {len(new_bytes)} bytes")

    additions = {}

    injected_so = 0
    for abi in ABIS:
        src = os.path.join(THIS_DIR, KILLER_LIB, abi, "libZcraft.so")
        if os.path.isfile(src):
            additions[f"lib/{abi}/libZcraft.so"] = open(src, "rb").read()
            injected_so += 1
            print(f"[ok] lib/{abi}/libZcraft.so")
    if injected_so == 0:
        print("FAIL: 没有注入 libZcraft.so（先运行 prepare 生成 work_killer/lib）")
        sys.exit(1)

        import random, string
    r_dir = "".join(random.choices(string.ascii_lowercase + string.digits, k=7))
    r_file = "".join(random.choices(string.ascii_lowercase + string.digits, k=9)) + ".apk"
    rand_entry = f"assets/{r_dir}/{r_file}"
    additions[rand_entry] = open(a.apk, "rb").read()
    print(f"[ok] {rand_entry} <- 输入 APK（全随机混淆名称，STORE供数据复用）"))

    killer_dex_src = os.path.join(THIS_DIR, "work_killer", "classes.dex")
    if not os.path.isfile(killer_dex_src):
        print("FAIL: 缺 work_killer/classes.dex")
        sys.exit(1)
    killer_dex_data = open(killer_dex_src, "rb").read()
    n = 2
    existing = set(dex_files)
    while f"classes{n}.dex" in existing:
        n += 1
    new_dex_name = f"classes{n}.dex"
    additions[new_dex_name] = killer_dex_data
    print(f"[ok] killer dex -> {new_dex_name}")

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    unsigned = os.path.join(WORK, f"dex_only_unsigned_{ts}.apk")
    build_unsigned(a.apk, unsigned, replaced=replaced, additions=additions)

    sign_cmd = ["python3", os.path.join(THIS_DIR, "finalize_sign.py"),
                "--input", unsigned,
                "--output", a.output,
                "--orig", a.apk]
    if a.dedup:
        sign_cmd.append("--multiplex")
    run(sign_cmd)


if __name__ == "__main__":
    main()
