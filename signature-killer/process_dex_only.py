#!/usr/bin/env python3
"""Dex-only pipeline for resource-obfuscated large APKs (QQ/WeChat style):
unzip -> baksmali patch Activity <clinit> -> rezip (original resources untouched)
-> zipalign -> finalize_sign (V1 trio preserved + new V2). No resource rebuild.
"""
import argparse, datetime, os, re, shutil, subprocess, sys, zipfile

WORK = "work_out"
DEX_WORK = os.path.join(WORK, "dexwork")
KILLER_DEX = "work_killer/classes.dex"
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
    # -s（不反编译 dex，manifest 解码为文本）；dexonly 不重编译资源，-r 不需要
    run(["java", "-jar", apktool, "d", "-f", "-s", "-o", man_dir, apk])
    _man_path = os.path.join(man_dir, "AndroidManifest.xml")
    man = open(_man_path, encoding="utf-8", errors="replace").read()
    if "<manifest" not in man:
        print("[warn] AndroidManifest.xml 非文本，尝试 binary fallback")
        import re as _re
        blob = open(_man_path, "rb").read()
        # 二进制 AXML 中 activity 类名仍以完整字符串存在
        cand = _re.findall(rb'[a-zA-Z_][a-zA-Z0-9_.]{10,120}\.activity\.[a-zA-Z0-9_.]+', blob)
        if cand:
            cls = cand[-1].decode(errors="replace")
            print("[info] binary activity:", cls)
            return cls
        # 最后尝试 treat as text with errors replaced
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", required=True)
    ap.add_argument("--apktool", required=True)
    ap.add_argument("--baksmali", required=True)
    ap.add_argument("--smali", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--dedup", action="store_true", help="remove assets/SignedByRS/input.apk copy")
    a = ap.parse_args()

    activity = get_activity(a.apk, a.apktool)
    print("[info] Activity:", activity)
    rel = activity.replace(".", "/") + ".smali"

    unz = os.path.join(DEX_WORK, "unzipped")
    os.makedirs(unz, exist_ok=True)
    with zipfile.ZipFile(a.apk) as z:
        z.extractall(unz)

    dex_files = sorted([n for n in os.listdir(unz) if re.fullmatch(r"classes\d*\.dex", n)])
    print("[info] dex files:", len(dex_files))
    if not find_and_patch(unz, dex_files, rel, a.baksmali, a.smali):
        print("FAIL: 未在任何 dex 找到 Activity")
        sys.exit(1)

    if not os.path.isfile(KILLER_DEX):
        print("FAIL: 缺 work_killer/classes.dex")
        sys.exit(1)
    # 注入 killer dex 作为新 classesN.dex
    existing = set(dex_files)
    n = 2
    while f"classes{n}.dex" in existing:
        n += 1
    new_dex_name = f"classes{n}.dex"

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    unsigned = os.path.join(WORK, f"dex_only_unsigned_{ts}.apk")
    skip_set = set()
    if a.dedup:
        skip_set.add("assets/SignedByRS/input.apk")
        print("[dedup] 移除 assets/SignedByRS/input.apk 副本")
    with zipfile.ZipFile(unsigned, "w") as zout:
        for root, dirs, files in os.walk(unz):
            for f in files:
                full = os.path.join(root, f)
                relf = os.path.relpath(full, unz)
                if relf.replace("\\", "/") in skip_set:
                    continue
                zout.write(full, relf)
        zout.write(KILLER_DEX, new_dex_name)
        print(f"[ok] killer dex -> {new_dex_name}")

    print("[ok] unsigned:", unsigned)

    run(["python3", os.path.join(THIS_DIR, "finalize_sign.py"),
         "--input", unsigned,
         "--output", a.output,
         "--orig", a.apk])


if __name__ == "__main__":
    main()
