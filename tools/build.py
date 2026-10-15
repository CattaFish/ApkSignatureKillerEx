#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys, re, shutil, subprocess, tempfile, zipfile, base64, traceback
from pathlib import Path

print("=== build.py loaded (classesN inject mode) ===", flush=True)

ROOT = Path(__file__).resolve().parent.parent

INPUT_APK     = os.environ.get("INPUT_APK", "input.apk")
ORIGINAL_APK  = os.environ.get("ORIGINAL_APK", "")
OUTPUT_APK    = os.environ.get("OUTPUT_APK", "output.apk")
SO_NAME       = os.environ.get("SO_NAME", "k")
ASSET_DIR     = os.environ.get("ASSET_DIR", "SginatareKiler")
ASSET_NAME    = os.environ.get("ASSET_NAME", "0rigih.apk")
FILES_DIR     = os.environ.get("FILES_DIR", "files/k")
TARGET_PKG    = os.environ.get("TARGET_PKG", "")
SIGNATURE_B64 = os.environ.get("SIGNATURE_B64", "")
ANDROID_HOME  = os.environ.get("ANDROID_HOME", "")
NDK_HOME      = os.environ.get("ANDROID_NDK_HOME", "") or os.environ.get("NDK_HOME", "")

APKTOOL_JAR   = ROOT / "tools/apktool.jar"

def log(m):
    print("[build] " + str(m), flush=True)

def die(m):
    print("[FATAL] " + str(m), file=sys.stderr, flush=True)
    sys.exit(1)

def run(cmd, capture=False, **kw):
    log("+ " + " ".join(str(c) for c in cmd))
    if capture:
        kw["capture_output"] = True
        kw["text"] = True
    try:
        return subprocess.run([str(c) for c in cmd], **kw)
    except FileNotFoundError as e:
        die("command not found: " + str(cmd[0]) + " (" + str(e) + ")")

def sdk_tool(name):
    if ANDROID_HOME:
        bt = Path(ANDROID_HOME) / "build-tools"
        if bt.exists():
            vers = sorted([d for d in bt.iterdir() if d.is_dir()], reverse=True)
            for v in vers:
                p = v / name
                if p.exists():
                    return str(p)
    return shutil.which(name)

def android_jar():
    if ANDROID_HOME:
        platforms = Path(ANDROID_HOME) / "platforms"
        if platforms.exists():
            vers = sorted([d for d in platforms.iterdir() if d.is_dir()], reverse=True)
            for v in vers:
                p = v / "android.jar"
                if p.exists():
                    return str(p)
    die("android.jar not found")

def extract_signature(apk):
    log("Extract signature from " + str(apk))

    # 1. 优先尝试 v1 签名（META-INF/*.RSA）
    try:
        with zipfile.ZipFile(apk) as z:
            for n in z.namelist():
                if re.match(r"META-INF/.*\.(RSA|DSA|EC)$", n):
                    b = base64.b64encode(z.read(n)).decode()
                    return re.sub(r"\s+", "", b)
    except Exception as e:
        log("v1 signature extract failed: " + str(e))

    # 2. 失败则用 keytool 读取 APK 整体签名证书（支持 v1/v2/v3）
    log("Try keytool -printcert -jarfile -rfc ...")
    r = run(["keytool", "-printcert", "-jarfile", str(apk), "-rfc"], capture=True)
    if r.returncode != 0:
        die("keytool failed: " + (r.stderr or r.stdout or ""))

    out = r.stdout or ""
    m = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", out, re.DOTALL)
    if not m:
        die("No certificate found in keytool output")
    b64 = m.group(1).replace("\n", "").replace("\r", "").strip()
    if not b64:
        die("Empty certificate in keytool output")
    return b64

def compile_java(out):
    log("Compile Java -> dex")
    src_dir = out / "java_src" / "r" / "k"
    stub_dir = ROOT / "tools/stub"
    aj = android_jar()
    cls = out / "classes"
    cls.mkdir(parents=True, exist_ok=True)
    files = list(src_dir.rglob("*.java"))
    if not files:
        die("no java files under src/java/r/k")
    log("javac " + str(len(files)) + " files...")
    cmd = ["javac", "-source", "1.8", "-target", "1.8",
           "-bootclasspath", aj,
           "-classpath", str(stub_dir),
           "-sourcepath", str(stub_dir),
           "-d", str(cls)] + files
    r = run(cmd)
    if r.returncode != 0:
        die("javac failed")
    # 移除 stub 产物
    for stub_pkg in ("sun", "dalvik"):
        d = cls / stub_pkg
        if d.exists():
            shutil.rmtree(d)
    classes = list(cls.rglob("*.class"))
    if not classes:
        die("no classes after javac")
    d8 = sdk_tool("d8")
    if not d8:
        die("d8 not found")
    log("d8 -> classes.dex")
    cmd = [d8, "--min-api", "21", "--lib", aj, "--output", str(out)] + classes
    r = run(cmd)
    if r.returncode != 0:
        die("d8 failed")
    dex_out = out / "classes.dex"
    if not dex_out.exists():
        die("classes.dex not produced")
    log("OK classes.dex size=" + str(dex_out.stat().st_size))
    return dex_out

def build_native(out):
    log("Build native lib" + SO_NAME)
    nat = ROOT / "native"
    xh = ROOT / "killer/src/main/c"
    for f in ["xhook.c", "xh_core.c", "xh_elf.c", "xh_log.c", "xh_util.c", "xh_version.c",
              "xhook.h", "xh_core.h", "xh_elf.h", "xh_errno.h", "xh_log.h", "xh_util.h",
              "xh_version.h", "queue.h", "tree.h"]:
        sf = xh / f
        df = nat / f
        if sf.exists() and not df.exists():
            shutil.copy(sf, df)
    (nat / "CMakeLists.txt").write_text(
        'cmake_minimum_required(VERSION 3.18)\n'
        'project(killer C)\n'
        'set(CMAKE_C_STANDARD 11)\n'
        'add_library(' + SO_NAME + ' SHARED mt_jni.c xhook.c xh_core.c xh_elf.c xh_log.c xh_util.c xh_version.c)\n'
        'target_include_directories(' + SO_NAME + ' PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})\n'
        'target_link_libraries(' + SO_NAME + ' log)\n'
    )
    if not NDK_HOME:
        log("WARN: NDK_HOME not set, skip native")
        return None
    toolchain = Path(NDK_HOME) / "build/cmake/android.toolchain.cmake"
    if not toolchain.exists():
        log("WARN: toolchain not found " + str(toolchain))
        return None
    so_dir = out / "jni"
    so_dir.mkdir(parents=True, exist_ok=True)
    for abi in ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]:
        bd = out / ("nb_" + abi)
        bd.mkdir(parents=True, exist_ok=True)
        log("NDK build " + abi)
        cmd = ["cmake", "-DCMAKE_TOOLCHAIN_FILE=" + str(toolchain),
               "-DANDROID_ABI=" + abi, "-DANDROID_PLATFORM=android-21",
               "-DCMAKE_BUILD_TYPE=Release", "-S", str(nat), "-B", str(bd)]
        r = run(cmd)
        if r.returncode != 0:
            log("cmake configure fail " + abi)
            continue
        r = run(["cmake", "--build", str(bd)])
        if r.returncode != 0:
            log("cmake build fail " + abi)
            continue
        so = bd / ("lib" + SO_NAME + ".so")
        if so.exists():
            d = so_dir / abi
            d.mkdir(parents=True, exist_ok=True)
            shutil.copy(so, d / so.name)
            log("OK lib/" + abi + "/" + so.name)
    if not any(so_dir.iterdir()):
        log("WARN: no .so produced")
        return None
    return so_dir

def patch_manifest(decoded_dir):
    """修改 AndroidManifest.xml，设置 android:name='r.k.app'"""
    mp = decoded_dir / "AndroidManifest.xml"
    txt = mp.read_text(encoding="utf-8", errors="ignore")
    m = re.search(r'<application\b[^>]*\bandroid:name="([^"]+)"', txt)
    if m:
        old_name = m.group(1)
        txt = txt.replace('android:name="' + old_name + '"', 'android:name="r.k.app"')
        log(f"Application name replaced: {old_name} -> r.k.app")
    else:
        txt = re.sub(r'(<application\b)', r'\1 android:name="r.k.app"', txt, count=1)
        log("Application name inserted: r.k.app")
    mp.write_text(txt, encoding="utf-8")

def inject_classesN(input_apk, output_unsigned, dex_file, so_dir, original_apk, work):
    """核心：不再 apktool d/b 全量解包，
    而是 apktool d -s 只解 Manifest（不动 dex），
    然后直接把 classesN.dex / lib / assets 塞进 APK。"""
    log("=== classesN inject mode ===")

    # 1. apktool d -s 只解 manifest 和资源
    dec = work / "decoded"
    dec.mkdir(parents=True, exist_ok=True)
    r = run(["java", "-jar", str(APKTOOL_JAR), "d", "-s", "-f", "-o", str(dec), str(input_apk)])
    if r.returncode != 0:
        die("apktool d -s failed (manifest/res decode)")

    # 2. 改 Manifest
    patch_manifest(dec)

    # 3. apktool b 重打包（不含 dex，但会把原资源/manifest 编回来）
    #    注意：-s 模式下，apktool b 不会重新生成 dex，原 dex 会怎样？
    #    实际上 apktool d -s 后，decoded 里没有 dex 文件，build 时不会生成 dex，
    #    所以需要手动把原 dex 从 input.apk 复制回 output。
    repacked = work / "repacked.apk"
    r = run(["java", "-jar", str(APKTOOL_JAR), "b", "-o", str(repacked), str(dec)])
    if r.returncode != 0:
        die("apktool b failed")
    log("repacked (manifest/res only): " + str(repacked.stat().st_size) + " bytes")

    # 4. 把原 APK 的 dex 全部复制进 repacked.apk
    log("Copy original dex files into output...")
    with zipfile.ZipFile(input_apk) as zin, zipfile.ZipFile(repacked, "a") as zout:
        # 先列出已有 dex
        existing = set(zout.namelist())
        for n in zin.namelist():
            if n.endswith(".dex") and n not in existing:
                zout.writestr(n, zin.read(n))
        # 5. 注入编译好的 dex 为 classes20.dex
        next_idx = 2
        while f"classes{next_idx}.dex" in existing or f"classes{next_idx}.dex" not in [x for x in zin.namelist() if x.endswith('.dex')]:
            # 找下一个空余编号
            all_dex = set(x for x in zin.namelist() if x.endswith(".dex"))
            if f"classes{next_idx}.dex" not in all_dex and f"classes{next_idx}.dex" not in zout.namelist():
                break
            next_idx += 1
        inject_name = f"classes{next_idx}.dex"
        log(f"Inject dex as {inject_name}")
        zout.writestr(inject_name, dex_file.read_bytes())

        # 6. 注入 native lib
        if so_dir:
            for abi in so_dir.iterdir():
                if abi.is_dir():
                    for so in abi.glob("*.so"):
                        arc = f"lib/{abi.name}/{so.name}"
                        zout.writestr(arc, so.read_bytes())
                        log(f"inject {arc}")

        # 7. 注入 assets 原包
        asset_arc = f"assets/{ASSET_DIR}/{ASSET_NAME}"
        if original_apk:
            zout.writestr(asset_arc, original_apk.read_bytes())
            log(f"inject {asset_arc} <- {original_apk.name}")

    log("injected APK: " + str(repacked.stat().st_size) + " bytes")
    return repacked

def sign(unsigned, final):
    log("apksigner sign")
    apksigner = sdk_tool("apksigner")
    if not apksigner:
        die("apksigner not found")
    ks = ROOT / "fake.jks"
    cmd = [apksigner, "sign",
           "--ks", str(ks), "--ks-pass", "pass:123456",
           "--key-pass", "pass:123456", "--ks-key-alias", "key0",
           "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
           "--out", str(final), str(unsigned)]
    r = run(cmd)
    if r.returncode != 0:
        die("apksigner failed")

def main():
    log("Input APK : " + INPUT_APK)
    log("Original  : " + ORIGINAL_APK)
    log("Output    : " + OUTPUT_APK)
    log("SO        : lib" + SO_NAME + ".so")
    log("Asset     : assets/" + ASSET_DIR + "/" + ASSET_NAME)
    log("Files dir : " + FILES_DIR)
    global SIGNATURE_B64, TARGET_PKG
    input_apk = ROOT / INPUT_APK
    if not input_apk.exists():
        die("input.apk not found: " + str(input_apk))
    original = (ROOT / ORIGINAL_APK) if ORIGINAL_APK else input_apk
    if not original.exists():
        die("original apk not found: " + str(original))
    if not SIGNATURE_B64:
        SIGNATURE_B64 = extract_signature(original)
    if not TARGET_PKG:
        aapt = sdk_tool("aapt")
        if aapt:
            r = run([aapt, "dump", "badging", str(input_apk)], capture=True)
            if r.returncode == 0:
                m = re.search(r"package: name='([^']+)'", r.stdout or "")
                if m:
                    TARGET_PKG = m.group(1)
                    log("Auto pkg: " + TARGET_PKG)
    if not TARGET_PKG:
        die("cannot detect package, set TARGET_PKG env")
    log("Package    : " + TARGET_PKG)
    with tempfile.TemporaryDirectory(prefix="apksig_", dir=str(ROOT)) as tmp:
        work = Path(tmp)
        java_src = work / "java_src"
        shutil.copytree(ROOT / "src/java/r", java_src / "r")
        ap = java_src / "r/k/app.java"
        t = ap.read_text(encoding="utf-8")
        t = t.replace("%%TARGET_PKG%%", TARGET_PKG)
        t = t.replace("%%SIGNATURE_B64%%", SIGNATURE_B64)
        t = t.replace("%%LIB_NAME%%", SO_NAME)
        t = t.replace("%%ASSET_PATH%%", "assets/" + ASSET_DIR + "/" + ASSET_NAME)
        t = t.replace("%%FILES_DIR%%", FILES_DIR)
        ap.write_text(t, encoding="utf-8")
        log("Java template updated")
        dex_file = compile_java(work)
        so_dir = None
        try:
            so_dir = build_native(work)
        except Exception as e:
            log("native skip: " + str(e))
        unsigned = inject_classesN(input_apk, original, dex_file, so_dir, original, work)
        final = ROOT / OUTPUT_APK
        sign(unsigned, final)
    log("BUILD SUCCESS: " + str(ROOT / OUTPUT_APK))

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        sys.exit(1)
