#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ApkSignatureKillerEx replica builder
No apktool. Direct zipfile copy + androguard manifest edit + aapt2 compile.
"""
import os, sys, re, shutil, subprocess, tempfile, zipfile, base64, traceback
from pathlib import Path

print("=== build.py loaded (no-apktool mode) ===", flush=True)

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
    try:
        with zipfile.ZipFile(apk) as z:
            for n in z.namelist():
                if re.match(r"META-INF/.*\.(RSA|DSA|EC)$", n):
                    b = base64.b64encode(z.read(n)).decode()
                    return re.sub(r"\s+", "", b)
    except Exception as e:
        log("v1 extract failed: " + str(e))
    log("keytool fallback...")
    r = run(["keytool", "-printcert", "-jarfile", str(apk), "-rfc"], capture=True)
    if r.returncode != 0:
        die("keytool failed")
    m = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", r.stdout or "", re.DOTALL)
    if not m:
        die("no cert in keytool output")
    return m.group(1).replace("\n", "").replace("\r", "").strip()

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
    r = run(["javac", "-source", "1.8", "-target", "1.8",
             "-bootclasspath", aj,
             "-classpath", str(stub_dir),
             "-sourcepath", str(stub_dir),
             "-d", str(cls)] + files)
    if r.returncode != 0:
        die("javac failed")
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
    r = run([d8, "--min-api", "21", "--lib", aj, "--output", str(out)] + classes)
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
        r = run(["cmake", "-DCMAKE_TOOLCHAIN_FILE=" + str(toolchain),
                 "-DANDROID_ABI=" + abi, "-DANDROID_PLATFORM=android-21",
                 "-DCMAKE_BUILD_TYPE=Release", "-S", str(nat), "-B", str(bd)])
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

def modify_manifest_text(xml_text):
    """Add/replace android:name to r.k.app in application tag."""
    m = re.search(r'<application\b[^>]*\bandroid:name="([^"]+)"', xml_text)
    if m:
        old = m.group(1)
        xml_text = xml_text.replace('android:name="' + old + '"', 'android:name="r.k.app"')
        log(f"Application name changed: {old} -> r.k.app")
    else:
        xml_text = re.sub(r'(<application\b)', r'\1 android:name="r.k.app"', xml_text, count=1)
        log("Application name inserted: r.k.app")
    return xml_text

def compile_manifest_binary(xml_text, work):
    """Compile clean XML text to binary AXML via aapt2."""
    aj = android_jar()
    tmp_manifest = work / "AndroidManifest_clean.xml"
    tmp_manifest.write_text(xml_text, encoding="utf-8")
    out_apk = work / "manifest_bin.apk"
    aapt2 = sdk_tool("aapt2")
    if not aapt2:
        die("aapt2 not found")
    r = run([aapt2, "link",
             "-o", str(out_apk),
             "--manifest", str(tmp_manifest),
             "-I", aj,
             "--min-sdk-version", "21",
             "--target-sdk-version", "32",
             "--version-code", "1",
             "--version-name", "1.0"])
    if r.returncode != 0:
        die("aapt2 link failed")
    binary_manifest = work / "AndroidManifest.bin"
    with zipfile.ZipFile(out_apk) as z:
        if "AndroidManifest.xml" not in z.namelist():
            die("aapt2 output has no AndroidManifest.xml")
        binary_manifest.write_bytes(z.read("AndroidManifest.xml"))
    log("OK binary manifest (" + str(binary_manifest.stat().st_size) + " bytes)")
    return binary_manifest

def inject(input_apk, dex_file, so_dir, original_apk, work):
    """No apktool: copy zip entries, replace binary manifest, inject dex/so/assets."""
    log("=== inject (no-apktool) ===")

    # 1. Extract binary manifest, modify directly via axml_modifier
    import importlib.util
    mod_path = ROOT / "tools" / "axml_modifier.py"
    spec = importlib.util.spec_from_file_location("axml_modifier", mod_path)
    axml_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(axml_mod)

    binary_manifest = work / "AndroidManifest.bin"
    with zipfile.ZipFile(input_apk) as z:
        if "AndroidManifest.xml" not in z.namelist():
            die("no AndroidManifest.xml in input apk")
        raw_axml = z.read("AndroidManifest.xml")
    log("modifying binary AXML directly...")
    new_axml = axml_mod.modify_application_name(raw_axml, "r.k.app")
    binary_manifest.write_bytes(new_axml)
    log("OK binary manifest modified (" + str(len(new_axml)) + " bytes)")

    # 2. Build output APK
    output_apk = work / "injected.apk"
    with zipfile.ZipFile(input_apk) as zin, zipfile.ZipFile(output_apk, "w") as zout:
        for item in zin.infolist():
            if item.filename.startswith("META-INF/"):
                continue
            zout.writestr(item, zin.read(item.filename))
        log("copied " + str(len(zin.namelist())) + " original entries (skip META-INF)")

        # 3. Replace binary manifest
        zout.writestr("AndroidManifest.xml", binary_manifest.read_bytes())
        log("replaced AndroidManifest.xml")

        # 4. Collect original dex numbers
        original_numbers = set()
        for n in zout.namelist():
            m = re.fullmatch(r"classes(\d*)\.dex", n)
            if m:
                num = int(m.group(1)) if m.group(1) else 1
                original_numbers.add(num)
        log(f"Original dex numbers: {sorted(original_numbers)}")

        # 5. Pick next free classesN.dex
        next_num = 1
        while True:
            name = "classes.dex" if next_num == 1 else f"classes{next_num}.dex"
            if next_num not in original_numbers and name not in zout.namelist():
                break
            next_num += 1
        if next_num == 1:
            next_num = 2
            while f"classes{next_num}.dex" in zout.namelist():
                next_num += 1
        inject_name = f"classes{next_num}.dex"
        log("Auto-selected new dex name: " + inject_name)
        zout.writestr(inject_name, dex_file.read_bytes())

        # 6. Inject native libs
        if so_dir:
            for abi in so_dir.iterdir():
                if abi.is_dir():
                    for so in abi.glob("*.so"):
                        arc = "lib/" + abi.name + "/" + so.name
                        zout.writestr(arc, so.read_bytes())
                        log("inject " + arc)

        # 7. Inject assets original
        if original_apk:
            asset_arc = "assets/" + ASSET_DIR + "/" + ASSET_NAME
            zout.writestr(asset_arc, original_apk.read_bytes())
            log("inject " + asset_arc + " <- " + original_apk.name)

    log("injected APK: " + str(output_apk.stat().st_size) + " bytes")
    return output_apk

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
        unsigned = inject(input_apk, dex_file, so_dir, original, work)
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
