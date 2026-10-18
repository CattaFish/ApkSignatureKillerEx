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

def axml_replace_string(raw, old, new):
    """在 AXML 字符串池中原地替换字符串（NUL 终止，长度可短不可长）"""
    # 尝试 UTF-8 池
    old_b = old.encode('utf-8')
    idx = raw.find(old_b)
    if idx != -1:
        new_b = new.encode('utf-8')
        if len(new_b) > len(old_b):
            raise ValueError("new string longer than old (utf8)")
        buf = bytearray(raw)
        buf[idx:idx+len(new_b)] = new_b
        # 剩余全部填 0
        for i in range(idx + len(new_b), idx + len(old_b)):
            buf[i] = 0
        return bytes(buf)
    # 尝试 UTF-16 池
    old_16 = old.encode('utf-16-le')
    idx16 = raw.find(old_16)
    if idx16 != -1:
        new_16 = new.encode('utf-16-le')
        if len(new_16) > len(old_16):
            raise ValueError("new string longer than old (utf16)")
        buf = bytearray(raw)
        buf[idx16:idx16+len(new_16)] = new_16
        # 剩余填 0（按 2 字节）
        for i in range(idx16 + len(new_16), idx16 + len(old_16)):
            buf[i] = 0
        return bytes(buf)
    raise ValueError("target string not found in AXML: " + old)


import struct as _struct


def _read_uleb128(data: bytes, p: int):
    """从 data[p] 解析一个 uleb128，返回 (值, 下一个位置)"""
    result = 0
    shift = 0
    while p < len(data):
        b = data[p]
        p += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, p


def _dex_get_string(data: bytes, string_ids_off: int, string_ids_size: int, idx: int):
    """真正解析 DEX string_data_item：跳过 utf16_size 后读 MUTF-8 直到 0x00。

    之前的 bug：把字符串内容第一个字节（如 'L'=0x4C=76）当成 uleb128 长度再解一遍，
    导致所有类名都解析错误，永远匹配不上 target_desc。
    """
    if idx >= string_ids_size:
        return None
    str_off = _struct.unpack_from("<I", data, string_ids_off + idx * 4)[0]
    p = str_off
    # 跳过 uleb128 utf16_size（字符串的 UTF-16 长度）
    _, p = _read_uleb128(data, p)
    start = p
    # MUTF-8 数据，0x00 结尾
    while p < len(data) and data[p] != 0:
        p += 1
    try:
        return data[start:p].decode("utf-8", errors="replace")
    except Exception:
        return None


def dex_defines_class(dex_data: bytes, target_desc: str) -> bool:
    """检查 dex 是否真正定义（class_defs）了 target_desc 这个类"""
    if len(dex_data) < 0x70:
        return False
    if dex_data[:4] != b"dex\n":
        return False
    # DEX header 字段偏移
    string_ids_size = _struct.unpack_from("<I", dex_data, 0x38)[0]
    string_ids_off  = _struct.unpack_from("<I", dex_data, 0x3C)[0]
    type_ids_size   = _struct.unpack_from("<I", dex_data, 0x40)[0]
    type_ids_off    = _struct.unpack_from("<I", dex_data, 0x44)[0]
    class_defs_size = _struct.unpack_from("<I", dex_data, 0x60)[0]
    class_defs_off  = _struct.unpack_from("<I", dex_data, 0x64)[0]

    if string_ids_off == 0 or type_ids_off == 0 or class_defs_off == 0:
        return False

    def get_type(idx):
        if idx >= type_ids_size:
            return None
        tidx = _struct.unpack_from("<I", dex_data, type_ids_off + idx * 4)[0]
        return _dex_get_string(dex_data, string_ids_off, string_ids_size, tidx)

    # 遍历 class_defs，检查 class_idx 对应的 type 描述符
    for i in range(class_defs_size):
        cls_idx = _struct.unpack_from("<I", dex_data, class_defs_off + i * 32)[0]
        t = get_type(cls_idx)
        if t == target_desc:
            return True
    return False


def dex_class_names(dex_data: bytes):
    """返回该 dex 中所有 class_defs 的类名（用于诊断）"""
    if len(dex_data) < 0x70 or dex_data[:4] != b"dex\n":
        return []
    string_ids_size = _struct.unpack_from("<I", dex_data, 0x38)[0]
    string_ids_off  = _struct.unpack_from("<I", dex_data, 0x3C)[0]
    type_ids_size   = _struct.unpack_from("<I", dex_data, 0x40)[0]
    type_ids_off    = _struct.unpack_from("<I", dex_data, 0x44)[0]
    class_defs_size = _struct.unpack_from("<I", dex_data, 0x60)[0]
    class_defs_off  = _struct.unpack_from("<I", dex_data, 0x64)[0]

    names = []
    for i in range(class_defs_size):
        cls_idx = _struct.unpack_from("<I", dex_data, class_defs_off + i * 32)[0]
        if cls_idx < type_ids_size:
            tidx = _struct.unpack_from("<I", dex_data, type_ids_off + cls_idx * 4)[0]
            s = _dex_get_string(dex_data, string_ids_off, string_ids_size, tidx)
            if s:
                names.append(s)
    return names


def find_tinker_dex(input_apk, work):
    """在 APK 所有 dex 中找出真正定义 TinkerApplication 的那个"""
    target = "Lcom/tencent/tinker/loader/app/TinkerApplication;"
    with zipfile.ZipFile(input_apk) as z:
        for n in sorted(z.namelist()):
            if not n.endswith(".dex"):
                continue
            data = z.read(n)
            if dex_defines_class(data, target):
                log("TinkerApplication DEFINED in: " + n)
                dex_path = work / n
                dex_path.write_bytes(data)
                return n, dex_path
            # 诊断：没匹配上时，看看这个 dex 里有没有 Tinker 相关类
            try:
                names = dex_class_names(data)
                tinker_like = [x for x in names if "Tinker" in x or "tinker" in x]
                if tinker_like:
                    log(f"  {n}: no exact match, Tinker-ish classes: {tinker_like[:20]}")
            except Exception:
                pass
    die("dex defining TinkerApplication not found")


def patch_tinker_application(input_apk, work):
    """从 classes5.dex 提取 TinkerApplication，改 super 为 r.k.app + getTinkerFlags 返回 0，再写回。"""
    log("=== patch TinkerApplication ===")

    baksmali_jar = ROOT / "tools/baksmali.jar"
    smali_jar = ROOT / "tools/smali.jar"
    if not baksmali_jar.exists() or not smali_jar.exists():
        die("baksmali.jar or smali.jar not found in tools/")

    # 1. 精确定位定义 TinkerApplication 的 dex（通过 class_defs 解析）
    target_dex, dex_path = find_tinker_dex(input_apk, work)

    # 3. baksmali 反编译
    smali_dir = work / "tinker_smali"
    smali_dir.mkdir(parents=True, exist_ok=True)
    r = run(["java", "-jar", str(baksmali_jar), "d", str(dex_path), "-o", str(smali_dir)])
    if r.returncode != 0:
        die("baksmali failed")

    # 4. 修改 TinkerApplication.smali（先诊断目录结构）
    ta_path = smali_dir / "com/tencent/tinker/loader/app/TinkerApplication.smali"
    if not ta_path.exists():
        log("=== DIAG: baksmali output structure ===")
        # 列出所有 smali 文件
        all_smali = list(smali_dir.rglob("*.smali"))
        log(f"total smali files: {len(all_smali)}")
        # 找包含 Tinker 的
        tinker_files = [f for f in all_smali if "Tinker" in f.name or "tinker" in str(f)]
        log(f"files containing Tinker: {len(tinker_files)}")
        for f in tinker_files[:20]:
            log("  " + str(f.relative_to(smali_dir)))
        # 找 com/tencent/tinker 目录
        tinker_dir = smali_dir / "com" / "tencent" / "tinker"
        if tinker_dir.exists():
            log("=== com/tencent/tinker exists ===")
            for f in list(tinker_dir.rglob("*.smali"))[:30]:
                log("  " + str(f.relative_to(smali_dir)))
        else:
            log("=== com/tencent/tinker NOT FOUND ===")
            # 打印顶层目录
            for d in sorted(smali_dir.iterdir()):
                log("  top: " + d.name)
        die("TinkerApplication.smali not found after baksmali")
    smali_text = ta_path.read_text(encoding="utf-8")

    # 4a. 改 super
    if ".super Landroid/app/Application;" not in smali_text:
        log("WARN: TinkerApplication.super is not Application, check content:")
        for line in smali_text.splitlines()[:5]:
            log("  " + line)
    smali_text = smali_text.replace(
        ".super Landroid/app/Application;",
        ".super Lr/k/app;"
    )

    # 4b. 改 getTinkerFlags 返回 0
    old_flags = """.method public getTinkerFlags()I
    .registers 2

    iget v0, p0, Lcom/tencent/tinker/loader/app/TinkerApplication;->tinkerFlags:I

    return v0

.end method"""
    new_flags = """.method public getTinkerFlags()I
    .registers 1

    const/4 p0, 0x0

    return p0

.end method"""
    if old_flags in smali_text:
        smali_text = smali_text.replace(old_flags, new_flags)
        log("getTinkerFlags patched to return 0")
    else:
        log("WARN: getTinkerFlags pattern not found, check method:")
        m = re.search(r'\.method public getTinkerFlags\(\)I.*?\.end method', smali_text, re.DOTALL)
        if m:
            log(m.group(0))
        else:
            log("getTinkerFlags method not found at all")

    ta_path.write_text(smali_text, encoding="utf-8")
    log("TinkerApplication.smali patched")

    # 5. smali 重新编译成 dex（新文件名 classes_patched.dex）
    patched_dex = work / "classes_patched.dex"
    r = run(["java", "-jar", str(smali_jar), "a", str(smali_dir), "-o", str(patched_dex)])
    if r.returncode != 0:
        die("smali assemble failed")
    log("patched dex: " + str(patched_dex.stat().st_size) + " bytes")
    return target_dex, patched_dex


def inject(input_apk, dex_file, so_dir, original_apk, work):
    """复制原 APK，patch TinkerApplication，注入 r.k.app dex + libk.so + assets，不修改 manifest。"""
    log("=== inject (TinkerApplication patch mode) ===")

    # 1. patch TinkerApplication
    target_dex_name, patched_dex = patch_tinker_application(input_apk, work)

    # 2. 构造输出 APK
    output_apk = work / "injected.apk"
    with zipfile.ZipFile(input_apk) as zin, zipfile.ZipFile(output_apk, "w") as zout:
        # 复制全部条目，跳过 META-INF 签名
        for item in zin.infolist():
            if item.filename.startswith("META-INF/"):
                continue
            # 替换被 patch 的 dex
            if item.filename == target_dex_name:
                zout.writestr(item, patched_dex.read_bytes())
                log("replaced " + target_dex_name + " with patched version")
            else:
                zout.writestr(item, zin.read(item.filename))
        log("copied original entries (skip META-INF)")

        # 3. 收集原始 dex 编号
        original_numbers = set()
        for n in zout.namelist():
            mm = re.fullmatch(r"classes(\d*)\.dex", n)
            if mm:
                num = int(mm.group(1)) if mm.group(1) else 1
                original_numbers.add(num)
        log(f"Original dex numbers: {sorted(original_numbers)}")

        # 4. 动态挑下一个空闲 classesN.dex
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

        # 5. 注入 native lib
        if so_dir:
            for abi in so_dir.iterdir():
                if abi.is_dir():
                    for so in abi.glob("*.so"):
                        arc = "lib/" + abi.name + "/" + so.name
                        zout.writestr(arc, so.read_bytes())
                        log("inject " + arc)

        # 6. 注入 assets 原包
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
