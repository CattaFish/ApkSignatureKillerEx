#!/usr/bin/env python3
"""ApkSignatureKillerEx replica build pipeline.
输入 APK -> 注入 r.k.app + libk.so + assets -> 输出 APK
"""

import os
import sys
import re
import shutil
import subprocess
import tempfile
import zipfile
import base64
import glob
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ---------- 读取环境变量（带默认值） ----------
INPUT_APK      = os.environ.get("INPUT_APK", "input.apk")
ORIGINAL_APK   = os.environ.get("ORIGINAL_APK", "")
OUTPUT_APK     = os.environ.get("OUTPUT_APK", "output.apk")
SO_NAME        = os.environ.get("SO_NAME", "k")
ASSET_DIR      = os.environ.get("ASSET_DIR", "SginatareKiler")
ASSET_NAME     = os.environ.get("ASSET_NAME", "0rigih.apk")
FILES_DIR      = os.environ.get("FILES_DIR", "files/k")
TARGET_PKG     = os.environ.get("TARGET_PKG", "")
SIGNATURE_B64  = os.environ.get("SIGNATURE_B64", "")

ANDROID_HOME   = os.environ.get("ANDROID_HOME", "")
NDK_HOME       = os.environ.get("ANDROID_NDK_HOME", "") or os.environ.get("NDK_HOME", "")
APKTOOL_JAR    = ROOT / "tools/apktool.jar"
BAKSMALI_JAR   = ROOT / "tools/baksmali.jar"

def log(msg):
    print(f"[build] {msg}", flush=True)

def die(msg):
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(1)

def run(cmd, **kw):
    log("+ " + " ".join(str(c) for c in cmd))
    return subprocess.run([str(c) for c in cmd], **kw)

def find_sdk_tool(name):
    """在 SDK build-tools 里查找可执行文件"""
    if ANDROID_HOME:
        bt_dir = Path(ANDROID_HOME) / "build-tools"
        if bt_dir.exists():
            # 找最高的 build-tools 版本
            versions = sorted([d for d in bt_dir.iterdir() if d.is_dir()], reverse=True)
            for v in versions:
                p = v / name
                if p.exists():
                    return str(p)
    # fallback: 直接 PATH
    return name

def locate_android_jar():
    if ANDROID_HOME:
        p = Path(ANDROID_HOME) / "platforms" / "android-32" / "android.jar"
        if p.exists():
            return str(p)
        # 搜索任意版本
        platforms = Path(ANDROID_HOME) / "platforms"
        if platforms.exists():
            vers = sorted([d for d in platforms.iterdir() if d.is_dir()], reverse=True)
            for v in vers:
                p = v / "android.jar"
                if p.exists():
                    return str(p)
    die("Cannot find android.jar. Set ANDROID_HOME or install platforms.")

def extract_signature(apk_path):
    """从 APK 的 META-INF/*.RSA 提取证书 DER，返回 Base64"""
    log(f"Extracting signature from {apk_path}")
    with zipfile.ZipFile(apk_path) as z:
        for name in z.namelist():
            m = re.match(r"META-INF/.*\.(RSA|DSA|EC)$", name)
            if m:
                der = z.read(name)
                b64 = base64.b64encode(der).decode()
                # 每76字符换行，符合 Signature Base64 格式
                lines = [b64[i:i+76] for i in range(0, len(b64), 76)]
                return "\n".join(lines)
    die(f"No signature file found in {apk_path}")

def compile_java_to_dex(out_dir, java_src_dir):
    """编译 Java 源码为 dex"""
    log("Compiling Java sources...")
    src_dir = java_src_dir / "r" / "k"
    stub_dir = ROOT / "tools" / "stub"
    android_jar = locate_android_jar()

    classes_dir = out_dir / "classes"
    classes_dir.mkdir(parents=True, exist_ok=True)

    # 收集全部 .java
    java_files = list(src_dir.rglob("*.java"))
    if not java_files:
        die("No Java sources found under src/java/r/k/")

    # 编译
    javac = find_sdk_tool("javac") if find_sdk_tool("javac") != "javac" else "javac"
    d8 = find_sdk_tool("d8")

    cmd = [
        "javac",
        "-source", "1.8",
        "-target", "1.8",
        "-bootclasspath", android_jar,
        "-classpath", f"{stub_dir}{os.pathsep}{classes_dir}",
        "-sourcepath", str(stub_dir),
        "-d", str(classes_dir), *java_files
    ]
    r = run(cmd)
    if r.returncode != 0:
        die(f"javac failed:\n{r.stdout}\n{r.stderr}")

    # dex
    class_files = list(classes_dir.rglob("*.class"))
    if not class_files:
        die("No class files after javac")

    dex_cmd = [d8, "--min-api", "21", "--lib", android_jar, "--output", str(out_dir), *class_files]
    r = run(dex_cmd)
    if r.returncode != 0:
        die(f"d8 failed:\n{r.stdout}\n{r.stderr}")

    dex_out = out_dir / "classes.dex"
    if not dex_out.exists():
        die("d8 did not produce classes.dex")

    log(f"Dex created: {dex_out}")
    return dex_out

def build_native(out_dir):
    """编译 C native 库为 lib{SO_NAME}.so (仅 arm64-v8a 和 armeabi-v7a、x86、x86_64)"""
    log(f"Building native lib lib{SO_NAME}.so...")
    native_dir = ROOT / "native"
    xhook_source = ROOT / "killer" / "src" / "main" / "c"
    build_dir = out_dir / "native_build"
    build_dir.mkdir(parents=True, exist_ok=True)

    if not NDK_HOME:
        die("NDK_HOME not set. Cannot compile native lib.")

    # 复制 xhook 源码到 native 目录（如果不存在）
    for f in ["xhook.c", "xh_core.c", "xh_elf.c", "xh_log.c", "xh_util.c", "xh_version.c",
              "xhook.h", "xh_core.h", "xh_elf.h", "xh_errno.h", "xh_log.h", "xh_util.h",
              "xh_version.h", "queue.h", "tree.h", "xh_version.c"]:
        src = xhook_source / f
        if src.exists() and not (native_dir / f).exists():
            shutil.copy(src, native_dir / f)

    # CMakeLists.txt
    cmake = f"""cmake_minimum_required(VERSION 3.18)
project(killer C)

set(CMAKE_C_STANDARD 11)

add_library({SO_NAME} SHARED
    mt_jni.c
    xhook.c xh_core.c xh_elf.c xh_log.c xh_util.c xh_version.c
)

target_include_directories({SO_NAME} PRIVATE ${{CMAKE_CURRENT_SOURCE_DIR}})

target_link_libraries({SO_NAME} log)
"""
    (native_dir / "CMakeLists.txt").write_text(cmake)

    abis = ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]
    so_dir = out_dir / "jni"
    so_dir.mkdir(parents=True, exist_ok=True)

    for abi in abis:
        log(f"Building for {abi}...")
        abi_dir = build_dir / abi
        abi_dir.mkdir(parents=True, exist_ok=True)
        toolchain = str(Path(NDK_HOME) / "build" / "cmake" / "android.toolchain.cmake")
        if not Path(toolchain).exists():
            die(f"NDK toolchain not found: {toolchain}")

        cmd = [
            "cmake",
            "-DCMAKE_TOOLCHAIN_FILE=" + toolchain,
            f"-DANDROID_ABI={abi}",
            "-DANDROID_PLATFORM=android-21",
            "-DCMAKE_BUILD_TYPE=Release",
            "-S", str(native_dir),
            "-B", str(abi_dir)
        ]
        r = run(cmd)
        if r.returncode != 0:
            log(f"cmake configure failed for {abi}, skip")
            continue

        cmd = ["cmake", "--build", str(abi_dir), "--config", "Release"]
        r = run(cmd)
        if r.returncode != 0:
            log(f"cmake build failed for {abi}, skip")
            continue

        so_file = abi_dir / f"lib{SO_NAME}.so"
        if so_file.exists():
            dest = so_dir / abi
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copy(so_file, dest / f"lib{SO_NAME}.so")
            log(f"  -> lib/{abi}/lib{SO_NAME}.so")
        else:
            log(f"  !! lib{SO_NAME}.so not found for {abi}")

    if not any(so_dir.iterdir()):
        die("No .so files were built")
    return so_dir

def inject(input_apk, original_apk, so_dir, dex_file, work_dir):
    """用 apktool 解包、注入、重打包"""
    log("Runnning apktool...")

    d = work_dir / "decoded"
    d.mkdir(parents=True, exist_ok=True)

    # apktool d
    cmd = ["java", "-jar", str(APKTOOL_JAR), "d", "-f", "-o", str(d), str(input_apk)]
    r = run(cmd)
    if r.returncode != 0:
        die(f"apktool d failed:\n{r.stdout}\n{r.stderr}")

    # 注入应用类
    smali_dir = d / "smali"
    smali_dir.mkdir(parents=True, exist_ok=True)

    # 把编译出的 dex 用 baksmali 拆成 smali（为了合并到应用自己的 dex）
    log("Baksmali classes.dex...")
    baksmali_out = work_dir / "baksmali"
    baksmali_out.mkdir(parents=True, exist_ok=True)
    cmd = ["java", "-jar", str(BAKSMALI_JAR), "d", str(dex_file), "-o", str(baksmali_out)]
    r = run(cmd)
    if r.returncode != 0:
        die(f"baksmali failed:\n{r.stdout}\n{r.stderr}")

    # 合并 smali
    for smali_file in baksmali_out.rglob("*.smali"):
        rel = smali_file.relative_to(baksmali_out)
        dest = smali_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(smali_file, dest)

    # 注入 native lib
    if so_dir is None:
        log("WARNING: no native lib built, skip injection")
        return out_unsigned
    for abi_dir in so_dir.iterdir():
        if abi_dir.is_dir():
            dest = d / "lib" / abi_dir.name
            dest.mkdir(parents=True, exist_ok=True)
            for so in abi_dir.glob("*.so"):
                shutil.copy(so, dest / so.name)

    # 注入 assets 原包
    if original_apk:
        asset_dest = d / "assets" / ASSET_DIR
        asset_dest.mkdir(parents=True, exist_ok=True)
        shutil.copy(original_apk, asset_dest / ASSET_NAME)
        log(f"assets/{ASSET_DIR}/{ASSET_NAME} <- {original_apk}")
    else:
        # 用 input.apk 自己作为原包？不行，因为注入后 input.apk 已经不包含原签名，所以这里必须用 original
        log("WARNING: original_apk not provided, using input.apk as original")
        asset_dest = d / "assets" / ASSET_DIR
        asset_dest.mkdir(parents=True, exist_ok=True)
        shutil.copy(input_apk, asset_dest / ASSET_NAME)

    # 修改 AndroidManifest 的 Application name
    manifest_path = d / "AndroidManifest.xml"
    if not manifest_path.exists():
        die("AndroidManifest.xml not found after apktool decode")
    manifest_text = manifest_path.read_text(encoding="utf-8")

    # 如果已有 android:name，保留为 original_app；否则直接设置
    app_name_match = re.search(r'<application\b[^>]*\bandroid:name="([^"]+)"', manifest_text)
    if app_name_match:
        original_app = app_name_match.group(1)
        log(f"Found original Application: {original_app}")
        manifest_text = manifest_text.replace(f'android:name="{original_app}"', 'android:name="r.k.app"')
        # 需要在 r.k.app 内部代理 original_app —— 先写成字段替换到 Java
        # 简化：由 r.k.app 在自己的静态块读取 meta-data
    else:
        manifest_text = re.sub(r'(<application\b)', r'\1 android:name="r.k.app"', manifest_text, count=1)

    manifest_path.write_text(manifest_text, encoding="utf-8")

    # 打包
    log("apktool b...")
    out_unsigned = work_dir / "unsigned.apk"
    cmd = ["java", "-jar", str(APKTOOL_JAR), "b", "-o", str(out_unsigned), str(d)]
    r = run(cmd)
    if r.returncode != 0:
        die(f"apktool b failed:\n{r.stdout}\n{r.stderr}")

    return out_unsigned

def sign(unsigned_apk, final_apk, work_dir):
    """用 fake.jks 签名"""
    log("Signing APK...")
    # 清理 META-INF 里的旧签名
    tmp = work_dir / "signed_tmp.apk"
    shutil.copy(unsigned_apk, tmp)
    # 用 apksigner
    apksigner = find_sdk_tool("apksigner")
    key = ROOT / "fake.jks"
    if not key.exists():
        die("fake.jks not found")
    cmd = [
        apksigner, "sign",
        "--ks", str(key),
        "--ks-pass", "pass:123456",
        "--key-pass", "pass:123456",
        "--ks-key-alias", "key0",
        "--v1-signing-enabled", "true",
        "--v2-signing-enabled", "true",
        "--out", str(final_apk),
        str(unsigned_apk)
    ]
    r = run(cmd)
    if r.returncode != 0:
        die(f"apksigner failed:\n{r.stdout}\n{r.stderr}")
    log(f"Output: {final_apk}")

def main():
    log(f"Input APK : {INPUT_APK}")
    log(f"Original  : {ORIGINAL_APK or '(use input)'}")
    log(f"Output    : {OUTPUT_APK}")
    log(f"SO        : lib{SO_NAME}.so")
    log(f"Asset     : assets/{ASSET_DIR}/{ASSET_NAME}")
    log(f"Files dir : {FILES_DIR}")

    input_apk = ROOT / INPUT_APK
    if not input_apk.exists():
        die(f"Input APK not found: {input_apk}")

    original_apk = None
    if ORIGINAL_APK:
        original_apk = ROOT / ORIGINAL_APK
        if not original_apk.exists():
            die(f"Original APK not found: {original_apk}")
    else:
        original_apk = input_apk

    # 提取签名
    global SIGNATURE_B64
    if not SIGNATURE_B64:
        SIGNATURE_B64 = extract_signature(original_apk)

    # 读取目标包名
    global TARGET_PKG
    if not TARGET_PKG:
        for tool in ("aapt", "aapt2"):
            aapt = find_sdk_tool(tool)
            if aapt:
                r = run([aapt, "dump", "badging", str(input_apk)])
                if r.returncode == 0:
                    m = re.search(r"package: name='([^']+)'", r.stdout)
                    if m:
                        TARGET_PKG = m.group(1)
                        log(f"Auto-detected package: {TARGET_PKG}")
                        break

    if not TARGET_PKG:
        die("Cannot determine target package. Set TARGET_PKG env.")

    log(f"Target package: {TARGET_PKG}")
    log(f"Signature len : {len(SIGNATURE_B64)} chars")

    with tempfile.TemporaryDirectory(prefix="apksig_", dir=str(ROOT)) as tmp:
        work = Path(tmp)

        # 复制 Java 源到临时目录并替换占位符
        java_src = work / "java_src"
        shutil.copytree(ROOT / "src" / "java" / "r", java_src / "r")
        src_java = java_src / "r" / "k" / "app.java"
        src_text = src_java.read_text(encoding="utf-8")
        src_text = src_text.replace("%%TARGET_PKG%%", TARGET_PKG)
        src_text = src_text.replace("%%SIGNATURE_B64%%", SIGNATURE_B64)
        src_text = src_text.replace("%%LIB_NAME%%", SO_NAME)
        src_text = src_text.replace("%%ASSET_PATH%%", f"assets/{ASSET_DIR}/{ASSET_NAME}")
        src_text = src_text.replace("%%FILES_DIR%%", FILES_DIR)
        src_java.write_text(src_text, encoding="utf-8")
        log("Java template updated")

        # 1. 编译 Java → dex
        dex_file = compile_java_to_dex(work, java_src)
        if not dex_file:
            die("Java compilation failed")

        # 2. 编译 native → so
        so_dir = None
        try:
            so_dir = build_native(work)
        except Exception as e:
            log(f"WARNING: native build skipped: {e}")

        # 3. 注入
        unsigned = inject(input_apk, original_apk, so_dir, dex_file, work)

        # 4. 签名
        final_apk = ROOT / OUTPUT_APK
        sign(unsigned, final_apk, work)

    log("BUILD SUCCESS")
    print(f"\nResult: {ROOT / OUTPUT_APK}")
