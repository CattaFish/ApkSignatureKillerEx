#!/usr/bin/env python3
"""
ApkSignatureKillerEx 全自动管线
输入: 根目录 origin.apk（clean-input：origin.jks 签名，自带 ch4~ch9 检测，无 killer）
输出: work_out/processed.apk（注入 killer + 内嵌 origin.apk + fake.jks 重签）
"""
import os
import re
import shutil
import subprocess
import sys

WORK = "work_out"
INPUT = "origin.apk"
DECODED = os.path.join(WORK, "decoded")
KILLER_SMALI = "work_killer/smali"
KILLER_LIB = "work_killer/lib"
KEYSTORE = "fake.jks"
STORE_PASS = "123456"
KEY_ALIAS = "key0"
ABIS = ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]


def run(cmd):
    print("+", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout[-3000:])
        print(r.stderr[-3000:])
        sys.exit(1)
    return r


def main():
    # 0. 检查输入
    if not os.path.exists(INPUT):
        print(f"FAIL: {INPUT} 不存在，请把 clean-input 构建产物放到仓库根目录")
        sys.exit(1)

    # 1. 清理 + 解包
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK)
    run(["java", "-jar", os.environ["APKTOOL_JAR"], "d", "-f", "-o", DECODED, INPUT])
    print("[ok] apktool d")

    # 2. 读取包名
    manifest_path = os.path.join(DECODED, "AndroidManifest.xml")
    manifest = open(manifest_path, encoding="utf-8").read()
    m = re.search(r'package="([^"]+)"', manifest)
    if not m:
        print("FAIL: 无法解析 package")
        sys.exit(1)
    package = m.group(1)
    print(f"[info] package = {package}")

    # 3. 注入 assets/SignedByRS/origin.apk（输入 APK 自身）
    asset_dir = os.path.join(DECODED, "assets", "SignedByRS")
    os.makedirs(asset_dir, exist_ok=True)
    shutil.copy(INPUT, os.path.join(asset_dir, "origin.apk"))
    print("[ok] assets/SignedByRS/origin.apk <- 输入 APK 自身")

    # 4. 注入 native 库
    injected = 0
    for abi in ABIS:
        src = os.path.join(KILLER_LIB, abi, "libSignedByRS.so")
        if os.path.exists(src):
            dst_dir = os.path.join(DECODED, "lib", abi)
            os.makedirs(dst_dir, exist_ok=True)
            shutil.copy(src, os.path.join(dst_dir, "libSignedByRS.so"))
            injected += 1
            print(f"[ok] lib/{abi}/libSignedByRS.so")
        else:
            print(f"[warn] 缺少 ABI {abi}: {src}")
    if injected == 0:
        print("FAIL: 没有注入任何 .so")
        sys.exit(1)

    # 5. 注入 smali（killer 代码 + hiddenapibypass）
    if not os.path.isdir(KILLER_SMALI):
        print(f"FAIL: {KILLER_SMALI} 不存在（workflow 的 Prepare 步骤没跑？）")
        sys.exit(1)
    shutil.copytree(KILLER_SMALI, os.path.join(DECODED, "smali"), dirs_exist_ok=True)
    print("[ok] smali 注入（r/s/sign + org/lsposed）")

    # 6. 修改 AndroidManifest.xml 的 application 入口
    new_manifest = re.sub(
        r'<application\b([^>]*?)\bandroid:name="[^"]*"',
        r'<application\1 android:name="r.s.sign.KillerApplication"',
        manifest, count=1)
    if new_manifest == manifest:
        new_manifest = re.sub(
            r'<application\b([^>]*)>',
            r'<application\1 android:name="r.s.sign.KillerApplication">',
            manifest, count=1)
    open(manifest_path, "w", encoding="utf-8").write(new_manifest)
    print("[ok] application android:name -> r.s.sign.KillerApplication")

    # 7. 重打包
    run(["java", "-jar", os.environ["APKTOOL_JAR"], "b", DECODED,
         "-o", os.path.join(WORK, "unsigned.apk")])
    print("[ok] apktool b")

    # 8. 对齐 + 签名
    bt = os.path.join(os.environ.get("ANDROID_HOME", ""), "build-tools", "34.0.0")
    zipalign = os.path.join(bt, "zipalign")
    apksigner = os.path.join(bt, "apksigner")
    aligned = os.path.join(WORK, "aligned.apk")
    processed = os.path.join(WORK, "processed.apk")
    run([zipalign, "-f", "4", os.path.join(WORK, "unsigned.apk"), aligned])
    run([apksigner, "sign",
         "--ks", KEYSTORE,
         "--ks-key-alias", KEY_ALIAS,
         "--ks-pass", f"pass:{STORE_PASS}",
         "--key-pass", f"pass:{STORE_PASS}",
         "--out", processed, aligned])
    print("[ok] 签名完成")
    print()
    print("输出: " + os.path.abspath(processed))
    print("预期: From API/APK 蓝, From SVC 红, ch4 蓝, ch5/ch7/ch9 HOOKED/FILTERED")


if __name__ == "__main__":
    main()
