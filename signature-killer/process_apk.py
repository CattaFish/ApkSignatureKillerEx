#!/usr/bin/env python3
"""
SignatureKiller 全自动管线
输入: --apk 用户提供的 APK（必填）
输出: work_out/processed_YYYYMMDD_HHMMSS.apk
"""
import argparse
import datetime
import os
import re
import shutil
import subprocess
import sys

WORK = "work_out"
DECODED = os.path.join(WORK, "decoded")
KILLER_SMALI = "work_killer/smali"
KILLER_LIB = "work_killer/lib"
KEYSTORE = "keys/fake.jks"
STORE_PASS = "123456"
KEY_ALIAS = "key0"
ABIS = ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]


def run(cmd):
    print("+", " ".join(cmd), flush=True)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout[-3000:])
        print(r.stderr[-3000:])
        print(f"FAIL: {cmd[0]} 失败，保留目录 {DECODED} 供排查")
        sys.exit(1)
    return r


def ensure_keystore():
    if os.path.exists(KEYSTORE):
        return os.path.abspath(KEYSTORE)
    os.makedirs(os.path.dirname(KEYSTORE), exist_ok=True)
    run(["keytool", "-genkeypair", "-v", "-keystore", KEYSTORE, "-alias", KEY_ALIAS,
         "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
         "-storepass", STORE_PASS, "-keypass", STORE_PASS,
         "-dname", "CN=Android, O=Android, C=US"])
    return os.path.abspath(KEYSTORE)


def find_build_tools():
    h = os.environ.get("ANDROID_HOME", "")
    base = os.path.join(h, "build-tools")
    if not os.path.isdir(base):
        return None, None
    vers = sorted(d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d)))
    if not vers:
        return None, None
    v = vers[-1]
    return os.path.join(base, v, "zipalign"), os.path.join(base, v, "apksigner")


def list_smali_dirs(decoded):
    out = []
    for name in sorted(os.listdir(decoded)):
        d = os.path.join(decoded, name)
        if re.fullmatch(r"smali(_classes\d+)?", name) and os.path.isdir(d):
            out.append(d)
    return out


def find_application_smali(smali_dirs, app_cls):
    rel = app_cls.replace(".", "/") + ".smali"
    for d in smali_dirs:
        p = os.path.join(d, rel)
        if os.path.exists(p):
            return p
    return None


def inject_smali_init(smali_file):
    with open(smali_file, encoding="utf-8") as f:
        content = f.read()
    marker = ".method protected onCreate(Landroid/os/Bundle;)V"
    if marker not in content:
        marker = ".method public onCreate(Landroid/os/Bundle;)V"
    if marker not in content:
        print(f"[warn] 未找到 onCreate，跳过注入 {smali_file}")
        return
    start = content.index(marker)
    body_start = content.index("    ", start)
    next_method = content.find(".method", start + 1)
    end = next_method if next_method != -1 else len(content)
    injection = "    invoke-static {p0}, Lr/s/sign/KillerApplication;->init(Landroid/content/Context;)V\n"
    content = content[:body_start] + injection + content[body_start:end] + content[end:]
    with open(smali_file, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[ok] injected init into {smali_file}")


def main():
    parser = argparse.ArgumentParser(description="Signature Killer pipeline")
    parser.add_argument("--apk", required=True, help="用户提供的输入 APK 路径")
    parser.add_argument("--apktool", default=os.environ.get("APKTOOL_JAR", "apktool.jar"))
    args = parser.parse_args()

    apk_path = os.path.abspath(args.apk)
    if not os.path.exists(apk_path):
        print(f"FAIL: {apk_path} 不存在")
        sys.exit(1)
    with open(apk_path, "rb") as f:
        if f.read(4) != b"PK\x03\x04":
            print(f"FAIL: {apk_path} 不是有效的 APK/ZIP（魔数错误）")
            sys.exit(1)
    print(f"[info] 输入 APK: {apk_path} ({os.path.getsize(apk_path)} bytes)")

    if not os.path.isfile(args.apktool):
        print(f"FAIL: 找不到 apktool: {args.apktool}，请安装并设置 APKTOOL_JAR")
        sys.exit(1)

    ensure_keystore()

    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK)

    run(["java", "-jar", args.apktool, "d", "-f", "-o", DECODED, apk_path])
    print("[ok] apktool d")

    manifest_path = os.path.join(DECODED, "AndroidManifest.xml")
    manifest = open(manifest_path, encoding="utf-8").read()
    m = re.search(r'package="([^"]+)"', manifest)
    if not m:
        print("FAIL: 无法解析 package")
        sys.exit(1)
    package = m.group(1)
    print(f"[info] package = {package}")

    asset_dir = os.path.join(DECODED, "assets", "SignedByRS")
    os.makedirs(asset_dir, exist_ok=True)
    shutil.copy(apk_path, os.path.join(asset_dir, "input.apk"))
    print("[ok] assets/SignedByRS/input.apk <- 输入 APK 自身")

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
        print("FAIL: 没有注入任何 .so（先运行 prepare 生成 work_killer）")
        sys.exit(1)

    if not os.path.isdir(KILLER_SMALI):
        print(f"FAIL: {KILLER_SMALI} 不存在（先运行 prepare 生成 work_killer）")
        sys.exit(1)

    # killer smali 固定进主 dex（Application 必须在 classes.dex，否则系统实例化前找不到类）
    smali_target = os.path.join(DECODED, "smali")
    os.makedirs(smali_target, exist_ok=True)
    smali_injected = 0
    for item in os.listdir(KILLER_SMALI):
        src = os.path.join(KILLER_SMALI, item)
        dst = os.path.join(smali_target, item)
        if os.path.isdir(src):
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            shutil.copy2(src, dst)
        smali_injected += 1
    print(f"[ok] killer smali 合并到主 dex {smali_target}（{smali_injected} 项）")

    app_match = re.search(r'<application[^>]*android:name="([^"]+)"', manifest)
    smali_dirs = list_smali_dirs(DECODED)
    if app_match:
        app_cls = app_match.group(1)
        if app_cls.startswith("."):
            app_cls = package + app_cls
        elif app_cls.startswith("/"):
            app_cls = app_cls[1:]
        target = find_application_smali(smali_dirs, app_cls)
        if target:
            inject_smali_init(target)
            print(f"[ok] 已注入 init 到原 Application: {app_cls} ({os.path.relpath(target, DECODED)})")
        else:
            new_manifest = re.sub(
                r'(<application[^>]*android:name=")[^"]*(")',
                r'\1r.s.sign.KillerApplication\2', manifest, count=1)
            open(manifest_path, "w", encoding="utf-8").write(new_manifest)
            print(f"[warn] 所有 dex 中均找不到 {app_cls}，android:name 替换为 KillerApplication")
    else:
        new_manifest = re.sub(r'<application\b([^>]*)>',
                              r'<application\1 android:name="r.s.sign.KillerApplication">',
                              manifest, count=1)
        open(manifest_path, "w", encoding="utf-8").write(new_manifest)
        print("[ok] 无 Application，android:name -> r.s.sign.KillerApplication")

    run(["java", "-jar", args.apktool, "b", DECODED, "-o", os.path.join(WORK, "unsigned.apk")])
    print("[ok] apktool b")

    zipalign, apksigner = find_build_tools()
    if not zipalign or not apksigner:
        print("FAIL: 未找到 $ANDROID_HOME/build-tools，请设置 ANDROID_HOME")
        sys.exit(1)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    aligned = os.path.join(WORK, "aligned.apk")
    processed = os.path.join(WORK, f"processed_{ts}.apk")
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
