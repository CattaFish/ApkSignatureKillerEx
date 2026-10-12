#!/usr/bin/env python3
"""
SignatureKiller 全自动管线 (manifest-free entry via Activity <clinit>)
输入: --apk 用户提供的 APK（必填）
输出: work_out/processed_YYYYMMDD_HHMMSS.apk
"""
import argparse
import datetime
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

WORK = "work_out"
DECODED = os.path.join(WORK, "decoded")
KILLER_SMALI = "work_killer/smali"
KILLER_LIB = "work_killer/lib"
KEYSTORE = "keys/fake.jks"
STORE_PASS = "123456"
KEY_ALIAS = "key0"
ABIS = ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]
THIS_DIR = os.path.dirname(os.path.abspath(__file__))


def run(cmd):
    print("+", " ".join(cmd), flush=True)
    r = subprocess.run(cmd, capture_output=True, text=True)
    try:
        os.makedirs(WORK, exist_ok=True)
        with open(os.path.join(WORK, "pipeline.log"), "a", encoding="utf-8") as lf:
            lf.write("+ " + " ".join(cmd) + "\n")
            lf.write(r.stdout[-4000:])
            lf.write("\n")
            lf.write(r.stderr[-4000:])
            lf.write("\n")
    except Exception:
        pass
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


def find_zipalign():
    h = os.environ.get("ANDROID_HOME", "")
    bt = os.path.join(h, "build-tools")
    if os.path.isdir(bt):
        vers = sorted(d for d in os.listdir(bt) if os.path.isdir(os.path.join(bt, d)))
        if vers:
            p = os.path.join(bt, vers[-1], "zipalign")
            if os.path.isfile(p):
                return p
    return shutil.which("zipalign")


def get_apk_signature_md5(apk_path):
    """读取输入 APK 证书 DER 的 MD5（v1 优先，v2/v3 兜底）。"""
    try:
        with zipfile.ZipFile(apk_path) as z:
            entry = None
            for n in z.namelist():
                if re.match(r"META-INF/.*\.(RSA|DSA|EC)$", n, re.I):
                    entry = n
                    break
            if entry is not None:
                fd, p7 = tempfile.mkstemp(suffix=".pkcs7")
                os.close(fd)
                with open(p7, "wb") as f:
                    f.write(z.read(entry))
                try:
                    r1 = subprocess.run(["openssl", "pkcs7", "-inform", "DER", "-in", p7,
                                         "-print_certs", "-outform", "DER"], capture_output=True)
                    if r1.returncode == 0 and r1.stdout:
                        r2 = subprocess.run(["openssl", "x509", "-inform", "DER", "-outform", "DER"],
                                            input=r1.stdout, capture_output=True)
                        if r2.returncode == 0 and r2.stdout:
                            return hashlib.md5(r2.stdout).hexdigest()
                finally:
                    os.unlink(p7)
        import struct
        with open(apk_path, "rb") as f:
            data = f.read()
        if len(data) < 32:
            return None
        eocd = -1
        tail_start = max(0, len(data) - 65557)
        for i in range(len(data) - 22, tail_start - 1, -1):
            if data[i:i+4] == b"PK\x05\x06":
                eocd = i
                break
        if eocd < 0:
            return None
        cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
        if cd_offset < 32 or cd_offset > len(data):
            return None
        footer_pos = cd_offset - 24
        if footer_pos < 0 or footer_pos + 24 > len(data):
            return None
        if data[footer_pos+8:footer_pos+24] != b"APK Sig Block 42":
            return None
        block_size = struct.unpack_from("<Q", data, footer_pos)[0]
        pairs_size = block_size - 24
        block_start = cd_offset - block_size
        if pairs_size <= 0 or block_start < 0 or block_start + pairs_size > len(data):
            return None
        off = block_start
        end = block_start + pairs_size
        while off + 12 <= end:
            pair_len = struct.unpack_from("<Q", data, off)[0]
            pair_id = struct.unpack_from("<I", data, off + 8)[0]
            off += 12
            if pair_len < 4 or off + pair_len - 4 > end:
                break
            if pair_id in (0x7109871a, 0xf05368c0):
                value = data[off:off + pair_len - 4]
                try:
                    signer_len = struct.unpack_from("<I", value, 0)[0]
                    if signer_len <= 0 or signer_len > len(value) - 4:
                        return None
                    signer = value[4:4 + signer_len]
                    signed_len = struct.unpack_from("<I", signer, 0)[0]
                    if signed_len <= 0 or signed_len > len(signer) - 4:
                        return None
                    signed = signer[4:4 + signed_len]
                    i = 0
                    while i + 4 <= len(signed):
                        if signed[i] == 0x30 and signed[i + 1] == 0x82:
                            cert_len = (signed[i + 2] << 8) | signed[i + 3]
                            total = 4 + cert_len
                            if i + total <= len(signed) and cert_len > 40:
                                return hashlib.md5(signed[i:i + total]).hexdigest()
                        i += 1
                    return None
                except Exception:
                    return None
            off += int(pair_len - 4)
        return None
    except Exception:
        return None


def patch_expected_signature(decoded, md5_hex):
    old_str = "1fb11e8214ae8b8c259aa9cd87387ac0"
    total = 0
    for name in os.listdir(decoded):
        d = os.path.join(decoded, name)
        if not (re.fullmatch(r"smali(_classes\d+)?", name) and os.path.isdir(d)):
            continue
        p = os.path.join(d, "r/s/test/MainActivity.smali")
        if not os.path.exists(p):
            continue
        s = open(p, encoding="utf-8").read()
        cnt = s.count(old_str)
        if cnt > 0:
            open(p, "w", encoding="utf-8").write(s.replace(old_str, md5_hex))
            total += cnt
    return total


def inject_clinit_entry(decoded):
    """在目标启动 Activity 的 <clinit> 第一条指令前插入 KillerApplication.onLoaded()"""
    manifest = open(os.path.join(decoded, "AndroidManifest.xml"), encoding="utf-8").read()
    m = re.search(r'<activity\b[^>]*\bandroid:name="([^"]+)"', manifest)
    if not m:
        print("[warn] 未找到 Activity android:name，跳过 clinit 插桩")
        return 0
    cls = m.group(1)
    rel = cls.replace(".", "/") + ".smali"
    target = None
    for name in os.listdir(decoded):
        if re.fullmatch(r"smali(_classes\d+)?", name):
            p = os.path.join(decoded, name, rel)
            if os.path.exists(p):
                target = p
                break
    if not target:
        print(f"[warn] 未找到 {rel}，跳过 clinit 插桩")
        return 0
    s = open(target, encoding="utf-8").read()
    marker = "invoke-static {}, Lr/s/sign/KillerApplication;->onLoaded()V"
    if marker in s:
        return 0
    clinit_pat = re.compile(r'(\.method static constructor <clinit>\(\)V\n(?:\s*\.registers \d+\n)?)')
    mm = clinit_pat.search(s)
    if mm:
        s = s[:mm.end()] + "\n    " + marker + "\n" + s[mm.end():]
    else:
        clinit = (
            "\n# injected by SignatureKiller\n"
            ".method static constructor <clinit>()V\n"
            "    .registers 0\n\n"
            "    " + marker + "\n\n"
            "    return-void\n"
            ".end method\n"
        )
        idx = s.find("\n.method ")
        if idx < 0:
            idx = len(s)
        s = s[:idx] + clinit + s[idx:]
    open(target, "w", encoding="utf-8").write(s)
    print(f"[ok] clinit 已注入: {target}")
    return 1


def main():
    parser = argparse.ArgumentParser(description="Signature Killer pipeline")
    parser.add_argument("--apk", required=True, help="用户提供的输入 APK 路径")
    parser.add_argument("--apktool", default=os.environ.get("APKTOOL_JAR", "apktool.jar"))
    parser.add_argument("--dedup", action="store_true", help="删除 assets/Zcraft/input.apk 副本（数据复用优化）")
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

        import random, string
    r_dir = "".join(random.choices(string.ascii_lowercase + string.digits, k=7))
    r_file = "".join(random.choices(string.ascii_lowercase + string.digits, k=9)) + ".apk"
    asset_dir = os.path.join(DECODED, "assets", r_dir)
    os.makedirs(asset_dir, exist_ok=True)
    shutil.copy(apk_path, os.path.join(asset_dir, r_file))
    print(f"[ok] assets/{r_dir}/{r_file} <- 输入 APK 自身 (全随机混淆名称)"))

    injected = 0
    for abi in ABIS:
        src = os.path.join(KILLER_LIB, abi, "libZcraft.so")
        if os.path.exists(src):
            dst_dir = os.path.join(DECODED, "lib", abi)
            os.makedirs(dst_dir, exist_ok=True)
            shutil.copy(src, os.path.join(dst_dir, "libZcraft.so"))
            injected += 1
            print(f"[ok] lib/{abi}/libZcraft.so")
    if injected == 0:
        print("FAIL: 没有注入任何 .so（先运行 prepare 生成 work_killer）")
        sys.exit(1)

    if not os.path.isdir(KILLER_SMALI):
        print(f"FAIL: {KILLER_SMALI} 不存在（先运行 prepare 生成 work_killer）")
        sys.exit(1)

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

    inject_clinit_entry(DECODED)

    expected = get_apk_signature_md5(apk_path)
    if expected:
        n = patch_expected_signature(DECODED, expected)
        print(f"[ok] 签名期望值已更新: {expected} ({n} 处)")
    else:
        print("[warn] 无法解析输入 APK 的 v1 签名，跳过期望值替换（界面红蓝判断可能失真）")

    run(["java", "-jar", args.apktool, "b", DECODED, "-o", os.path.join(WORK, "unsigned.apk")])
    print("[ok] apktool b")

    if not find_zipalign():
        print("FAIL: 未找到 zipalign，请设置 ANDROID_HOME")
        sys.exit(1)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    processed = os.path.join(WORK, f"processed_{ts}.apk")

    sign_cmd = ["python3", os.path.join(THIS_DIR, "finalize_sign.py"),
                "--input", os.path.join(WORK, "unsigned.apk"),
                "--output", processed,
                "--orig", apk_path]
    if args.dedup:
        sign_cmd.append("--multiplex")
    run(sign_cmd)
    print("[ok] 签名完成")
    print()
    print("输出: " + os.path.abspath(processed))
    print("入口: Activity <clinit>（manifest 未注入 Provider）")


if __name__ == "__main__":
    main()
