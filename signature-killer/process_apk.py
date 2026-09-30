#!/usr/bin/env python3
"""
SignatureKiller 全自动管线
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


def get_apk_signature_md5(apk_path):
    """读取输入 APK 证书 DER 的 MD5（v1 优先，v2/v3 兜底），与 Java X509Certificate.getEncoded() 一致。"""
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
        # v2/v3 fallback：APK Signing Block（little-endian）
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
        if block_size < 24 or pairs_size <= 0 or block_start < 0 or block_start + pairs_size > len(data):
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
                    # 搜索 X.509 标记 30 82 <len16>，不逐层解析
                    i = 0
                    while i + 4 <= len(signed):
                        if signed[i] == 0x30 and signed[i + 1] == 0x82:
                            cert_len = (signed[i + 2] << 8) | signed[i + 3]
                            total = 4 + cert_len
                            if i + total <= len(signed) and cert_len > 40:
                                cert_der = signed[i:i + total]
                                return hashlib.md5(cert_der).hexdigest()
                        i += 1
                    return None
                except Exception:
                    return None
            off += int(pair_len - 4)
        return None
    except Exception as e:
        print(f"[warn] 签名解析异常: {e}")
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


def inject_original_meta_inf(apk_path, unsigned_apk):
    """zip 级注入：把原包 META-INF 证书放回未签名 APK（apktool build 之后）。
    native 从外层 APK 解析 META-INF/*.RSA，重打包后保持原证书即可通过校验。"""
    try:
        import zipfile
        with zipfile.ZipFile(apk_path) as z:
            cert_entries = [n for n in z.namelist()
                            if re.match(r"META-INF/.*\.(RSA|DSA|EC)$", n, re.I)]
            if not cert_entries:
                print("[warn] 原包无 META-INF V1 证书，跳过注入")
                return 0
            cert_name = os.path.basename(cert_entries[0])
            cert_data = z.read(cert_entries[0])

        tmp_apk = unsigned_apk + ".tmp"
        with zipfile.ZipFile(unsigned_apk, "r") as zin, zipfile.ZipFile(tmp_apk, "w") as zout:
            for item in zin.infolist():
                name = item.filename
                if re.match(r"META-INF/.*\.(RSA|DSA|EC|SF|MF)$", name, re.I):
                    continue
                zout.writestr(item, zin.read(name))
            zi = zipfile.ZipInfo("META-INF/" + cert_name)
            zi.external_attr = 0o644 << 16
            zout.writestr(zi, cert_data)
        import os as _os
        _os.replace(tmp_apk, unsigned_apk)
        print(f"[ok] META-INF/{cert_name} 已注入未签名 APK")
        return 1
    except Exception as e:
        print(f"[warn] META-INF 注入失败: {e}")
        return 0



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

    # 动态签名期望值：替换 MainActivity.smali 里硬编码的 expected MD5
    expected = get_apk_signature_md5(apk_path)
    if expected:
        n = patch_expected_signature(DECODED, expected)
        print(f"[ok] 签名期望值已更新: {expected} ({n} 处)")
    else:
        print("[warn] 无法解析输入 APK 的 v1 签名，跳过期望值替换（界面红蓝判断可能失真）")

    # 注入 KillerProvider：进程启动早期执行 KillerApplication.init，
    # 不依赖原 Application 是否存在 onCreate
    manifest = open(manifest_path, encoding="utf-8").read()
    provider = (
        '<provider\n'
        '            android:name="r.s.sign.KillerProvider"\n'
        f'            android:authorities="{package}.killerprovider"\n'
        '            android:enabled="true"\n'
        '            android:exported="false" />'
    )
    new_manifest = re.sub(
        r'(<application\b[^>]*>)',
        lambda mo: mo.group(1) + '\n        ' + provider,
        manifest, count=1, flags=re.S)
    if new_manifest == manifest:
        print("[warn] 未找到 <application> 标签，KillerProvider 注入失败")
    else:
        try:
            import xml.etree.ElementTree as ET
            ET.fromstring(new_manifest)
        except Exception as e:
            print(f"FAIL: 注入后的 AndroidManifest.xml 非法: {e}")
            sys.exit(1)
        open(manifest_path, "w", encoding="utf-8").write(new_manifest)
        print(f"[ok] KillerProvider 已注入 (authorities={package}.killerprovider)")

    run(["java", "-jar", args.apktool, "b", DECODED, "-o", os.path.join(WORK, "unsigned.apk")])

    # 原证书注入：native 从外层 APK META-INF 解析原签名（apktool build 后 zip 级注入）
    inject_original_meta_inf(apk_path, os.path.join(WORK, "unsigned.apk"))
    with zipfile.ZipFile(os.path.join(WORK, "unsigned.apk")) as zchk:
        _has_cert = any(re.match(r"META-INF/.*\.(RSA|DSA|EC)$", n, re.I) for n in zchk.namelist())
    print(f"[check] unsigned.apk META-INF cert present: {_has_cert}")
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
         "--v1-signing-enabled", "false",
         "--v2-signing-enabled", "true",
         "--out", processed, aligned])
    print("[ok] 签名完成")
    print()
    print("输出: " + os.path.abspath(processed))
    print("预期: From API/APK 蓝, From SVC 红, ch4 蓝, ch5/ch7/ch9 HOOKED/FILTERED")


if __name__ == "__main__":
    main()
