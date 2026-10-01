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
import binascii
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
    try:
        log_path = os.path.join(WORK, "pipeline.log")
        if os.environ.get("WORK") or True:
            os.makedirs(WORK, exist_ok=True)
            with open(log_path, "a", encoding="utf-8") as lf:
                lf.write("+ " + " ".join(cmd) + "\n")
                lf.write(r.stdout[-4000:])
                lf.write("\n")
                lf.write(r.stderr[-4000:])
                lf.write("\n")
    except Exception as e:
        print(f"[warn] 日志写入失败: {e}")
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



def _locate_eocd(data):
    tail_start = max(0, len(data) - 65557)
    for i in range(len(data) - 22, tail_start - 1, -1):
        if data[i:i+4] == b"PK\x05\x06":
            return i
    return -1


def _make_zip_entry(fname, data, offset, dostime, dosdate):
    crc = binascii.crc32(data) & 0xffffffff
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034b50, 20, 0, 0, dostime, dosdate,
        crc, len(data), len(data), len(fname), 0) + fname + data
    external = (0o644 & 0xFFFF) << 16
    cd = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014b50,
        (3 << 8) | 20,   # version made by
        20,              # version needed
        0,               # flag
        0,               # compression = STORED
        dostime, dosdate,
        crc, len(data), len(data),
        len(fname), 0, 0,
        0,               # disk
        0,               # internal attr
        external,
        offset) + fname
    return local, cd


def _find_eocd(data):
    for i in range(len(data) - 22, max(0, len(data) - 65557) - 1, -1):
        if data[i:i+4] == b"PK\x05\x06":
            return i
    return -1


def append_cert_after_sign(apk_path, signed_apk):
    """纯追加：把原证书作为新 zip 条目附在已签名 APK 末尾。
    - 签名块之前的字节（V2/V3 保护区）完全不动；
    - 中央目录追加一条目、EOCD 更新计数，但 cd_offset 保持不变，
      因此 V2/V3 签名仍然有效 —— 与 MT管理器(关自动签名)等效，不重新签名。"""
    import struct, binascii
    from datetime import datetime
    try:
        with zipfile.ZipFile(apk_path) as z:
            cert_entries = [n for n in z.namelist()
                            if re.match(r"META-INF/.*\.(RSA|DSA|EC)$", n, re.I)]
            if not cert_entries:
                print("[warn] 无原证书可追加")
                return 0
            cert_name = os.path.basename(cert_entries[0])
            cert_data = z.read(cert_entries[0])

        with open(signed_apk, "rb") as f:
            data = f.read()

        eocd_pos = _find_eocd(data)
        if eocd_pos < 0:
            print("[warn] EOCD 未找到")
            return 0
        cd_offset = struct.unpack_from("<I", data, eocd_pos + 16)[0]
        cd_size = struct.unpack_from("<I", data, eocd_pos + 12)[0]
        total = struct.unpack_from("<H", data, eocd_pos + 10)[0]

        if cd_offset + cd_size > eocd_pos:
            print("[warn] 中央目录越界，放弃")
            return 0

        fname = "META-INF/" + cert_name
        crc = binascii.crc32(cert_data) & 0xffffffff
        now = datetime.now()
        dostime = (now.hour << 11) | (now.minute << 5) | (now.second // 2)
        dosdate = ((now.year - 1980) << 9) | (now.month << 5) | now.day

        # 新本地条目（STORED，不压缩）
        local = struct.pack(
            "<IHHHHHIIIHH",
            0x04034b50, 20, 0, 0, dostime, dosdate,
            crc, len(cert_data), len(cert_data), len(fname), 0,
        ) + fname + cert_data

        # 新中央目录条目（offset 指向新本地位：紧接着原中央目录之后）
        local_offset = cd_offset + cd_size + len(local)  # 先占位，实际下面重算
        # 中央目录条目要放在新本地之后，因此条目里的 offset = 中央目录起始 + 本地位于其前
        # 布局：原数据[0..cd_offset) 原CD 新CD条目 新本地条目 新EOCD
        new_cd_entry_start = cd_offset + cd_size
        local_at = new_cd_entry_start + 44 + len(fname)  # 44 = CD entry 固定头
        external = (0o644 & 0xFFFF) << 16
        cd_entry = struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014b50,
            (3 << 8) | 20, 20, 0, 0, dostime, dosdate,
            crc, len(cert_data), len(cert_data),
            len(fname), 0, 0, 0, 0, external, local_at,
        ) + fname

        # 重排：原数据前段 + 原CD + 新CD条目 + 新本地条目 + 新EOCD
        prefix = data[:cd_offset + cd_size]
        new_cd = data[cd_offset:cd_offset + cd_size] + cd_entry
        new_total = total + 1
        new_cd_size = len(new_cd)
        # EOCD 的 cd_offset 保持原值（V2 定位签名块用），只更新条目数和目录大小
        new_eocd = struct.pack(
            "<IHHHHIIH",
            0x06054b50, 0, 0,
            new_total & 0xFFFF, new_total & 0xFFFF,
            new_cd_size, cd_offset, 0,
        )

        # local_at 必须在写入前确定：把本地条目放在新CD之后、EOCD之前
        # 因此 local_at = len(prefix)+len(cd_entry)
        local_at = len(prefix) + len(cd_entry)
        cd_entry = struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014b50,
            (3 << 8) | 20, 20, 0, 0, dostime, dosdate,
            crc, len(cert_data), len(cert_data),
            len(fname), 0, 0, 0, 0, external, local_at,
        ) + fname

        out = prefix + cd_entry + local + new_eocd

        with open(signed_apk, "wb") as f:
            f.write(out)

        with zipfile.ZipFile(signed_apk) as z:
            ok = any(re.match(r"META-INF/.*\.(RSA|DSA|EC)$", n, re.I) for n in z.namelist())
        print(f"[check] 最终 APK META-INF cert present: {ok} ({cert_name})")
        return 1 if ok else 0
    except Exception as e:
        print(f"[warn] 纯追加失败: {e}")
        return 0



def ensure_v2_key():
    out_dir = "work_killer"
    os.makedirs(out_dir, exist_ok=True)
    key = os.path.join(out_dir, "v2_key.pem")
    cert = os.path.join(out_dir, "v2_cert.der")
    pub = os.path.join(out_dir, "v2_pub.der")
    if not (os.path.exists(key) and os.path.exists(cert) and os.path.exists(pub)):
        cert_pem = os.path.join(out_dir, "v2_cert.pem")
        run(["openssl", "genrsa", "-out", key, "2048"])
        run(["openssl", "req", "-new", "-x509", "-key", key, "-out", cert_pem,
             "-days", "10950", "-subj", "/CN=K"])
        run(["openssl", "x509", "-in", cert_pem, "-outform", "DER", "-out", cert])
        run(["openssl", "x509", "-in", cert_pem, "-pubkey", "-noout"],
             # 管道写法用 shell 处理：直接调用 openssl 生成 pub DER
             )
        # 分开执行：x509 -pubkey 输出 PEM，再转 DER
        pub_pem = os.path.join(out_dir, "v2_pub.pem")
        r = subprocess.run(["openssl", "x509", "-in", cert_pem, "-pubkey", "-noout"],
                           capture_output=True, text=True)
        open(pub_pem, "w").write(r.stdout)
        run(["openssl", "pkey", "-pubin", "-in", pub_pem, "-outform", "DER", "-out", pub])
    return key, cert, pub


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

        # 两阶段解码：
    # 1) -s（不反编译 dex）: 得到可编辑的文本 AndroidManifest.xml（资源解码失败不影响）
    # 2) -s -r（+原始资源）: 得到可供 apktool b 直接复制的 raw res/arsc
    DECODED_TEXT = os.path.join(WORK, "decoded_text")
    run(["java", "-jar", args.apktool, "d", "-f", "-s", "-o", DECODED_TEXT, apk_path])
    run(["java", "-jar", args.apktool, "d", "-f", "-s", "-r", "-o", DECODED, apk_path])
    # 用文本 manifest 覆盖 raw 目录的二进制 manifest（Provider 注入在文本上做）
    shutil.copy2(os.path.join(DECODED_TEXT, "AndroidManifest.xml"),
                 os.path.join(DECODED, "AndroidManifest.xml"))
    shutil.rmtree(DECODED_TEXT, ignore_errors=True)
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

    # 追加 killer dex（d8 产物，不反编译原 dex）：作为新 classesN.dex
    import zipfile as _zi
    _killer_dex = os.path.join(KILLER_SMALI, "..", "classes.dex")
    if not os.path.isfile(_killer_dex):
        _killer_dex = os.path.join(os.path.dirname(KILLER_SMALI), "classes.dex")
    if os.path.isfile(_killer_dex):
        _unsigned = os.path.join(WORK, "unsigned.apk")
        with _zi.ZipFile(_unsigned, "a") as _zout:
            _names = set(_zout.namelist())
            _n = 2
            while f"classes{_n}.dex" in _names:
                _n += 1
            _entry = f"classes{_n}.dex"
            _zout.write(_killer_dex, _entry)
            print(f"[ok] killer dex -> {_entry}")
    else:
        print("[warn] 未找到 killer classes.dex，跳过 dex 注入")

    # 原证书注入：native 从外层 APK META-INF 解析原签名（apktool build 后 zip 级注入）
    inject_original_meta_inf(apk_path, os.path.join(WORK, "unsigned.apk"))
    with zipfile.ZipFile(os.path.join(WORK, "unsigned.apk")) as zchk:
        _has_cert = any(re.match(r"META-INF/.*\.(RSA|DSA|EC)$", n, re.I) for n in zchk.namelist())
    print(f"[check] unsigned.apk META-INF cert present: {_has_cert}")
    print("[ok] apktool b")

    # 注入 V1 三件套（无签名时 zip 重写无妨）：原证书 + 伪 MANIFEST/SF
    import zipfile as _zi
    with _zi.ZipFile(apk_path) as z:
        _certs = [n for n in z.namelist()
                  if re.match(r"META-INF/.*\\.(RSA|DSA|EC)$", n, re.I)]
        _cert_data = z.read(_certs[0]) if _certs else b""
    _tmp = os.path.join(WORK, "unsigned_v1.apk")
    with _zi.ZipFile(os.path.join(WORK, "unsigned.apk"), "r") as zin, \
         _zi.ZipFile(_tmp, "w") as zout:
        for item in zin.infolist():
            zout.writestr(item, zin.read(item.filename))
        zout.writestr("META-INF/MANIFEST.MF",
                      "Manifest-Version: 1.0\r\nCreated-By: custom\r\n\r\n")
        zout.writestr("META-INF/CERT.SF",
                      "Signature-Version: 1.0\r\nCreated-By: custom\r\n\r\n")
        if _cert_data:
            zout.writestr("META-INF/CERT.RSA", _cert_data)
    os.replace(_tmp, os.path.join(WORK, "unsigned.apk"))
    print("[ok] V1 三件套注入（原证书 + 伪 MF/SF）")

    zipalign, _apksigner = find_build_tools()
    if not zipalign:
        print("FAIL: 未找到 $ANDROID_HOME/build-tools，请设置 ANDROID_HOME")
        sys.exit(1)

    zipalign, _apksigner = find_build_tools()
    if not zipalign:
        print("FAIL: 未找到 $ANDROID_HOME/build-tools，请设置 ANDROID_HOME")
        sys.exit(1)

    # V1 壳三件套：原证书 + 空 MF/SF（V1 校验必然失败；V2 由自研签名器生成）
    import zipfile as _zi
    with _zi.ZipFile(apk_path) as _z:
        _certs = [n for n in _z.namelist()
                  if re.match(r"META-INF/.*\.(RSA|DSA|EC)$", n, re.I)]
        _cert_data = _z.read(_certs[0]) if _certs else b""
    _tmp = os.path.join(WORK, "unsigned_v1.apk")
    with _zi.ZipFile(os.path.join(WORK, "unsigned.apk"), "r") as _zin, \
         _zi.ZipFile(_tmp, "w") as _zout:
        for _item in _zin.infolist():
            _zout.writestr(_item, _zin.read(_item.filename))
        _zout.writestr("META-INF/MANIFEST.MF",
                       "Manifest-Version: 1.0\r\nCreated-By: custom\r\n\r\n")
        _zout.writestr("META-INF/CERT.SF",
                       "Signature-Version: 1.0\r\nCreated-By: custom\r\n\r\n")
        if _cert_data:
            _zout.writestr("META-INF/CERT.RSA", _cert_data)
    os.replace(_tmp, os.path.join(WORK, "unsigned.apk"))
    print("[ok] V1 壳三件套注入（原证书 + 空 MF/SF）")

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    aligned = os.path.join(WORK, "aligned.apk")
    processed = os.path.join(WORK, f"processed_{ts}.apk")
    run([zipalign, "-f", "4", os.path.join(WORK, "unsigned.apk"), aligned])
    run(["python3", os.path.join(os.path.dirname(os.path.abspath(__file__)), "finalize_sign.py"),
         "--input", os.path.join(WORK, "unsigned.apk"),
         "--output", processed,
         "--orig", apk_path])
    print("[ok] 签名完成")

    print("预期: From API/APK 蓝, From SVC 红, ch4 蓝, ch5/ch7/ch9 HOOKED/FILTERED")


if __name__ == "__main__":
    main()
