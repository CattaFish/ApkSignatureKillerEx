package r.s.test;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ApplicationInfo;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import java.io.File;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

public class MainActivity extends Activity {

    static {
        System.loadLibrary("test");
    }

    private static void append(SpannableStringBuilder sb, String header, String value, int color) {
        int start = sb.length();
        sb.append(header).append(value).append("\n");
        int end = sb.length();
        sb.setSpan(new ForegroundColorSpan(color), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
    }

    private static native int openAt(String path);

    private static final String BUILD_TAG = "v13-20260930";

    private String repPath;
    private byte[] apkSignatureCache;
    private boolean apkSignatureCacheSet;
    private static String v2LastError;


    @SuppressLint("SetTextI18n")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        TextView msg = findViewById(R.id.msg);

        // The following demonstrates three ways to get the MD5 of a signature

        String signatureExpected = resolveExpectedSignature();
        String signatureFromAPI = md5(signatureFromAPI());
        String signatureFromAPK = md5(signatureFromAPK());
        String signatureFromSVC = md5(signatureFromSVC());

        // When over-signing is turned on, the API and APK methods will get the false signature MD5

        // And the SVC method always gets the real signature MD5

        SpannableStringBuilder sb = new SpannableStringBuilder();
        append(sb, "Expected[auto]: ", signatureExpected, Color.BLACK);
        append(sb, "Build: ", BUILD_TAG, Color.BLACK);
        append(sb, "From API: ", signatureFromAPI, signatureExpected.equals(signatureFromAPI) ? Color.BLUE : Color.RED);
        append(sb, "From APK: ", signatureFromAPK, signatureExpected.equals(signatureFromAPK) ? Color.BLUE : Color.RED);
        append(sb, "From SVC: ", signatureFromSVC, signatureExpected.equals(signatureFromSVC) ? Color.BLUE : Color.RED);

        // Of course, SVC is not absolutely safe, but relatively more reliable,
        // the actual use of the means need to be combined with more
        append(sb, "Package Name: ", getAPKPackageName(), Color.BLACK);
        // Print SignatureData as hex string
        // append(sb, "Signature Data: ", Arrays.toString(getAPKSignatureData()), Color.BLACK);
        // Print the signature data as base64 string
        append(sb, "Signature Data: ", safeBase64(getAPKSignatureData()), Color.BLACK);
        // Print to log for easy copy
        System.out.println("Signature Data: " + safeBase64(getAPKSignatureData()));
        byte[] signatureData = getAPKSignatureData();
        if (signatureData != null) {
            String base64Signature = safeBase64(signatureData);
            Log.i("SignatureData", "Signature Data: " + safeBase64(signatureData));
        } else {
            Log.e("SignatureData", "Signature data is null");
        }

        runDetectors(sb, signatureExpected);

        // ---- Stage 1.5 probes (for stage-1 killer validation) ----
        byte[] sigSigningInfo = signatureFromSigningInfo();
        String strSigningInfo = sigSigningInfo == null
                ? (Build.VERSION.SDK_INT < Build.VERSION_CODES.P ? "SKIP(<28)" : "N/A")
                : md5(sigSigningInfo);
        append(sb, "From SigningInfo: ", strSigningInfo,
                sigSigningInfo != null && signatureExpected.equals(strSigningInfo) ? Color.BLUE
                        : (sigSigningInfo == null ? Color.GRAY : Color.RED));

        String strHasSigningCert = probeHasSigningCertificate();
        append(sb, "hasSigningCertificate: ", strHasSigningCert,
                "true".equals(strHasSigningCert) ? Color.BLUE
                        : (strHasSigningCert.startsWith("SKIP") || strHasSigningCert.startsWith("ERR") ? Color.GRAY : Color.RED));

        byte[] sigArchiveInfo = signatureFromArchiveInfo();
        String strArchiveInfo = sigArchiveInfo == null ? "N/A" : md5(sigArchiveInfo);
        append(sb, "From ArchiveInfo: ", strArchiveInfo,
                sigArchiveInfo != null && signatureExpected.equals(strArchiveInfo) ? Color.BLUE
                        : (sigArchiveInfo == null ? Color.GRAY : Color.RED));

        // ---- 外部直解析 APK Signing Block v2/v3（模拟外部 native 检测） ----
        byte[] sigV2Block = signatureFromV2Block();
        String strV2Block = sigV2Block == null ? "N/A" : md5(sigV2Block);
        append(sb, "From V2Block: ", strV2Block,
                sigV2Block != null && signatureExpected.equals(strV2Block) ? Color.BLUE : Color.RED);

        byte[] sigV2BlockSvc = signatureFromV2BlockSvc();
        String strV2BlockSvc = sigV2BlockSvc == null ? "N/A" : md5(sigV2BlockSvc);
        append(sb, "From V2Block SVC: ", strV2BlockSvc,
                sigV2BlockSvc != null && signatureExpected.equals(strV2BlockSvc) ? Color.BLUE : Color.RED);
        // ---- end stage 1.5 probes ----
        append(sb, "V2DBG: ", v2LastError == null ? "ok" : v2LastError, Color.GRAY);

        msg.setText(sb);
    }

    private byte[] signatureFromAPI() {
        try {
            @SuppressLint("PackageManagerGetSignatures")
            PackageInfo info = getPackageManager().getPackageInfo(getPackageName(), PackageManager.GET_SIGNATURES);
            return info.signatures[0].toByteArray();
        } catch (PackageManager.NameNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] signatureFromAPK() {
        byte[] sig = signatureFromAPKV1();
        if (sig != null) return sig;
        return signatureFromApkSigningBlock();
    }

    private byte[] signatureFromAPKV1() {
        try (ZipFile zipFile = new ZipFile(getPackageResourcePath())) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.getName().matches("(META-INF/.*)\\.(RSA|DSA|EC)")) {
                    InputStream is = zipFile.getInputStream(entry);
                    CertificateFactory certFactory = CertificateFactory.getInstance("X509");
                    X509Certificate x509Cert = (X509Certificate) certFactory.generateCertificate(is);
                    return x509Cert.getEncoded();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] signatureFromSVC() {
        byte[] sig = signatureFromSVCV1();
        if (sig != null) return sig;
        byte[] apkBytes = readRawApkBytesViaSvc();
        return signatureFromApkSigningBlockBytes(apkBytes);
    }

    // ---- Stage 1.5 probe helpers ----

    private byte[] signatureFromSigningInfo() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null;
        try {
            PackageInfo info = getPackageManager().getPackageInfo(getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
            SigningInfo signingInfo = info.signingInfo;
            if (signingInfo == null) return null;
            Signature[] signatures = signingInfo.getApkContentsSigners();
            if (signatures == null || signatures.length == 0) return null;
            return signatures[0].toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    private String probeHasSigningCertificate() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return "SKIP(<28)";
        try {
            byte[] cert = null;
            try {
                cert = signatureFromAPI();
            } catch (RuntimeException ignored) {
            }
            if (cert == null) cert = getAPKSignatureData();
            if (cert == null) return "ERR:cert";
            byte[] sha256 = MessageDigest.getInstance("SHA-256").digest(cert);
            boolean ok = getPackageManager().hasSigningCertificate(
                    getPackageName(), sha256, PackageManager.CERT_INPUT_SHA256);
            return ok ? "true" : "false";
        } catch (Exception e) {
            return "ERR:" + e.getClass().getSimpleName();
        }
    }

    private byte[] signatureFromArchiveInfo() {
        try {
            PackageInfo info = getPackageManager().getPackageArchiveInfo(
                    getPackageResourcePath(), PackageManager.GET_SIGNATURES);
            if (info == null || info.signatures == null || info.signatures.length == 0) return null;
            return info.signatures[0].toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    private byte[] signatureFromV2Block() {
        // 正常读：xhook 生效时 open 会被重定向到 signed.apk（原V2证书），未生效则读到 fake
        return signatureFromApkSigningBlock();
    }

    private byte[] signatureFromV2BlockSvc() {
        // raw syscall 直读磁盘 base.apk：绕过所有用户态 hook，必读 fake V2 证书
        byte[] apkBytes = readRawApkBytesViaSvc();
        return signatureFromApkSigningBlockBytes(apkBytes);
    }

    // ---- end stage 1.5 probe helpers ----

    private byte[] signatureFromSVCV1() {
        try (ParcelFileDescriptor fd = ParcelFileDescriptor.adoptFd(openAt(getPackageResourcePath()));
             ZipInputStream zis = new ZipInputStream(new FileInputStream(fd.getFileDescriptor()))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().matches("(META-INF/.*)\\.(RSA|DSA|EC)")) {
                    CertificateFactory certFactory = CertificateFactory.getInstance("X509");
                    X509Certificate x509Cert = (X509Certificate) certFactory.generateCertificate(zis);
                    return x509Cert.getEncoded();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] readRawApkBytesViaSvc() {
        try (ParcelFileDescriptor fd = ParcelFileDescriptor.adoptFd(openAt(getPackageResourcePath()));
             FileInputStream fis = new FileInputStream(fd.getFileDescriptor())) {
            long len = fd.getStatSize();
            if (len <= 0 || len > 200 * 1024 * 1024) return null;
            byte[] buf = new byte[(int) len];
            int off = 0;
            while (off < buf.length) {
                int n = fis.read(buf, off, buf.length - off);
                if (n < 0) break;
                off += n;
            }
            return off == buf.length ? buf : null;
        } catch (Exception e) {
            return null;
        }
    }



    /** 解析 APK Signing Block v2 块，取 signer 证书 DER（v1-only 之外的兜底）。 */






    private static void skipFully(DataInputStream in, int n) throws java.io.IOException {
        long skipped = 0;
        while (skipped < n) {
            long s = in.skip((long) n - skipped);
            if (s <= 0) {
                if (in.read() == -1) throw new java.io.IOException("EOF");
                skipped++;
            } else {
                skipped += s;
            }
        }
    }

    private byte[] signatureFromApkSigningBlock() {
        try (RandomAccessFile raf = new RandomAccessFile(getPackageResourcePath(), "r")) {
            long fileLen = raf.length();
            if (fileLen <= 0 || fileLen > 200 * 1024 * 1024) { v2LastError = "apk size " + fileLen; return null; }
            byte[] data = new byte[(int) fileLen];
            raf.readFully(data);
            return signatureFromApkSigningBlockBytes(data);
        } catch (Exception e) {
            v2LastError = "read apk: " + e.toString();
            return null;
        }
    }

    private static byte[] signatureFromApkSigningBlockBytes(byte[] data) {
        v2LastError = null;
        if (data == null || data.length < 32) { v2LastError = "data too small"; return null; }
        int fileLen = data.length;
        // 1) 找 EOCD
        int eocd = -1;
        int tailStart = Math.max(0, fileLen - 65557);
        for (int i = fileLen - 22; i >= tailStart; i--) {
            if ((data[i] & 0xff) == 0x50 && (data[i + 1] & 0xff) == 0x4b
                    && (data[i + 2] & 0xff) == 0x05 && (data[i + 3] & 0xff) == 0x06) {
                eocd = i;
                break;
            }
        }
        if (eocd < 0) { v2LastError = "EOCD not found"; return null; }
        // 2) Central Directory offset
        long cdOffset = 0;
        for (int i = 0; i < 4; i++) cdOffset |= (long) (data[eocd + 16 + i] & 0xff) << (8 * i);
        if (cdOffset < 32 || cdOffset > fileLen) { v2LastError = "bad cdOffset=" + cdOffset; return null; }
        // 3) Signing Block footer
        long footerPos = cdOffset - 24;
        if (footerPos < 0 || footerPos + 24 > fileLen) { v2LastError = "bad footerPos"; return null; }
        if (!"APK Sig Block 42".equals(new String(data, (int) footerPos + 8, 16, StandardCharsets.US_ASCII))) {
            v2LastError = "magic mismatch"; return null;
        }
        long blockSize = 0;
        for (int i = 0; i < 8; i++) blockSize |= (long) (data[(int) footerPos + i] & 0xff) << (8 * i);
        if (blockSize < 24 || blockSize > 100 * 1024 * 1024) { v2LastError = "bad blockSize=" + blockSize; return null; }
        long pairsSize = blockSize - 24;
        long blockStart = cdOffset - blockSize;
        if (pairsSize <= 0 || blockStart < 0 || blockStart + pairsSize > fileLen) { v2LastError = "bad pairs"; return null; }
        // 4) 遍历 ID-value 对
        int off = (int) blockStart;
        int end = (int) (blockStart + pairsSize);
        while (off + 12 <= end) {
            long pairLen = 0;
            for (int i = 0; i < 8; i++) pairLen |= (long) (data[off + i] & 0xff) << (8 * i);
            long id = 0;
            for (int i = 0; i < 4; i++) id |= (long) (data[off + 8 + i] & 0xff) << (8 * i);
            off += 12;
            if (pairLen < 4 || off + pairLen - 4 > end) { v2LastError = "bad pairLen=" + pairLen; break; }
            if (id == 0x7109871aL || id == 0xf05368c0L) { // v2 / v3
                v2LastError = "scheme block len=" + (pairLen - 4);
                byte[] der = parseApkSignerBlock(data, off, (int) (pairLen - 4));
                if (der != null) { v2LastError = "ok"; return der; }
                break;
            }
            off += (int) (pairLen - 4);
        }
        if (v2LastError == null) v2LastError = "no v2/v3 pair";
        return null;
    }

    private static byte[] parseApkSignerBlock(byte[] value, int start, int len) {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(value, start, len);
             DataInputStream dis = new DataInputStream(bais)) {
            // 关键：v2/v3 块 value = 长度前缀的 signer 序列（无 count 字段）
            while (dis.available() > 0) {
                int signerLen = readLEInt(dis);
                if (signerLen <= 0 || signerLen > dis.available()) {
                    v2LastError = "bad signerLen=" + signerLen + " avail=" + dis.available();
                    return null;
                }
                byte[] signer = new byte[signerLen];
                dis.readFully(signer);
                byte[] der = extractCertFromSigner(signer);
                if (der != null) { v2LastError = "ok"; return der; }
            }
            if (v2LastError == null) v2LastError = "signer loop empty";
            return null;
        } catch (Exception e) {
            v2LastError = "parseSigners: " + e.toString();
            return null;
        }
    }

    private static byte[] extractCertFromSigner(byte[] signer) {
        // signer = signedData | signatures | publicKey（均为 length-prefixed）
        // 不逐层猜测字段：直接搜索 X.509 证书标记（30 82 <len16> + 完整 ASN.1）
        try {
            int signedDataLen = readLEInt(new DataInputStream(new ByteArrayInputStream(signer)));
            if (signedDataLen <= 0 || signedDataLen > signer.length - 4) {
                v2LastError = "bad signedDataLen=" + signedDataLen;
                return null;
            }
            byte[] sd = new byte[signedDataLen];
            System.arraycopy(signer, 4, sd, 0, signedDataLen);
            for (int i = 0; i + 4 <= sd.length; i++) {
                if ((sd[i] & 0xff) == 0x30 && (sd[i + 1] & 0xff) == 0x82) {
                    int certLen = ((sd[i + 2] & 0xff) << 8) | (sd[i + 3] & 0xff);
                    int total = 4 + certLen;
                    if (i + total <= sd.length && certLen > 40) {
                        byte[] der = Arrays.copyOfRange(sd, i, i + total);
                        try {
                            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X509")
                                    .generateCertificate(new ByteArrayInputStream(der));
                            v2LastError = "ok cert@" + i + " len=" + total;
                            return cert.getEncoded();
                        } catch (Exception ignore) {
                            // 30 82 但解码失败，继续找下一个
                        }
                    }
                }
            }
            v2LastError = "X.509 cert not found in signedData";
        } catch (Exception e) {
            v2LastError = "extractCert: " + e.toString();
        }
        return null;
    }



    private String getAPKPackageName() {
        return getApplicationContext().getPackageName();
    }

    private byte[] getAPKSignatureData() {
        if (apkSignatureCacheSet) return apkSignatureCache;
        byte[] sig = signatureFromAPK();
        if (sig == null) sig = signatureFromApkSigningBlock();
        apkSignatureCache = sig;
        apkSignatureCacheSet = true;
        return sig;
    }

    private String safeBase64(byte[] data) {
        return data == null ? "<null>" : Base64.encodeToString(data, Base64.DEFAULT);
    }

    /** APK v2/v3 长度字段全部是 little-endian uint32；DataInputStream.readInt() 是大端，必须手动反转 */
    private static int readLEInt(DataInputStream in) throws java.io.IOException {
        int b0 = in.read() & 0xff;
        int b1 = in.read() & 0xff;
        int b2 = in.read() & 0xff;
        int b3 = in.read() & 0xff;
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }

    private String md5(byte[] bytes) {
        if (bytes == null) {
            return "null";
        }
        try {
            byte[] digest = MessageDigest.getInstance("MD5").digest(bytes);
            String hexDigits = "0123456789abcdef";
            char[] str = new char[digest.length * 2];
            int k = 0;
            for (byte b : digest) {
                str[k++] = hexDigits.charAt(b >>> 4 & 0xf);
                str[k++] = hexDigits.charAt(b & 0xf);
            }
            return new String(str);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }



    private static final String[] SENS_WORDS = {
            "frida", "rwxp", "zygisk", "riru", "lsposed", "xposed",
            "/data/local/tmp", "/data/adb/"
    };
    private static final Pattern RE_INO = Pattern.compile("ino=(\\d+)");
    private static final Pattern RE_MAP_INO = Pattern.compile("\\s+(\\d+)\\s+(/[^\\s]+\\.apk)(?: \\(deleted\\))?$");
    private static final Pattern RE_MAP_SO = Pattern.compile("\\s(/[^\\s]+\\.so)(?: \\(deleted\\))?$");

    
    private String resolveExpectedSignature() {
        byte[] selfSig = null;
        try {
            selfSig = signatureFromAPI();
        } catch (Throwable ignored) {
        }
        byte[] repSig = null;
        File rep = new File(getApplicationInfo().dataDir, "signed.apk");
        if (rep.isFile() && rep.length() > 0) {
            repSig = signatureFromApkFile(rep);
        }
        byte[] expected;
        if (repSig != null && selfSig != null && MessageDigest.isEqual(repSig, selfSig)) {
            // killer 生效：API 注入签名 == 内嵌 input 签名（唯一可信场景）
            expected = repSig;
        } else if (selfSig != null) {
            // 干净安装，或 signed.apk 为旧安装残留：以当前安装为准
            expected = selfSig;
        } else if (repSig != null) {
            expected = repSig;
        } else {
            return "1fb11e8214ae8b8c259aa9cd87387ac0";
        }
        String resolved = md5(expected);
        String source;
        if (repSig != null && selfSig != null && MessageDigest.isEqual(repSig, selfSig)) {
            source = "signed.apk";
        } else if (selfSig != null) {
            source = "current-install";
        } else {
            source = "signed.apk-only";
        }
        Log.i("SigDetector", "Dynamic Expected=" + resolved + " source=" + source);
        return resolved;
    }

    private static byte[] signatureFromApkFile(File apkFile) {
        if (apkFile == null || !apkFile.isFile()) return null;
        byte[] sig = signatureFromApkV1File(apkFile);
        if (sig != null) return sig;
        return signatureFromApkSigningBlockFile(apkFile);
    }

    private static byte[] signatureFromApkV1File(File apkFile) {
        try (ZipFile zipFile = new ZipFile(apkFile)) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.getName().matches("(META-INF/.*)\\.(RSA|DSA|EC)")) {
                    InputStream is = zipFile.getInputStream(entry);
                    CertificateFactory certFactory = CertificateFactory.getInstance("X509");
                    X509Certificate x509Cert = (X509Certificate) certFactory.generateCertificate(is);
                    return x509Cert.getEncoded();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static byte[] signatureFromApkSigningBlockFile(File apkFile) {
        long fileLen = apkFile.length();
        if (fileLen <= 0 || fileLen > 200 * 1024 * 1024) return null;
        try (RandomAccessFile raf = new RandomAccessFile(apkFile, "r")) {
            byte[] data = new byte[(int) fileLen];
            raf.readFully(data);
            return signatureFromApkSigningBlockBytes(data);
        } catch (Exception e) {
            return null;
        }
    }





    private String findRepPath() {
        File f = new File(getApplicationInfo().dataDir, "signed.apk");
        if (f.exists()) return f.getAbsolutePath();
        return null;
    }

    private long extractIno(String statStr, int index) {
        if (statStr == null) return -1;
        String[] parts = statStr.split("\\|");
        if (parts.length <= index) return -1;
        Matcher m = RE_INO.matcher(parts[index]);
        return m.find() ? Long.parseLong(m.group(1)) : -1;
    }

    private int countSensitiveWords(String text) {
        if (text == null) return 0;
        String lower = text.toLowerCase();
        int count = 0;
        for (String w : SENS_WORDS) {
            if (lower.contains(w)) count++;
        }
        return count;
    }

    private int countSensitiveSos(String maps) {
        if (maps == null) return 0;
        java.util.Set<String> sos = new java.util.LinkedHashSet<>();
        Matcher m = RE_MAP_SO.matcher(maps);
        while (m.find()) sos.add(m.group(1));
        int count = 0;
        for (String so : sos) {
            for (String w : SENS_WORDS) {
                if (so.toLowerCase().contains(w)) {
                    count++;
                    break;
                }
            }
        }
        return count;
    }

    private long extractMapsApkInode(String maps, String apkPath) {
        if (maps == null || apkPath == null) return -1;
        for (String line : maps.split("\n")) {
            if (line.contains(apkPath)) {
                Matcher m = RE_MAP_INO.matcher(line);
                if (m.find()) return Long.parseLong(m.group(1));
            }
        }
        return -1;
    }

    @SuppressLint("SetTextI18n")
    private void appendProbe(SpannableStringBuilder sb, String header, String value, int color) {
        append(sb, header, value, color);
        Log.i("SigDetector", header + value);
    }

    @SuppressLint("SetTextI18n")
    private void runDetectors(SpannableStringBuilder sb, String signatureExpected) {
        String apkPath = getPackageResourcePath();
        if (repPath == null) repPath = findRepPath();

        byte[] fopenData = NativeDetector.probeFopen(apkPath);
        String md5Fopen = "ERR";
        if (fopenData != null) {
            boolean found = false;
            try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(fopenData))) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    if (entry.getName().matches("(META-INF/.*)\\.(RSA|DSA|EC)")) {
                        CertificateFactory cf = CertificateFactory.getInstance("X509");
                        X509Certificate cert = (X509Certificate) cf.generateCertificate(zis);
                        md5Fopen = md5(cert.getEncoded());
                        found = true;
                        break;
                    }
                }
            } catch (Exception e) {
                md5Fopen = "ERR:" + e.getClass().getSimpleName();
            }
            if (!found) {
                byte[] der = signatureFromApkSigningBlockBytes(fopenData);
                if (der != null) md5Fopen = md5(der);
            }
        }
        boolean pass4 = md5Fopen.equals(signatureExpected);
        appendProbe(sb, "ch4 native_fopen: ", md5Fopen + (pass4 ? " (PASS)" : " (FAIL)"), pass4 ? Color.BLUE : Color.RED);

        String statStr = NativeDetector.probeStat(apkPath);
        long normalIno = extractIno(statStr, 0);
        long rawIno = extractIno(statStr, 1);
        boolean pass5 = normalIno > 0 && rawIno > 0;
        boolean hooked5 = normalIno != rawIno;
        appendProbe(sb, "ch5 stat norm/raw: ",
                "normal_ino=" + normalIno + " raw_ino=" + rawIno + (hooked5 ? " (HOOKED)" : " (PASS)"),
                pass5 ? Color.BLUE : Color.RED);

        String normMaps = NativeDetector.probeMaps(false);
        String rawMaps = NativeDetector.probeMaps(true);
        int normSens = countSensitiveWords(normMaps);
        int rawSens = countSensitiveWords(rawMaps);
        long normApkIno = extractMapsApkInode(normMaps, apkPath);
        long rawApkIno = extractMapsApkInode(rawMaps, apkPath);
        boolean dimensionSame = normApkIno == rawApkIno && normSens == rawSens;
        boolean hasOrigin = repPath != null && new File(repPath).exists();
        long originIno = -1;
        if (hasOrigin) {
            String repStat = NativeDetector.probeStat(repPath);
            originIno = extractIno(repStat, 0);
        }
        boolean pass7;
        String ch7Mark;
        if (hasOrigin) {
            if (normalIno != rawIno) {
                // stat 已被 hook：校验重定向目标 + maps 无敏感词
                pass7 = normalIno > 0 && normalIno == originIno && normSens == 0;
                ch7Mark = pass7 ? "HOOKED" : "CHECK";
            } else {
                // stat 未被 hook（纯净/未处理）：按维度一致判定，残留文件不参与
                pass7 = dimensionSame;
                ch7Mark = pass7 ? "PASS" : "CHECK";
            }
        } else {
            pass7 = dimensionSame;
            ch7Mark = pass7 ? "PASS" : "CHECK";
        }
        int ch7Color = pass7 ? Color.BLUE : Color.RED;
        String ch7line = "norm_sens=" + normSens + " raw_sens=" + rawSens
                + " maps_inode(norm/raw/origin)=" + normApkIno + "/" + rawApkIno + "/" + originIno
                + " stat_ino(norm/raw)=" + normalIno + "/" + rawIno
                + " dim_same:" + dimensionSame + " (" + ch7Mark + ")";
        appendProbe(sb, "ch7 maps: ", ch7line, ch7Color);

        String fds = NativeDetector.probeFds();
        appendProbe(sb, "ch8 fds: ", fds.replace("\n", " | "), Color.GRAY);

        int normSos = countSensitiveSos(normMaps);
        int rawSos = countSensitiveSos(rawMaps);
        boolean filtered9 = normSos < rawSos;
        appendProbe(sb, "ch9 so_list: ",
                "norm_sens=" + normSos + " raw_sens=" + rawSos + (filtered9 ? " (FILTERED)" : " (PASS)"),
                Color.BLUE);
    }





    public static class App extends Application {
    }

}