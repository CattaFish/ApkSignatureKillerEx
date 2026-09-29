package r.s.test;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.Application;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
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
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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

    private String repPath;
    private byte[] apkSignatureCache;
    private boolean apkSignatureCacheSet;


    @SuppressLint("SetTextI18n")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        TextView msg = findViewById(R.id.msg);

        // The following demonstrates three ways to get the MD5 of a signature

        String signatureExpected = "1fb11e8214ae8b8c259aa9cd87387ac0";
        String signatureFromAPI = md5(signatureFromAPI());
        String signatureFromAPK = md5(signatureFromAPK());
        String signatureFromSVC = md5(signatureFromSVC());

        // When over-signing is turned on, the API and APK methods will get the false signature MD5

        // And the SVC method always gets the real signature MD5

        SpannableStringBuilder sb = new SpannableStringBuilder();
        append(sb, "Expected: ", signatureExpected, Color.BLACK);
        append(sb, "From API: ", signatureFromAPI, signatureExpected.equals(signatureFromAPI) ? Color.BLUE : Color.RED);
        append(sb, "From APK: ", signatureFromAPK, signatureExpected.equals(signatureFromAPK) ? Color.BLUE : Color.RED);
        append(sb, "From SVC: ", signatureFromSVC, signatureExpected.equals(signatureFromSVC) ? Color.BLUE : Color.RED);

        // Of course, SVC is not absolutely safe, but relatively more reliable,
        // the actual use of the means need to be combined with more
        append(sb, "Package Name: ", getAPKPackageName(), Color.BLACK);
        // Print SignatureData as hex string
        // append(sb, "Signature Data: ", Arrays.toString(getAPKSignatureData()), Color.BLACK);
        // Print the signature data as base64 string
        append(sb, "Signature Data: ", Base64.encodeToString(getAPKSignatureData(), Base64.DEFAULT), Color.BLACK);
        // Print to log for easy copy
        System.out.println("Signature Data: " + Base64.encodeToString(getAPKSignatureData(), Base64.DEFAULT));
        byte[] signatureData = getAPKSignatureData();
        if (signatureData != null) {
            String base64Signature = Base64.encodeToString(signatureData, Base64.DEFAULT);
            Log.i("SignatureData", "Signature Data: " + base64Signature);
        } else {
            Log.e("SignatureData", "Signature data is null");
        }

        runDetectors(sb, signatureExpected);

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


    /** 解析 APK Signing Block v2 块，取 signer 证书 DER（v1-only 之外的兜底）。 */
    private byte[] signatureFromApkSigningBlock() {
        try (RandomAccessFile raf = new RandomAccessFile(getPackageResourcePath(), "r")) {
            long fileLen = raf.length();
            if (fileLen < 22) return null;
            int tailLen = (int) Math.min(fileLen, 65557);
            byte[] tail = new byte[tailLen];
            raf.seek(fileLen - tailLen);
            raf.readFully(tail);
            int eocd = -1;
            for (int i = tailLen - 22; i >= 0; i--) {
                if ((tail[i] & 0xff) == 0x50 && (tail[i + 1] & 0xff) == 0x4b
                        && (tail[i + 2] & 0xff) == 0x05 && (tail[i + 3] & 0xff) == 0x06) {
                    eocd = i;
                    break;
                }
            }
            if (eocd < 0) return null;
            long cdOffset = 0;
            for (int i = 0; i < 4; i++) {
                cdOffset |= (long) (tail[eocd + 16 + i] & 0xff) << (8 * i);
            }
            if (cdOffset < 32) return null;
            long footerPos = cdOffset - 24;
            raf.seek(footerPos);
            byte[] footer = new byte[24];
            raf.readFully(footer);
            if (!"APK Sig Block 42".equals(new String(footer, 8, 16, "US-ASCII"))) return null;
            long blockSize = 0;
            for (int i = 0; i < 8; i++) blockSize |= (long) (footer[i] & 0xff) << (8 * i);
            if (blockSize < 24 || blockSize > 100 * 1024 * 1024) return null;
            long pairsSize = blockSize - 24;
            if (pairsSize <= 0 || pairsSize > 100 * 1024 * 1024) return null;
            long blockStart = cdOffset - blockSize;
            if (blockStart < 0) return null;
            raf.seek(blockStart);
            byte[] pairs = new byte[(int) pairsSize];
            raf.readFully(pairs);
            int off = 0;
            while (off + 12 <= pairs.length) {
                long pairLen = 0;
                for (int i = 0; i < 8; i++) pairLen |= (long) (pairs[off + i] & 0xff) << (8 * i);
                long id = 0;
                for (int i = 0; i < 4; i++) id |= (long) (pairs[off + 8 + i] & 0xff) << (8 * i);
                off += 12;
                if (pairLen < 4 || off + pairLen - 4 > (long) pairs.length) break;
                if (id == 0x7109871aL || id == 0xf05368c0L) {
                    byte[] der = parseApkSignerBlock(pairs, off, (int) (pairLen - 4));
                    if (der != null) return der;
                }
                off += (int) (pairLen - 4);
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    private byte[] parseApkSignerBlock(byte[] value, int start, int len) {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(value, start, len);
             DataInputStream dis = new DataInputStream(bais)) {
            int signerCount = dis.readInt();
            if (signerCount <= 0 || signerCount > 16) return null;
            while (signerCount-- > 0) {
                int signerLen = dis.readInt();
                if (signerLen <= 0 || signerLen > len - 4) return null;
                byte[] signer = new byte[signerLen];
                dis.readFully(signer);
                byte[] der = extractCertFromSigner(signer);
                if (der != null) return der;
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    private byte[] extractCertFromSigner(byte[] signer) {
        try (ByteArrayInputStream sb = new ByteArrayInputStream(signer);
             DataInputStream sdis = new DataInputStream(sb)) {
            int signedDataLen = sdis.readInt();
            if (signedDataLen <= 0 || signedDataLen > signer.length - 4) return null;
            byte[] signedData = new byte[signedDataLen];
            sdis.readFully(signedData);
            try (ByteArrayInputStream sd = new ByteArrayInputStream(signedData);
                 DataInputStream sdd = new DataInputStream(sd)) {
                int digestsLen = sdd.readInt();
                if (digestsLen < 0) return null;
                skipFully(sdd, digestsLen);
                int certsLen = sdd.readInt();
                if (certsLen <= 0) return null;
                byte[] certs = new byte[certsLen];
                sdd.readFully(certs);
                try (ByteArrayInputStream cb = new ByteArrayInputStream(certs);
                     DataInputStream cd = new DataInputStream(cb)) {
                    int certCount = cd.readInt();
                    if (certCount <= 0 || certCount > 16) return null;
                    int certLen = cd.readInt();
                    if (certLen <= 0 || certLen > 100000) return null;
                    byte[] der = new byte[certLen];
                    cd.readFully(der);
                    X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X509")
                            .generateCertificate(new ByteArrayInputStream(der));
                    return cert.getEncoded();
                }
            }
        } catch (Exception e) {
            return null;
        }
    }



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
            try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(fopenData))) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    if (entry.getName().matches("(META-INF/.*)\\.(RSA|DSA|EC)")) {
                        CertificateFactory cf = CertificateFactory.getInstance("X509");
                        X509Certificate cert = (X509Certificate) cf.generateCertificate(zis);
                        md5Fopen = md5(cert.getEncoded());
                        break;
                    }
                }
            } catch (Exception e) {
                md5Fopen = "ERR:" + e.getClass().getSimpleName();
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