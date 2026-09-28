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


    private String getAPKPackageName() {
        return getApplicationContext().getPackageName();
    }

    private byte[] getAPKSignatureData() {
        return signatureFromAPK();
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
    private static final Pattern RE_MAP_INO = Pattern.compile("^[0-9a-f]+-[0-9a-f]+\\s+\\S+\\s+\\S+\\s+\\S+\\s+(\\d+)\\s+");
    private static final Pattern RE_MAP_SO = Pattern.compile("\\s(/[^\\s]+\\.so)(?: \\(deleted\\))?$");

    private String findRepPath() {
        String[] candidates = {"/data/user/0/r.s.sign/origin.apk", "/data/data/r.s.sign/origin.apk"};
        for (String c : candidates) {
            if (new File(c).exists()) return c;
        }
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
            pass7 = normApkIno > 0 && normApkIno == originIno && normSens == 0;
            ch7Mark = pass7 ? "HOOKED" : "CHECK";
        } else {
            pass7 = dimensionSame;
            ch7Mark = pass7 ? "PASS" : "CHECK";
        }
        int ch7Color = pass7 ? Color.BLUE : Color.RED;
        String ch7line = "norm_sens=" + normSens + " raw_sens=" + rawSens
                + " inode(norm/raw/origin)=" + normApkIno + "/" + rawApkIno + "/" + originIno
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