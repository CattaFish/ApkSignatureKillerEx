package r.s.sign;

import android.annotation.SuppressLint;
import android.app.Application;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Environment;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.Log;

import org.lsposed.hiddenapibypass.HiddenApiBypass;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class KillerApplication extends Application {
    private static final String TAG = "KillerApp";
    public static final String URL = "https://github.com/L-JINBIN/ApkSignatureKillerEx";
    private static final AtomicBoolean sInitDone = new AtomicBoolean(false);

    // 作为 Application 入口（manifest android:name="r.s.sign.KillerApplication"）时自动初始化
    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        init(this);
    }

    /**
     * 通用入口：任意应用的 Application 可调用 KillerApplication.init(this)。
     * 包名、签名数据全部运行时从 signed.apk 动态提取，无任何硬编码。
     */
    @SuppressLint("UnsafeDynamicallyLoadedCode")
    public static void init(Context context) {
        if (context == null) {
            Log.w(TAG, "init: null context");
            return;
        }
        if (!sInitDone.compareAndSet(false, true)) {
            Log.w(TAG, "init: already done, skip");
            return;
        }
        try {
            String packageName = context.getPackageName();
            Log.w(TAG, "init: pkg=" + packageName);
            File dataFile = getDataFile(packageName);
            if (dataFile == null) {
                Log.w(TAG, "init: dataFile null");
                return;
            }
            File repFile = new File(dataFile, "signed.apk");
            extractOriginApk(context, repFile);
            Log.w(TAG, "init: origin exists=" + repFile.exists() + " len=" + repFile.length());
            if (!repFile.exists()) return;

            byte[] signatureBytes = readSignatureFromApk(repFile);
            Log.w(TAG, "init: sig=" + (signatureBytes != null ? signatureBytes.length : "null"));
            if (signatureBytes != null) {
                try {
                    killPM(packageName, signatureBytes);
                    Log.w(TAG, "init: killPM done");
                } catch (Throwable t) {
                    Log.e(TAG, "init: killPM threw", t);
                }
            }
            try {
                killOpen(packageName);
                Log.w(TAG, "init: killOpen done");
            } catch (Throwable t) {
                Log.e(TAG, "init: killOpen threw", t);
            }
        } catch (Throwable t) {
            Log.e(TAG, "init: outer threw", t);
        }
    }

    private static void extractOriginApk(Context context, File repFile) {
        try {
            if (repFile.exists() && repFile.length() > 0) return;
            InputStream is = context.getAssets().open("SignedByRS/input.apk");
            if (is == null) return;
            File parent = repFile.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            try (OutputStream os = new FileOutputStream(repFile)) {
                byte[] buf = new byte[102400];
                int len;
                while ((len = is.read(buf)) != -1) os.write(buf, 0, len);
            }
            is.close();
        } catch (IOException ignored) {
        }
    }

    private static byte[] readSignatureFromApk(File apkFile) {
        if (apkFile == null || !apkFile.exists()) return null;
        // 1) v1: META-INF 证书
        try (ZipFile zip = new ZipFile(apkFile)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.getName().matches("(META-INF/.*)\\.(RSA|DSA|EC)")) {
                    try (InputStream is = zip.getInputStream(entry)) {
                        CertificateFactory cf = CertificateFactory.getInstance("X509");
                        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
                        return cert.getEncoded();
                    }
                }
            }
        } catch (Exception ignored) {
        }
        // 2) v2/v3: APK Signing Block（v1-only 之外的必需兜底）
        return readSignatureFromSigningBlock(apkFile);
    }

    /* ============ APK Signature Scheme v2/v3 解析 ============ */

    private static byte[] readSignatureFromSigningBlock(File apkFile) {
        try (RandomAccessFile raf = new RandomAccessFile(apkFile, "r")) {
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
            for (int i = 0; i < 4; i++) cdOffset |= (long) (tail[eocd + 16 + i] & 0xff) << (8 * i);
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
                if (id == 0x7109871aL || id == 0xf05368c0L) { // v2 / v3
                    byte[] der = parseApkSignerBlock(pairs, off, (int) (pairLen - 4));
                    if (der != null) return der;
                }
                off += (int) (pairLen - 4);
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private static byte[] parseApkSignerBlock(byte[] value, int start, int len) {
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
        } catch (Exception ignored) {
        }
        return null;
    }

    private static byte[] extractCertFromSigner(byte[] signer) {
        try (ByteArrayInputStream sb = new ByteArrayInputStream(signer);
             DataInputStream sdis = new DataInputStream(sb)) {
            // Signer: SignedData | signatures | publicKey
            int signedDataLen = sdis.readInt();
            if (signedDataLen <= 0 || signedDataLen > signer.length - 4) return null;
            byte[] signedData = new byte[signedDataLen];
            sdis.readFully(signedData);
            try (ByteArrayInputStream sd = new ByteArrayInputStream(signedData);
                 DataInputStream sdd = new DataInputStream(sd)) {
                // SignedData: digests | certificates | attributes
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
        } catch (Exception ignored) {
        }
        return null;
    }

    private static void skipFully(DataInputStream in, int n) throws IOException {
        long skipped = 0;
        while (skipped < n) {
            long s = in.skip((long) n - skipped);
            if (s <= 0) {
                if (in.read() == -1) throw new IOException("EOF");
                skipped++;
            } else {
                skipped += s;
            }
        }
    }

    private static void killPM(String packageName, byte[] signatureBytes) {
        Signature fakeSignature = new Signature(signatureBytes);
        Parcelable.Creator<PackageInfo> originalCreator = PackageInfo.CREATOR;
        Parcelable.Creator<PackageInfo> creator = new Parcelable.Creator<PackageInfo>() {
            @Override
            public PackageInfo createFromParcel(Parcel source) {
                PackageInfo packageInfo = originalCreator.createFromParcel(source);
                if (packageInfo.packageName.equals(packageName)) {
                    if (packageInfo.signatures != null && packageInfo.signatures.length > 0) {
                        packageInfo.signatures[0] = fakeSignature;
                    }
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        if (packageInfo.signingInfo != null) {
                            Signature[] signaturesArray = packageInfo.signingInfo.getApkContentsSigners();
                            if (signaturesArray != null && signaturesArray.length > 0) {
                                signaturesArray[0] = fakeSignature;
                            }
                        }
                    }
                }
                return packageInfo;
            }

            @Override
            public PackageInfo[] newArray(int size) {
                return originalCreator.newArray(size);
            }
        };
        try {
            findField(PackageInfo.class, "CREATOR").set(null, creator);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            HiddenApiBypass.addHiddenApiExemptions("Landroid/os/Parcel;", "Landroid/content/pm", "Landroid/app");
        }
        try {
            Object cache = findField(PackageManager.class, "sPackageInfoCache").get(null);
            //noinspection ConstantConditions
            cache.getClass().getMethod("clear").invoke(cache);
        } catch (Throwable ignored) {
        }
        try {
            Map<?, ?> mCreators = (Map<?, ?>) findField(Parcel.class, "mCreators").get(null);
            //noinspection ConstantConditions
            mCreators.clear();
        } catch (Throwable ignored) {
        }
        try {
            Map<?, ?> sPairedCreators = (Map<?, ?>) findField(Parcel.class, "sPairedCreators").get(null);
            //noinspection ConstantConditions
            sPairedCreators.clear();
        } catch (Throwable ignored) {
        }
    }

    private static Field findField(Class<?> clazz, String fieldName) throws NoSuchFieldException {
        try {
            Field field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
            return field;
        } catch (NoSuchFieldException e) {
            while (true) {
                clazz = clazz.getSuperclass();
                if (clazz == null || clazz.equals(Object.class)) {
                    break;
                }
                try {
                    Field field = clazz.getDeclaredField(fieldName);
                    field.setAccessible(true);
                    return field;
                } catch (NoSuchFieldException ignored) {
                }
            }
            throw e;
        }
    }

    private static void killOpen(String packageName) {
        try {
            System.loadLibrary("SignedByRS");
        } catch (Throwable e) {
            System.err.println("Load SignedByRS library failed");
            return;
        }
        String apkPath = getApkPath(packageName);
        if (apkPath == null) {
            System.err.println("Get apk path failed");
            return;
        }
        File repFile = new File(getDataFile(packageName), "signed.apk");
        if (!repFile.exists()) {
            System.err.println("signed.apk not found");
            return;
        }
        hookApkPath(apkPath, repFile.getAbsolutePath());
    }

    @SuppressLint("SdCardPath")
    private static File getDataFile(String packageName) {
        try {
            String username = Environment.getExternalStorageDirectory().getName();
            if (username.matches("\\d+")) {
                File file = new File("/data/user/" + username + "/" + packageName);
                if (file.canWrite() || file.isDirectory()) {
                    return file;
                }
            }
        } catch (Throwable ignored) {
        }
        return new File("/data/data/" + packageName);
    }

    private static String getApkPath(String packageName) {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] arr = line.split("\\s+");
                String path = arr[arr.length - 1];
                if (isApkPath(packageName, path)) {
                    return path;
                }
            }
            return null;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean isApkPath(String packageName, String path) {
        if (!path.startsWith("/") || !path.endsWith(".apk")) {
            return false;
        }
        String[] splitStr = path.substring(1).split("/", 6);
        int splitCount = splitStr.length;
        if (splitCount == 4 || splitCount == 5) {
            if (splitStr[0].equals("data") && splitStr[1].equals("app") && splitStr[splitCount - 1].equals("base.apk")) {
                return splitStr[splitCount - 2].startsWith(packageName);
            }
            if (splitStr[0].equals("mnt") && splitStr[1].equals("asec") && splitStr[splitCount - 1].equals("pkg.apk")) {
                return splitStr[splitCount - 2].startsWith(packageName);
            }
        } else if (splitCount == 3) {
            if (splitStr[0].equals("data") && splitStr[1].equals("app")) {
                return splitStr[2].startsWith(packageName);
            }
        } else if (splitCount == 6) {
            if (splitStr[0].equals("mnt") && splitStr[1].equals("expand") && splitStr[3].equals("app") && splitStr[5].equals("base.apk")) {
                return splitStr[4].endsWith(packageName);
            }
        }
        return false;
    }

    private static native void hookApkPath(String apkPath, String repPath);

    /** 刷新全部已加载 .so 的 hook：目标应用后续 loadLibrary 的检测库需要此入口 */
    public static native void refreshHooks();
}
