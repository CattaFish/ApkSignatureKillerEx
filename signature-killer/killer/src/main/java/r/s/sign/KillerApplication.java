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

    private static int readLEInt(DataInputStream in) throws IOException {
        int b0 = in.read() & 0xff;
        int b1 = in.read() & 0xff;
        int b2 = in.read() & 0xff;
        int b3 = in.read() & 0xff;
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }

    /* ============ APK Signature Scheme v2/v3 解析 ============ */


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
                        Log.d(TAG, "init: sig scheme=v1 len=" + cert.getEncoded().length);
                        return cert.getEncoded();
                    }
                }
            }
        } catch (Exception ignored) {
        }
        // 2) v2/v3: APK Signing Block（little-endian 长度字段）
        byte[] v23 = readSignatureFromSigningBlock(apkFile);
        Log.d(TAG, "init: sig scheme=v2/v3 len=" + (v23 != null ? v23.length : 0));
        return v23;
    }

    private static byte[] readSignatureFromSigningBlock(File apkFile) {
        try (RandomAccessFile raf = new RandomAccessFile(apkFile, "r")) {
            long fileLen = raf.length();
            if (fileLen < 32 || fileLen > 200 * 1024 * 1024) return null;
            byte[] data = new byte[(int) fileLen];
            raf.readFully(data);
            int eocd = -1;
            int tailStart = Math.max(0, data.length - 65557);
            for (int i = data.length - 22; i >= tailStart; i--) {
                if ((data[i] & 0xff) == 0x50 && (data[i + 1] & 0xff) == 0x4b
                        && (data[i + 2] & 0xff) == 0x05 && (data[i + 3] & 0xff) == 0x06) {
                    eocd = i;
                    break;
                }
            }
            if (eocd < 0) return null;
            long cdOffset = 0;
            for (int i = 0; i < 4; i++) cdOffset |= (long) (data[eocd + 16 + i] & 0xff) << (8 * i);
            if (cdOffset < 32 || cdOffset > data.length) return null;
            long footerPos = cdOffset - 24;
            if (footerPos < 0 || footerPos + 24 > data.length) return null;
            if (!"APK Sig Block 42".equals(new String(data, (int) footerPos + 8, 16, "US-ASCII"))) return null;
            long blockSize = 0;
            for (int i = 0; i < 8; i++) blockSize |= (long) (data[(int) footerPos + i] & 0xff) << (8 * i);
            if (blockSize < 24 || blockSize > 100 * 1024 * 1024) return null;
            long pairsSize = blockSize - 24;
            long blockStart = cdOffset - blockSize;
            if (pairsSize <= 0 || blockStart < 0 || blockStart + pairsSize > data.length) return null;
            int off = (int) blockStart;
            int end = (int) (blockStart + pairsSize);
            while (off + 12 <= end) {
                long pairLen = 0;
                for (int i = 0; i < 8; i++) pairLen |= (long) (data[off + i] & 0xff) << (8 * i);
                long id = 0;
                for (int i = 0; i < 4; i++) id |= (long) (data[off + 8 + i] & 0xff) << (8 * i);
                off += 12;
                if (pairLen < 4 || off + pairLen - 4 > end) break;
                if (id == 0x7109871aL || id == 0xf05368c0L) {
                    byte[] der = parseApkSignerBlock(data, off, (int) (pairLen - 4));
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
            // v2/v3 value = 长度前缀 signer 序列（无 count）
            while (dis.available() > 0) {
                int signerLen = readLEInt(dis);
                if (signerLen <= 0 || signerLen > dis.available()) break;
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
        // signer = signedData | signatures | publicKey（均为 length-prefixed）
        // 直接搜索 X.509 标记（30 82 <len16>），不逐层猜字段
        try {
            int signedDataLen = readLEInt(new DataInputStream(new ByteArrayInputStream(signer)));
            if (signedDataLen <= 0 || signedDataLen > signer.length - 4) return null;
            byte[] sd = new byte[signedDataLen];
            System.arraycopy(signer, 4, sd, 0, signedDataLen);
            for (int i = 0; i + 4 <= sd.length; i++) {
                if ((sd[i] & 0xff) == 0x30 && (sd[i + 1] & 0xff) == 0x82) {
                    int certLen = ((sd[i + 2] & 0xff) << 8) | (sd[i + 3] & 0xff);
                    int total = 4 + certLen;
                    if (i + total <= sd.length && certLen > 40) {
                        byte[] der = java.util.Arrays.copyOfRange(sd, i, i + total);
                        try {
                            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X509")
                                    .generateCertificate(new ByteArrayInputStream(der));
                            return cert.getEncoded();
                        } catch (Exception ignored) {
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return null;
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
