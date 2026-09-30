package r.s.sign;

import android.annotation.SuppressLint;
import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
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
import java.util.Set;
import java.util.HashSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class KillerApplication extends Application {
    private static final String TAG = "KillerApp";
    public static final String URL = "https://github.com/L-JINBIN/ApkSignatureKillerEx";
    private static final AtomicBoolean sInitDone = new AtomicBoolean(false);
    private static final Map<String, Signature[]> sSignatureCache = new ConcurrentHashMap<>();
    private static final Set<String> sSignatureMisses = new HashSet<>();
    private static byte[] sPmExpectedCert;
    private static String sRedirectApkPath;
    private static final AtomicBoolean sPmProxyInstalled = new AtomicBoolean(false);

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
            String originPath = OriginApkCache.prepare(context);
            File repFile = originPath != null ? new File(originPath) : null;
            Log.w(TAG, "init: origin exists=" + (repFile != null && repFile.exists()) + " len=" + (repFile != null ? repFile.length() : 0));
            if (repFile == null || !repFile.exists()) return;

            byte[] signatureBytes = readSignatureFromApk(repFile);
            Log.w(TAG, "init: sig=" + (signatureBytes != null ? signatureBytes.length : "null"));
            if (signatureBytes != null) {
                try {
                    try {
                        File repFile = new File(context.getDataDir(), "signed.apk");
                        if (repFile.isFile()) sRedirectApkPath = repFile.getAbsolutePath();
                    } catch (Throwable ignored) {
                    }
                    cacheOriginalSignature(packageName, signatureBytes);
                    killPM(packageName);
                    installPmProxy(context);
                    Log.w(TAG, "init: killPM done");
                } catch (Throwable t) {
                    Log.e(TAG, "init: killPM threw", t);
                }
            }
            try {
                redirectApkPaths(context);
                Log.w(TAG, "init: redirectApkPaths done");
            } catch (Throwable t) {
                Log.e(TAG, "init: redirectApkPaths threw", t);
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
        // 由 OriginApkCache.prepare() 接管；此方法保留仅为兼容旧调用。
        OriginApkCache.prepare(context);
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



    private static void cacheOriginalSignature(String packageName, byte[] signatureBytes) {
        if (packageName == null || signatureBytes == null) return;
        try {
            Signature[] sigs = new Signature[]{new Signature(signatureBytes)};
            sSignatureCache.put(packageName, sigs);
            sSignatureMisses.remove(packageName);
            sPmExpectedCert = signatureBytes;
            try {
                File repFile = new File(context.getDataDir(), "signed.apk");
                if (repFile.isFile()) sRedirectApkPath = repFile.getAbsolutePath();
            } catch (Throwable ignored) {
            }
        } catch (Throwable e) {
            Log.w(TAG, "cacheOriginalSignature failed for " + packageName, e);
        }
    }

    private static Signature[] getOriginalSignatures(String packageName) {
        if (packageName == null) return null;
        Signature[] cached = sSignatureCache.get(packageName);
        if (cached != null) return cached;
        sSignatureMisses.add(packageName);
        return null;
    }

    private static Signature[] cloneSignatures(Signature[] signatures) {
        if (signatures == null) return null;
        Signature[] cloned = new Signature[signatures.length];
        for (int i = 0; i < signatures.length; i++) {
            cloned[i] = signatures[i] == null ? null : new Signature(signatures[i].toByteArray());
        }
        return cloned;
    }

    private static void replaceSignatureArray(Signature[] target, Signature[] replacements) {
        if (target == null || replacements == null) return;
        int count = Math.min(target.length, replacements.length);
        for (int i = 0; i < count; i++) {
            target[i] = replacements[i] == null ? null : new Signature(replacements[i].toByteArray());
        }
    }

    private static void replaceAppInfoPaths(PackageInfo packageInfo) {
        if (packageInfo == null || sRedirectApkPath == null) return;
        ApplicationInfo ai = packageInfo.applicationInfo;
        if (ai == null) return;
        ai.sourceDir = sRedirectApkPath;
        ai.publicSourceDir = sRedirectApkPath;
        setPathField(ai, "scanSourceDir", sRedirectApkPath);
        setPathField(ai, "scanPublicSourceDir", sRedirectApkPath);
        setPathField(ai, "baseCodePath", sRedirectApkPath);
        setPathField(ai, "baseResourcePath", sRedirectApkPath);
    }

    private static void replacePackageSignatures(String packageName, PackageInfo packageInfo) {
        if (packageInfo == null || packageName == null) return;
        if (!packageName.equals(packageInfo.packageName)) return;
        Signature[] replacements = getOriginalSignatures(packageName);
        if (replacements == null || replacements.length == 0) return;

        // 1) legacy signatures array: replace every element
        if (packageInfo.signatures != null && packageInfo.signatures.length > 0) {
            packageInfo.signatures = cloneSignatures(replacements);
        }

        // 2) signingInfo: apkContentsSigners + certificate history (API 28+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && packageInfo.signingInfo != null) {
            try {
                Signature[] contents = packageInfo.signingInfo.getApkContentsSigners();
                if (contents != null && contents.length > 0) {
                    replaceSignatureArray(contents, replacements);
                }
                Signature[] history = packageInfo.signingInfo.getSigningCertificateHistory();
                if (history != null && history.length > 0) {
                    replaceSignatureArray(history, replacements);
                }
            } catch (Throwable e) {
                Log.w(TAG, "replace signingInfo failed for " + packageName, e);
            }
        }

        // 3) deep: mSigningDetails internal arrays (reflection, best-effort)
        try {
            Object signingInfo = packageInfo.signingInfo;
            if (signingInfo != null) {
                Object details = findField(signingInfo.getClass(), "mSigningDetails").get(signingInfo);
                if (details != null) {
                    try {
                        Object past = findField(details.getClass(), "pastSigningCertificates").get(details);
                        if (past instanceof Signature[]) {
                            Signature[] pastArr = (Signature[]) past;
                            if (pastArr.length > 0) {
                                replaceSignatureArray(pastArr, replacements);
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                    try {
                        Object cur = findField(details.getClass(), "signatures").get(details);
                        if (cur instanceof Signature[]) {
                            Signature[] curArr = (Signature[]) cur;
                            if (curArr.length > 0) {
                                replaceSignatureArray(curArr, replacements);
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }
        } catch (Throwable e) {
            Log.w(TAG, "deep mSigningDetails replace failed for " + packageName, e);

        replaceAppInfoPaths(packageInfo);
        }
    }

    private static boolean pmCertMatches(byte[] cert, int type) {
        if (sPmExpectedCert == null || cert == null) return false;
        try {
            if (type == PackageManager.CERT_INPUT_RAW_X509) {
                return java.security.MessageDigest.isEqual(sPmExpectedCert, cert);
            }
            if (type == PackageManager.CERT_INPUT_SHA256) {
                byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(sPmExpectedCert);
                return java.security.MessageDigest.isEqual(digest, cert);
            }
        } catch (Throwable e) {
            Log.w(TAG, "pmCertMatches failed", e);
        }
        return false;
    }

    private static void installPmProxy(Context ctx) {
        try {
            if (ctx == null || sPmExpectedCert == null || !sPmProxyInstalled.compareAndSet(false, true)) {
                return;
            }
            Object pm = ctx.getPackageManager();
            if (pm == null) return;
            Field mPmField = findField(pm.getClass(), "mPM");
            mPmField.setAccessible(true);
            final Object orig = mPmField.get(pm);
            final Class<?> iPmClass = mPmField.getType();
            final String selfPkg = ctx.getPackageName();
            Object proxy = java.lang.reflect.Proxy.newProxyInstance(
                    ctx.getClass().getClassLoader(),
                    new Class<?>[]{iPmClass},
                    new java.lang.reflect.InvocationHandler() {
                        @Override
                        public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) throws Throwable {
                            String name = method.getName();
                            if (("getPackageInfo".equals(name) || "getApplicationInfo".equals(name))
                                    && ret instanceof PackageInfo && selfPkg.equals(args[0])) {
                                replaceAppInfoPaths((PackageInfo) ret);
                                replacePackageSignatures(selfPkg, (PackageInfo) ret);
                            }
                            if ("hasSigningCertificate".equals(name)
                                    && args != null && args.length >= 3
                                    && args[0] instanceof String
                                    && selfPkg.equals(args[0])
                                    && args[1] instanceof byte[]
                                    && args[2] instanceof Integer) {
                                if (pmCertMatches((byte[]) args[1], (Integer) args[2])) {
                                    Log.w(TAG, "PmProxy: hasSigningCertificate -> true for " + selfPkg);
                                    return Boolean.TRUE;
                                }
                            }
                            Object ret = method.invoke(orig, args);
                            return ret;
                        }
                    });
            mPmField.set(pm, proxy);
            try {
                Class<?> atClass = Class.forName("android.app.ActivityThread");
                java.lang.reflect.Field s = null;
                Class<?> sc = atClass;
                while (sc != null) {
                    try {
                        s = sc.getDeclaredField("sPackageManager");
                        break;
                    } catch (NoSuchFieldException e) {
                        sc = sc.getSuperclass();
                    }
                }
                if (s != null) {
                    s.setAccessible(true);
                    s.set(null, proxy);
                }
            } catch (Throwable ignored) {
            }
            Log.w(TAG, "PmProxy installed");
        } catch (Throwable t) {
            Log.w(TAG, "installPmProxy failed", t);
        }
    }

    private static void setPathField(ApplicationInfo ai, String field, String path) {
        try {
            findField(ApplicationInfo.class, field).set(ai, path);
        } catch (Throwable ignored) {
        }
    }

    private static void redirectApkPaths(Context ctx) {
        try {
            File repFile = new File(ctx.getDataDir(), "signed.apk");
            if (!repFile.isFile() || repFile.length() <= 0) return;
            final String target = repFile.getAbsolutePath();

            ApplicationInfo ai = ctx.getApplicationInfo();
            ai.sourceDir = target;
            ai.publicSourceDir = target;
            setPathField(ai, "scanSourceDir", target);
            setPathField(ai, "scanPublicSourceDir", target);
            setPathField(ai, "baseCodePath", target);
            setPathField(ai, "baseResourcePath", target);

            Class<?> atClass = Class.forName("android.app.ActivityThread");
            java.lang.reflect.Method cm = atClass.getDeclaredMethod("currentActivityThread");
            cm.setAccessible(true);
            Object at = cm.invoke(null);
            if (at == null) return;

            try {
                Object bound = findField(atClass, "mBoundApplication").get(at);
                if (bound != null) {
                    Object loadedApk = findField(bound.getClass(), "info").get(bound);
                    if (loadedApk != null) {
                        findField(loadedApk.getClass(), "mResDir").set(loadedApk, target);
                        Log.w(TAG, "redirectApkPaths: LoadedApk.mResDir -> " + target);
                        try {
                            findField(loadedApk.getClass(), "mCodePath").set(loadedApk, target);
                        } catch (Throwable ignored) {
                        }
                        try {
                            findField(loadedApk.getClass(), "mAppDir").set(loadedApk, target);
                        } catch (Throwable ignored) {
                        }
                        try {
                            Object lai = findField(loadedApk.getClass(), "mApplicationInfo").get(loadedApk);
                            if (lai instanceof ApplicationInfo) {
                                ApplicationInfo laAppInfo = (ApplicationInfo) lai;
                                laAppInfo.sourceDir = target;
                                laAppInfo.publicSourceDir = target;
                            }
                        } catch (Throwable ignored) {
                        }
                    }
                }
            } catch (Throwable ignored) {
            }

            try {
                Object all = findField(atClass, "mAllApplications").get(at);
                if (all instanceof java.util.List) {
                    for (Object appObj : (java.util.List<?>) all) {
                        try {
                            Object base = findField(appObj.getClass(), "mBase").get(appObj);
                            if (base != null) {
                                Object pi = findField(base.getClass(), "mPackageInfo").get(base);
                                if (pi != null) {
                                    findField(pi.getClass(), "mResDir").set(pi, target);
                                    try {
                                        findField(pi.getClass(), "mCodePath").set(pi, target);
                                    } catch (Throwable ignored) {
                                    }
                                    try {
                                        findField(pi.getClass(), "mAppDir").set(pi, target);
                                    } catch (Throwable ignored) {
                                    }
                                }
                            }
                        } catch (Throwable ignored) {
                        }
                    }
                }
            } catch (Throwable ignored) {
            }
        } catch (Throwable t) {
            Log.w(TAG, "redirectApkPaths failed", t);
        }
    }

    private static void killPM(String packageName) {
        Parcelable.Creator<PackageInfo> originalCreator = PackageInfo.CREATOR;
        Parcelable.Creator<PackageInfo> creator = new Parcelable.Creator<PackageInfo>() {
            @Override
            public PackageInfo createFromParcel(Parcel source) {
                PackageInfo packageInfo = originalCreator.createFromParcel(source);
                try {
                    replacePackageSignatures(packageName, packageInfo);
                } catch (Throwable t) {
                    Log.w(TAG, "createFromParcel replace failed", t);
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
