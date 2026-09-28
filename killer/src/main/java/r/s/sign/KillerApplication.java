package r.s.sign;

import android.annotation.SuppressLint;
import android.app.Application;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Environment;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.Base64;

import org.lsposed.hiddenapibypass.HiddenApiBypass;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class KillerApplication extends Application {
    public static final String URL = "https://github.com/L-JINBIN/ApkSignatureKillerEx";

    static {
        // Replace the following package name with your own
        String packageName = "r.s.sign";
        // Replace the following signature data with your own
                String signatureData = "MIIDBDCCAeygAwIBAgIJAKUYjx3CbzZUMA0GCSqGSIb3DQEBCwUAMC8xCzAJBgNVBAYTAlVTMQ8w\n" +
                "DQYDVQQKEwZPcmlnaW4xDzANBgNVBAMTBk9yaWdpbjAgFw0yNjA5MjgxMDU5NDVaGA8yMDU0MDIx\n" +
                "MzEwNTk0NVowLzELMAkGA1UEBhMCVVMxDzANBgNVBAoTBk9yaWdpbjEPMA0GA1UEAxMGT3JpZ2lu\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArYANZDTR8oCtl0zZum80EM0isoBKW2Ka\n" +
                "nTo0rK7d6Ueju8CebRfCVIFy561tM2C0wWr9ZnW1wBpdKNfjwfI65bixiNs3yFVzBOsRt5aa5roC\n" +
                "TeZx6dXTXv1WkJvKbY2ixgvS9lKyunUktQBZaMNJHRlPckJ7T4zevGi3tcB4zLwJ21ZOe8j6rQcM\n" +
                "8FLubhwTOHyG+zyjxVeNyXz7+qu8I+zTVKMoMvOSSstRmgV0cUiJuCpH1voMzcfwYc6l/ak0/dWS\n" +
                "pOs+/m6vu6XabVDCDjAigO2lsyBMnhsC9orh2qxfUBnahY4tGQI+yJ6qHpmy+JJzJnujO00/sXmy\n" +
                "wUnJuwIDAQABoyEwHzAdBgNVHQ4EFgQUndwSFLnD4NOLc56aB6O5KGi1e1AwDQYJKoZIhvcNAQEL\n" +
                "BQADggEBADR0nEcy+jIhjpbBVialX8HZFHcHEa0Q7AWAOK4SAfkEXiLH3NGc5xOTucahCzNuyxjz\n" +
                "X1QUgIzW1Zf9qFceMW6UZWd+WHWoZmEIwQH9iW9aMRzjpF9XnWpHVRgaHc/nEbMG/0KFrPZFKeSd\n" +
                "5OiEqoE1h+jv/XYQPJ+/rMidHOybg+lU8HDk0Gq/xWZO9Pfh8EpzenJErlT9TAx+hnO9EkCKDViF\n" +
                "Cq3w5JE2vmfiyWLlsgCb+zPeD0B577GlJzrroQEmlp0npk71dDAzCTn/1QUyWJlgOzQLRYXbLc89\n" +
                "sfXP9V4RWj4JHlJll4V85WkGesaHdWsajf4Ac/fJ44ufgTc=";
        killPM(packageName, signatureData);
        killOpen(packageName);
    }

    private static void killPM(String packageName, String signatureData) {
        Signature fakeSignature = new Signature(Base64.decode(signatureData, Base64.DEFAULT));
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

    public static String repPath() {
        String pkg = "r.s.sign";
        File f = new File(getDataFile(pkg), "origin.apk");
        return f.exists() ? f.getAbsolutePath() : null;
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
        File apkFile = new File(apkPath);
        File repFile = new File(getDataFile(packageName), "origin.apk");
        try (ZipFile zipFile = new ZipFile(apkFile)) {
            String name = "assets/SignedByRS/origin.apk";
            ZipEntry entry = zipFile.getEntry(name);
            if (entry == null) {
                System.err.println("Entry not found: " + name);
                return;
            }
            if (!repFile.exists() || repFile.length() != entry.getSize()) {
                try (InputStream is = zipFile.getInputStream(entry); OutputStream os = new FileOutputStream(repFile)) {
                    byte[] buf = new byte[102400];
                    int len;
                    while ((len = is.read(buf)) != -1) {
                        os.write(buf, 0, len);
                    }
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        hookApkPath(apkFile.getAbsolutePath(), repFile.getAbsolutePath());
    }

    @SuppressLint("SdCardPath")
    private static File getDataFile(String packageName) {
        String username = Environment.getExternalStorageDirectory().getName();
        if (username.matches("\\d+")) {
            File file = new File("/data/user/" + username + "/" + packageName);
            if (file.canWrite()) {
                return file;
            }
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

    public static native void refreshHooks();

    public static native byte[] probeFopen(String path);

    public static native String probeStat(String path);

    public static native String probePaths(String path);

    /** Normal = 经普通 open 读（应被洗白）；Raw = 原始 syscall 直读（负对照） */
    public static native String probeMaps(boolean raw);

    public static native String probeFds();

    public static native String probeDlIterate(boolean raw);
}

