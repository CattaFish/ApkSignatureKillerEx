package r.s.sign;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.os.Build;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

public class OriginApkCache {
    private static final String TAG = "OriginApkCache";
    public static final String TARGET_NAME = "signed.apk";
    private static final String SP_NAME = "origin_apk_cache_meta";
    private static final String KEY_VERSION = "apk_version_key";
    private static final String KEY_ENTRY_PATH = "origin_entry_path";

    public static synchronized String prepare(Context context) {
        if (context == null) return null;
        Context ctx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        
        File target = getTargetApkFile(ctx);
        String currentVersion = getCurrentAppVersion(ctx);

        if (isCacheValid(ctx, target, currentVersion)) {
            Log.i(TAG, "[优化命中] 原包缓存有效 (" + (target.length() / 1024 / 1024) + "MB)，直接复用");
            return target.getAbsolutePath();
        }

        Log.i(TAG, "检测到新版安装包或缓存失效，正在动态检索原包并解压...");
        boolean success = extractOriginApkSafely(ctx, target);
        if (success && target.isFile() && target.length() > 0) {
            saveAppVersion(ctx, currentVersion);
            Log.i(TAG, "原包解压成功并锁定缓存: " + target.getAbsolutePath());
            return target.getAbsolutePath();
        }

        return target.exists() ? target.getAbsolutePath() : null;
    }

    private static File getTargetApkFile(Context ctx) {
        File dir = ctx.getDataDir();
        if (dir == null || !dir.exists()) dir = ctx.getFilesDir();
        return new File(dir, TARGET_NAME);
    }

    private static String getCurrentAppVersion(Context ctx) {
        try {
            PackageInfo pi = ctx.getPackageManager().getPackageInfo(ctx.getPackageName(), 0);
            long vc = Build.VERSION.SDK_INT >= 28 ? pi.getLongVersionCode() : pi.versionCode;
            return (pi.versionName != null ? pi.versionName : "") + "#" + vc;
        } catch (Throwable t) {
            return "unknown";
        }
    }

    private static boolean isCacheValid(Context ctx, File target, String currentVersion) {
        if (target == null || !target.isFile() || target.length() <= 0) {
            return false;
        }
        SharedPreferences sp = ctx.getSharedPreferences(SP_NAME, Context.MODE_PRIVATE);
        String savedVersion = sp.getString(KEY_VERSION, "");
        return currentVersion.equals(savedVersion);
    }

    private static void saveAppVersion(Context ctx, String version) {
        try {
            ctx.getSharedPreferences(SP_NAME, Context.MODE_PRIVATE)
               .edit().putString(KEY_VERSION, version).commit();
        } catch (Throwable ignored) {}
    }

    private static boolean extractOriginApkSafely(Context ctx, File target) {
        File tmpFile = new File(target.getParentFile(), TARGET_NAME + ".tmp." + android.os.Process.myPid());
        if (tmpFile.exists()) tmpFile.delete();

        String baseApk = ctx.getPackageResourcePath();
        SharedPreferences sp = ctx.getSharedPreferences(SP_NAME, Context.MODE_PRIVATE);

        try (ZipFile zip = new ZipFile(new File(baseApk))) {
            ZipEntry matchedEntry = null;

            // 1. 优先读取上一次探测到的随机路径（0ms 命中）
            String cachedName = sp.getString(KEY_ENTRY_PATH, null);
            if (cachedName != null) {
                matchedEntry = zip.getEntry(cachedName);
            }

            // 2. 兼容历史遗留路径（过渡兜底）
            if (matchedEntry == null) {
                String[] legacy = new String[]{"assets/Zcraft/input.apk", "Zcraft/input.apk", "assets/input.apk", "input.apk"};
                for (String p : legacy) {
                    ZipEntry e = zip.getEntry(p);
                    if (e != null) {
                        matchedEntry = e;
                        break;
                    }
                }
            }

            // 3. 全动态无特征嗅探：遍历 assets/ 下大于 500KB 且包含 AndroidManifest.xml 的 ZIP
            if (matchedEntry == null) {
                Enumeration<? extends ZipEntry> entries = zip.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    String name = entry.getName();
                    if (name.startsWith("assets/") && entry.getSize() > 500 * 1024) {
                        if (isOriginApkEntry(zip, entry)) {
                            matchedEntry = entry;
                            sp.edit().putString(KEY_ENTRY_PATH, name).apply();
                            Log.i(TAG, "已动态锁定随机原包资产: " + name + " (" + (entry.getSize() / 1024 / 1024) + "MB)");
                            break;
                        }
                    }
                }
            }

            if (matchedEntry == null) {
                Log.e(TAG, "未在安装包中定位到任何内嵌原包！");
                return false;
            }

            try (InputStream is = zip.getInputStream(matchedEntry);
                 FileOutputStream fos = new FileOutputStream(tmpFile)) {
                byte[] buf = new byte[65536];
                int len;
                while ((len = is.read(buf)) != -1) {
                    fos.write(buf, 0, len);
                }
                fos.flush();
            }

            if (target.exists()) target.delete();
            boolean renamed = tmpFile.renameTo(target);
            if (!renamed) {
                tmpFile.renameTo(target);
            }
            return target.isFile() && target.length() > 0;
        } catch (Throwable t) {
            Log.e(TAG, "解包原包异常", t);
            if (tmpFile.exists()) tmpFile.delete();
            return false;
        }
    }

    private static boolean isOriginApkEntry(ZipFile zip, ZipEntry entry) {
        try (InputStream is = zip.getInputStream(entry)) {
            byte[] magic = new byte[4];
            if (is.read(magic) != 4) return false;
            if (magic[0] != 0x50 || magic[1] != 0x4B || magic[2] != 0x03 || magic[3] != 0x04) {
                return false;
            }
        } catch (Throwable ignored) {
            return false;
        }

        try (ZipInputStream zis = new ZipInputStream(zip.getInputStream(entry))) {
            ZipEntry sub;
            int count = 0;
            while ((sub = zis.getNextEntry()) != null && count < 25) {
                count++;
                if ("AndroidManifest.xml".equals(sub.getName())) {
                    return true;
                }
            }
        } catch (Throwable ignored) {}
        return false;
    }
}
