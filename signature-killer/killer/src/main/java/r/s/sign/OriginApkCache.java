package r.s.sign;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.os.Build;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class OriginApkCache {
    private static final String TAG = "OriginApkCache";
    public static final String TARGET_NAME = "signed.apk";
    private static final String SP_NAME = "origin_apk_cache_meta";
    private static final String KEY_VERSION = "apk_version_key";

    /**
     * 核心入口：优先秒级命中缓存；仅在首次安装或升级新版 QQ 时触发解包
     */
    public static synchronized String prepare(Context context) {
        if (context == null) return null;
        Context ctx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        
        File target = getTargetApkFile(ctx);
        String currentVersion = getCurrentAppVersion(ctx);

        // 1. [秒级命中缓存] 目标文件完整且版本一致时，0ms 直接返回！
        if (isCacheValid(ctx, target, currentVersion)) {
            Log.i(TAG, "[优化命中] 原包缓存有效 (" + (target.length() / 1024 / 1024) + "MB, 版本:" + currentVersion + ")，直接复用，免去解包！");
            return target.getAbsolutePath();
        }

        // 2. [需要全新解压] 仅限首次安装或覆盖升级 QQ
        Log.i(TAG, "检测到新版安装包或缓存失效，正在干净重新解包原包...");
        boolean success = extractOriginApkSafely(ctx, target);
        if (success && target.isFile() && target.length() > 0) {
            // 3. 成功落盘后才记录版本号，中途被杀不记录，保证下次自愈
            saveAppVersion(ctx, currentVersion);
            Log.i(TAG, "原包解压成功并已锁定缓存: " + target.getAbsolutePath());
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
        if (target == null || !target.isFile() || target.length() < 30 * 1024 * 1024) {
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

    /**
     * 原子安全解包：通过临时文件写入，写完再重命名，彻底防范中途强杀导致文件残损
     */
    private static boolean extractOriginApkSafely(Context ctx, File target) {
        File tmpFile = new File(target.getParentFile(), TARGET_NAME + ".tmp." + android.os.Process.myPid());
        if (tmpFile.exists()) tmpFile.delete();

        // 尝试两种渠道读取原包：1. Assets (Zcraft/input.apk)  2. 直接从自身 APK 提取
        try (InputStream is = openOriginApkStream(ctx)) {
            if (is == null) {
                Log.e(TAG, "无法找到内嵌的官方原包资产 (input.apk)！");
                return false;
            }
            try (FileOutputStream fos = new FileOutputStream(tmpFile)) {
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
                // 某些机型 renameTo 失败时的保底移动
                tmpFile.renameTo(target);
            }
            return target.isFile() && target.length() > 0;
        } catch (Throwable t) {
            Log.e(TAG, "解包原包异常", t);
            if (tmpFile.exists()) tmpFile.delete();
            return false;
        }
    }

    private static InputStream openOriginApkStream(Context ctx) {
        // 途径 A: 直接通过 AssetsManager 打开
        String[] possibleAssets = new String[]{"assets/Zcraft/input.apk", "Zcraft/input.apk", "assets/input.apk", "input.apk"};
        for (String p : possibleAssets) {
            try {
                InputStream is = ctx.getAssets().open(p);
                if (is != null) return is;
            } catch (Throwable ignored) {}
        }

        // 途径 B: 穿透式从宿主实际安装包中直接读取 ZipEntry
        try {
            String baseApk = ctx.getPackageResourcePath();
            ZipFile zip = new ZipFile(new File(baseApk));
            for (String p : possibleAssets) {
                ZipEntry entry = zip.getEntry(p);
                if (entry != null) {
                    return zip.getInputStream(entry);
                }
            }
        } catch (Throwable ignored) {}

        return null;
    }
}
