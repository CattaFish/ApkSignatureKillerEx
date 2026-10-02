package r.s.sign;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 把 assets/SignedByRS/input.apk（原始 APK）稳定解包到 dataDir/signed.apk。
 * 与旧实现（exists && length>0 即复用）的区别：
 *  - 跨进程 FileLock，避免多进程同时写同一个 signed.apk；
 *  - 先写同目录临时文件，校验通过后原子替换目标；
 *  - sidecar 记录 mtime:size，命中则跳过 ZipFile 校验。
 * 使用方（KillerApplication.killOpen）仍按 dataDir/signed.apk 读取，路径不改变。
 */
public final class OriginApkCache {

    private static final String TAG = "OriginApkCache";
    private static final String ASSET_PATH = "Zcraft/input.apk";
    private static final String TARGET_NAME = "signed.apk";
    private static final String VERIFIED_SUFFIX = ".verified";
    private static final long LOCK_TIMEOUT_MS = 10_000L;

    private OriginApkCache() {}

    /**
     * 确保 dataDir/signed.apk 存在且有效，返回其绝对路径；失败返回 null。
     */
    public static String prepare(Context context) {
        if (context == null) return null;
        File dataDir = context.getDataDir();
        if (dataDir == null) return null;
        File target = new File(dataDir, TARGET_NAME);

        long assetCrc = getAssetCrc(context);
        // 快路径：sidecar 命中且 CRC 与当前内嵌 input 一致才复用
        if (isValidCached(target, assetCrc)) {
            return target.getAbsolutePath();
        }

        File lockFile = new File(dataDir, TARGET_NAME + ".lock");
        try (FileChannel channel = FileChannel.open(lockFile.toPath(),
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.WRITE)) {
            FileLock lock = null;
            long deadline = System.currentTimeMillis() + LOCK_TIMEOUT_MS;
            while (lock == null) {
                try {
                    lock = channel.tryLock();
                } catch (IOException e) {
                    Log.w(TAG, "tryLock threw, proceeding without lock", e);
                    break;
                }
                if (lock == null) {
                    if (System.currentTimeMillis() >= deadline) {
                        Log.w(TAG, "lock timeout, proceeding without lock (degraded)");
                        break;
                    }
                    try {
                        Thread.sleep(50L);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }

            try {
                if (isValidCached(target, assetCrc)) {
                    return target.getAbsolutePath();
                }

                File tmp = new File(dataDir, TARGET_NAME + ".tmp." + android.os.Process.myPid());
                try (InputStream is = context.getAssets().open(ASSET_PATH);
                     FileOutputStream fos = new FileOutputStream(tmp)) {
                    byte[] buf = new byte[524288];
                    int len;
                    while ((len = is.read(buf)) > 0) {
                        fos.write(buf, 0, len);
                    }
                    fos.flush();
                    // fos.getFD().sync(); 移除闪存主线程强制同步，彻底消除冷启动卡顿
                }

                if (!isZipWithManifest(tmp)) {
                    Log.e(TAG, "Extracted tmp is not a valid APK, aborting");
                    //noinspection ResultOfMethodCallIgnored
                    tmp.delete();
                    return null;
                }

                File verified = new File(dataDir, TARGET_NAME + VERIFIED_SUFFIX);
                //noinspection ResultOfMethodCallIgnored
                target.delete();
                if (!tmp.renameTo(target)) {
                    Log.e(TAG, "renameTo failed for " + target);
                    //noinspection ResultOfMethodCallIgnored
                    tmp.delete();
                    return null;
                }

                writeVerifiedSidecar(target, assetCrc);
                markReadOnly(target);
                return target.getAbsolutePath();
            } finally {
                if (lock != null) {
                    try {
                        lock.release();
                    } catch (IOException ignored) {
                    }
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "prepare failed", e);
            return null;
        }
    }

    private static long getAssetCrc(Context context) {
        try (ZipFile zip = new ZipFile(context.getPackageResourcePath())) {
            ZipEntry entry = zip.getEntry(ASSET_PATH);
            return entry != null ? entry.getCrc() : 0;
        } catch (IOException e) {
            Log.w(TAG, "getAssetCrc failed", e);
            return 0;
        }
    }

    private static boolean isValidCached(File target, long expectedCrc) {
        if (target == null || !target.isFile() || target.length() <= 0) {
            return false;
        }
        try {
            long mtime = target.lastModified();
            long size = target.length();
            String expected = expectedCrc + ":" + mtime + ":" + size;

            File verified = new File(target.getParentFile(), TARGET_NAME + VERIFIED_SUFFIX);
            if (verified.isFile()) {
                String stamp = new String(java.nio.file.Files.readAllBytes(verified.toPath()),
                        java.nio.charset.StandardCharsets.UTF_8).trim();
                if (expected.equals(stamp)) {
                    return true;
                }
            }
        } catch (IOException ignored) {
        }

        if (!isZipWithManifest(target)) {
            return false;
        }
        writeVerifiedSidecar(target, expectedCrc);
        markReadOnly(target);
        return true;
    }

    private static boolean isZipWithManifest(File file) {
        try (ZipFile zip = new ZipFile(file)) {
            ZipEntry entry = zip.getEntry("AndroidManifest.xml");
            return entry != null;
        } catch (Throwable e) {
            Log.w(TAG, "isZipWithManifest failed: " + file, e);
            return false;
        }
    }

    private static void writeVerifiedSidecar(File target, long crc) {
        try {
            String stamp = crc + ":" + target.lastModified() + ":" + target.length();
            File verified = new File(target.getParentFile(), TARGET_NAME + VERIFIED_SUFFIX);
            java.nio.file.Files.write(verified.toPath(),
                    stamp.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.TRUNCATE_EXISTING,
                    java.nio.file.StandardOpenOption.WRITE);
        } catch (IOException e) {
            Log.w(TAG, "Failed to write verified sidecar", e);
        }
    }

    private static void markReadOnly(File file) {
        try {
            //noinspection ResultOfMethodCallIgnored
            file.setReadOnly();
        } catch (Throwable ignored) {
        }
    }

    /** 仅供 KillerApplication 判断 signed.apk 是否存在（保持旧行为）。 */
    public static boolean exists(Context context) {
        if (context == null || context.getDataDir() == null) return false;
        return new File(context.getDataDir(), TARGET_NAME).isFile();
    }
}
