package r.s.sign;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 将内嵌原包稳定解包到 dataDir/signed.apk：
 * 1. 严格 CRC 校验：包体一旦更新，坚决干净清除并解包新包，绝不复用旧文件；
 * 2. 彻底移除 markReadOnly，避免 Android/Linux 权限锁死导致的覆盖更新失败；
 * 3. 采用 512KB 缓冲区，移除卡死的 sync() 保证冷启动秒开。
 */
public final class OriginApkCache {

    private static final String TAG = "OriginApkCache";
    private static final String ASSET_PATH = "Zcraft/input.apk";
    private static final String ASSET_PATH_LEGACY = "SignedByRS/input.apk";
    private static final String TARGET_NAME = "signed.apk";
    private static final String VERIFIED_SUFFIX = ".verified";
    private static final long LOCK_TIMEOUT_MS = 10_000L;
    private static final int BUFFER_SIZE = 524288; // 512KB

    private OriginApkCache() {}

    public static String prepare(Context context) {
        if (context == null) return null;
        File dataDir = context.getDataDir();
        if (dataDir == null) return null;
        File target = new File(dataDir, TARGET_NAME);

        long assetCrc = getAssetCrc(context);
        // 快速自检：只有完全吻合才复用
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
                // 二次校验锁内状态
                if (isValidCached(target, assetCrc)) {
                    return target.getAbsolutePath();
                }

                Log.i(TAG, "检测到新版安装包或缓存失效，正在干净重新解包原包...");

                // 1. 彻底清除旧缓存与凭证，并先恢复写权限防 EACCES 锁死
                cleanFile(target);
                cleanFile(new File(dataDir, TARGET_NAME + VERIFIED_SUFFIX));

                // 2. 解包到 pid 专属临时文件
                File tmp = new File(dataDir, TARGET_NAME + ".tmp." + android.os.Process.myPid());
                cleanFile(tmp);

                InputStream is = null;
                try {
                    try {
                        is = context.getAssets().open(ASSET_PATH);
                    } catch (IOException e) {
                        is = context.getAssets().open(ASSET_PATH_LEGACY);
                    }

                    try (FileOutputStream fos = new FileOutputStream(tmp)) {
                        byte[] buf = new byte[BUFFER_SIZE];
                        int len;
                        while ((len = is.read(buf)) > 0) {
                            fos.write(buf, 0, len);
                        }
                        fos.flush();
                    }
                } finally {
                    if (is != null) {
                        try { is.close(); } catch (Throwable ignored) {}
                    }
                }

                // 3. 校验解包临时文件有效性
                if (!isZipWithManifest(tmp)) {
                    Log.e(TAG, "解包产物损坏，取消替换并清理临时文件");
                    cleanFile(tmp);
                    return null;
                }

                // 4. 原子重命名替换
                cleanFile(target);
                if (!tmp.renameTo(target)) {
                    Log.w(TAG, "renameTo 失败，降级为文件流对拷");
                    copyFile(tmp, target);
                    cleanFile(tmp);
                }

                // 5. 确保标准读写权限，绝不调用 markReadOnly() 避免权限锁死
                ensureWritable(target);

                // 6. 写入新版校验凭证
                writeVerifiedSidecar(target, assetCrc);
                Log.i(TAG, "新版原包解包就绪: " + target.getAbsolutePath());
                return target.getAbsolutePath();

            } finally {
                if (lock != null) {
                    try { lock.release(); } catch (IOException ignored) {}
                }
            }
        } catch (Throwable e) {
            Log.e(TAG, "prepare failed", e);
            return null;
        }
    }

    private static long getAssetCrc(Context context) {
        String apkPath = context.getPackageResourcePath();
        if (apkPath == null || !new File(apkPath).isFile()) {
            apkPath = context.getApplicationInfo().sourceDir;
        }
        if (apkPath == null || !new File(apkPath).isFile()) return 0;

        try (ZipFile zip = new ZipFile(apkPath)) {
            ZipEntry entry = zip.getEntry(ASSET_PATH);
            if (entry == null) entry = zip.getEntry(ASSET_PATH_LEGACY);
            return entry != null ? entry.getCrc() : 0;
        } catch (Throwable e) {
            Log.w(TAG, "getAssetCrc failed", e);
            return 0;
        }
    }

    /**
     * 严格缓存判定：
     * 只有当凭据完全匹配、CRC 一致、且文件合法时才返回 true。
     * 一旦 CRC 不匹配（安装包更新），坚决返回 false！
     */
    private static boolean isValidCached(File target, long expectedCrc) {
        if (target == null || !target.isFile() || target.length() <= 0 || expectedCrc <= 0) {
            return false;
        }
        File verified = new File(target.getParentFile(), TARGET_NAME + VERIFIED_SUFFIX);
        if (!verified.isFile()) {
            return false;
        }
        try {
            String expected = expectedCrc + ":" + target.lastModified() + ":" + target.length();
            String stamp = new String(java.nio.file.Files.readAllBytes(verified.toPath()),
                    java.nio.charset.StandardCharsets.UTF_8).trim();
            if (expected.equals(stamp)) {
                return isZipWithManifest(target);
            }
        } catch (Throwable ignored) {}
        return false;
    }

    private static boolean isZipWithManifest(File file) {
        if (file == null || !file.isFile() || file.length() <= 0) return false;
        try (ZipFile zip = new ZipFile(file)) {
            return zip.getEntry("AndroidManifest.xml") != null;
        } catch (Throwable e) {
            return false;
        }
    }

    private static void writeVerifiedSidecar(File target, long crc) {
        try {
            String stamp = crc + ":" + target.lastModified() + ":" + target.length();
            File verified = new File(target.getParentFile(), TARGET_NAME + VERIFIED_SUFFIX);
            cleanFile(verified);
            java.nio.file.Files.write(verified.toPath(),
                    stamp.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.TRUNCATE_EXISTING,
                    java.nio.file.StandardOpenOption.WRITE);
            ensureWritable(verified);
        } catch (Throwable e) {
            Log.w(TAG, "Failed to write verified sidecar", e);
        }
    }

    private static void cleanFile(File file) {
        if (file == null || !file.exists()) return;
        try {
            // 先赋写权限，杜绝因历史只读残留导致无法删除
            //noinspection ResultOfMethodCallIgnored
            file.setWritable(true, false);
            //noinspection ResultOfMethodCallIgnored
            file.delete();
        } catch (Throwable ignored) {}
    }

    private static void ensureWritable(File file) {
        if (file == null || !file.exists()) return;
        try {
            //noinspection ResultOfMethodCallIgnored
            file.setReadable(true, false);
            //noinspection ResultOfMethodCallIgnored
            file.setWritable(true, false);
        } catch (Throwable ignored) {}
    }

    private static void copyFile(File src, File dst) throws IOException {
        try (InputStream in = new FileInputStream(src);
             OutputStream out = new FileOutputStream(dst)) {
            byte[] buf = new byte[BUFFER_SIZE];
            int len;
            while ((len = in.read(buf)) > 0) {
                out.write(buf, 0, len);
            }
            out.flush();
        }
    }

    public static boolean exists(Context context) {
        if (context == null || context.getDataDir() == null) return false;
        return new File(context.getDataDir(), TARGET_NAME).isFile();
    }
}
