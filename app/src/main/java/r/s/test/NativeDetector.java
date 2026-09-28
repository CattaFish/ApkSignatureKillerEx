package r.s.test;

public final class NativeDetector {
    static {
        System.loadLibrary("test");
    }

    private NativeDetector() {}

    public static native byte[] probeFopen(String path);

    public static native String probeStat(String path);

    public static native String probeMaps(boolean raw);

    public static native String probeFds();
}
