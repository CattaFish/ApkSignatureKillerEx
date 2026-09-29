#include <jni.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__aarch64__) || defined(__x86_64__)
#define RAW_STAT __NR_newfstatat
#else
#define RAW_STAT __NR_fstatat64
#endif

static int raw_open(const char *path) {
    return (int)syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
}

static char *raw_read_fd(int fd) {
    size_t cap = 8192, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;
    while (1) {
        if (len + 4096 >= cap) {
            cap *= 2;
            char *g = (char *)realloc(buf, cap);
            if (!g) { free(buf); return NULL; }
            buf = g;
        }
        ssize_t n = syscall(__NR_read, fd, buf + len, cap - len - 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf); return NULL;
        }
        if (n == 0) break;
        len += (size_t)n;
    }
    buf[len] = '\0';
    return buf;
}

static char *raw_readlink(const char *path) {
    size_t cap = 256;
    while (cap <= 65536) {
        char *buf = (char *)malloc(cap + 1);
        if (!buf) return NULL;
        ssize_t n = syscall(__NR_readlinkat, AT_FDCWD, path, buf, cap);
        if (n < 0) { free(buf); return NULL; }
        if ((size_t)n < cap) { buf[n] = '\0'; return buf; }
        free(buf);
        cap *= 2;
    }
    return NULL;
}

static char *read_file(const char *path, int raw) {
    int fd = raw ? raw_open(path) : open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    char *buf = raw_read_fd(fd);
    syscall(__NR_close, fd);
    return buf;
}

JNIEXPORT jbyteArray JNICALL
Java_r_s_test_NativeDetector_probeFopen(JNIEnv *env, jclass clazz, jstring jpath) {
    (void)clazz;
    if (jpath == NULL) return NULL;
    const char *path = (*env)->GetStringUTFChars(env, jpath, NULL);
    if (!path) return NULL;
    FILE *fp = fopen(path, "r");
    if (!fp) { (*env)->ReleaseStringUTFChars(env, jpath, path); return NULL; }
    size_t cap = 65536, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) { fclose(fp); (*env)->ReleaseStringUTFChars(env, jpath, path); return NULL; }
    while (1) {
        size_t rd = fread(buf + len, 1, cap - len - 1, fp);
        len += rd;
        if (rd == 0) break;
        if (len + 65536 >= cap) {
            cap *= 2;
            char *g = (char *)realloc(buf, cap);
            if (!g) { free(buf); fclose(fp); (*env)->ReleaseStringUTFChars(env, jpath, path); return NULL; }
            buf = g;
        }
    }
    fclose(fp);
    jbyteArray out = (*env)->NewByteArray(env, (jsize)len);
    if (out) (*env)->SetByteArrayRegion(env, out, 0, (jsize)len, (const jbyte *)buf);
    free(buf);
    (*env)->ReleaseStringUTFChars(env, jpath, path);
    return out;
}

JNIEXPORT jstring JNICALL
Java_r_s_test_NativeDetector_probeStat(JNIEnv *env, jclass clazz, jstring jpath) {
    (void)clazz;
    if (jpath == NULL) return (*env)->NewStringUTF(env, "ERR:null");
    const char *path = (*env)->GetStringUTFChars(env, jpath, NULL);
    if (!path) return (*env)->NewStringUTF(env, "ERR:oom");
    char out[1024];
    out[0] = '\0';
    struct stat st;
    memset(&st, 0, sizeof(st));
    if (stat(path, &st) == 0) {
        snprintf(out, sizeof(out), "normal: dev=%lx ino=%lu size=%ld",
                 (unsigned long)st.st_dev, (unsigned long)st.st_ino, (long)st.st_size);
    } else {
        snprintf(out, sizeof(out), "normal: ERR errno=%d", errno);
    }
    memset(&st, 0, sizeof(st));
    if (syscall(RAW_STAT, AT_FDCWD, path, &st, 0) == 0) {
        char part[512];
        snprintf(part, sizeof(part), " | raw: dev=%lx ino=%lu size=%ld",
                 (unsigned long)st.st_dev, (unsigned long)st.st_ino, (long)st.st_size);
        strncat(out, part, sizeof(out) - strlen(out) - 1);
    } else {
        strncat(out, " | raw: ERR", sizeof(out) - strlen(out) - 1);
    }
    (*env)->ReleaseStringUTFChars(env, jpath, path);
    return (*env)->NewStringUTF(env, out);
}

JNIEXPORT jstring JNICALL
Java_r_s_test_NativeDetector_probeMaps(JNIEnv *env, jclass clazz, jboolean raw) {
    (void)clazz;
    char *content = read_file("/proc/self/maps", raw == JNI_TRUE);
    if (!content) return (*env)->NewStringUTF(env, "ERR:read");
    jstring out = (*env)->NewStringUTF(env, content);
    free(content);
    return out;
}

JNIEXPORT jstring JNICALL
Java_r_s_test_NativeDetector_probeFds(JNIEnv *env, jclass clazz) {
    (void)clazz;
    static char out[16384];
    char fd_path[64];
    size_t used = 0;
    out[0] = '\0';
    for (int fd = 0; fd < 1024; ++fd) {
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
        char *target = raw_readlink(fd_path);
        if (!target) continue;
        int n = snprintf(out + used, sizeof(out) - used, "fd=%d -> %s\n", fd, target);
        if (n > 0 && (size_t)n < sizeof(out) - used) used += (size_t)n;
        free(target);
        if (used >= sizeof(out) - 256) break;
    }
    return (*env)->NewStringUTF(env, out);
}
