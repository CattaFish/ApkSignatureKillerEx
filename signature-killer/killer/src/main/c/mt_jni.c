#include <jni.h>
#include <link.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <stdbool.h>
#include <errno.h>
#include <linux/stat.h>
#include <sys/statfs.h>
#include <sys/vfs.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "xhook.h"
#include "xh_log.h"
#include "sigbypass_core.h"
#include <dlfcn.h>

/* ================= Step 4: path family ================= */
static int (*old_access)(const char *, int);
static ssize_t (*old_readlink)(const char *, char *, size_t);
static ssize_t (*old_readlinkat)(int, const char *, char *, size_t);
static char *(*old_realpath)(const char *, char *);

static int accessImpl(const char *pathname, int mode);
static ssize_t readlinkImpl(const char *pathname, char *buf, size_t bufsiz);
static ssize_t readlinkatImpl(int dirfd, const char *pathname, char *buf, size_t bufsiz);
static char *realpathImpl(const char *pathname, char *resolved_path);

/* ================= Step 5: stat family ================= */
static int (*old_stat)(const char *, struct stat *);
static int (*old_lstat)(const char *, struct stat *);
static int (*old_stat64)(const char *, struct stat64 *);
static int (*old_lstat64)(const char *, struct stat64 *);
static int (*old_statfs)(const char *, struct statfs *);
static int (*old_statx)(int, const char *, int, unsigned int, struct statx *);

static int statImpl(const char *pathname, struct stat *st);
static int lstatImpl(const char *pathname, struct stat *st);
static int stat64Impl(const char *pathname, struct stat64 *st);
static int lstat64Impl(const char *pathname, struct stat64 *st);
static int statfsImpl(const char *pathname, struct statfs *st);
static int statxImpl(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *stx);

/* ================= Step 6: stdio + open2 ================= */
static FILE *(*old_fopen)(const char *, const char *);
static int (*old___open_2)(const char *, int);

static FILE *fopenImpl(const char *pathname, const char *mode);
static int __open_2Impl(const char *pathname, int flags);
static int serve_sanitized_proc(const char *pathname);

/* ================= Step 8.5: dlopen hooks -> 新加载 .so 自动刷新 ================= */
static void *(*old_dlopen)(const char *, int);
static void *(*old_android_dlopen_ext)(const char *, int, const void *);

static void sigb_refresh_after_load(void) {
    sigb_set_state(SIGB_STATE_REENTRY);
    xhook_refresh(0);
    sigb_set_state(SIGB_STATE_NORMAL);
}

static void *dlopenImpl(const char *filename, int flags) {
    void *h = old_dlopen != NULL ? old_dlopen(filename, flags) : dlopen(filename, flags);
    if (h != NULL) {
        sigb_refresh_after_load();
    }
    return h;
}

static void *android_dlopen_extImpl(const char *filename, int flags, const void *extinfo) {
    static void *(*real_android_dlopen_ext)(const char *, int, const void *) = NULL;
    if (real_android_dlopen_ext == NULL) {
        real_android_dlopen_ext = (void *(*)(const char *, int, const void *))
                dlsym(RTLD_DEFAULT, "android_dlopen_ext");
    }
    void *h;
    if (old_android_dlopen_ext != NULL) {
        h = old_android_dlopen_ext(filename, flags, extinfo);
    } else if (real_android_dlopen_ext != NULL) {
        h = real_android_dlopen_ext(filename, flags, extinfo);
    } else {
        h = dlopen(filename, flags);
    }
    if (h != NULL) {
        sigb_refresh_after_load();
    }
    return h;
}

/* ================= Step 8: dl_iterate_phdr ================= */
static int (*old_dl_iterate_phdr)(int (*)(struct dl_phdr_info *, size_t, void *), void *);

struct DlIterateCtx {
    int (*callback)(struct dl_phdr_info *, size_t, void *);
    void *data;
};

static int sanitizedDlCallback(struct dl_phdr_info *info, size_t size, void *data);
static int dlIteratePhdrImpl(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data);

int (*old_open)(const char *, int, mode_t);
static int openImpl(const char *pathname, int flags, mode_t mode) {
    if (!sigb_maybe_relevant(pathname)) {
        if (old_open == NULL) { errno = ENOSYS; return -1; }
        return old_open(pathname, flags, mode);
    }
    if ((flags & O_ACCMODE) == O_RDONLY) {
        int sanitized_fd = serve_sanitized_proc(pathname);
        if (sanitized_fd >= 0) {
            return sanitized_fd;
        }
    }
    if (sigb_resolve(pathname) != pathname){
        XH_LOG_WARN("REDIRECT open %s -> %s", pathname, sigb_get_rep_path());
        return old_open(sigb_get_rep_path(), flags, mode);
    }
    return old_open(pathname, flags, mode);
}

int (*old_open64)(const char *, int, mode_t);
static int open64Impl(const char *pathname, int flags, mode_t mode) {
    if (!sigb_maybe_relevant(pathname)) {
        if (old_open64 == NULL) { errno = ENOSYS; return -1; }
        return old_open64(pathname, flags, mode);
    }
    if ((flags & O_ACCMODE) == O_RDONLY) {
        int sanitized_fd = serve_sanitized_proc(pathname);
        if (sanitized_fd >= 0) {
            return sanitized_fd;
        }
    }
    if (sigb_resolve(pathname) != pathname){
        XH_LOG_WARN("REDIRECT open64 %s -> %s", pathname, sigb_get_rep_path());
        return old_open64(sigb_get_rep_path(), flags, mode);
    }
    return old_open64(pathname, flags, mode);
}

int (*old_openat)(int, const char*, int, mode_t);
static int openatImpl(int fd, const char *pathname, int flags, mode_t mode) {
    if (!sigb_maybe_relevant(pathname)) {
        if (old_openat == NULL) { errno = ENOSYS; return -1; }
        return old_openat(fd, pathname, flags, mode);
    }
    if ((flags & O_ACCMODE) == O_RDONLY) {
        int sanitized_fd = serve_sanitized_proc(pathname);
        if (sanitized_fd >= 0) {
            return sanitized_fd;
        }
    }
    if (sigb_resolve(pathname) != pathname){
        XH_LOG_WARN("REDIRECT openat %s -> %s", pathname, sigb_get_rep_path());
        return old_openat(fd, sigb_get_rep_path(), flags, mode);
    }
    return old_openat(fd, pathname, flags, mode);
}

int (*old_openat64)(int, const char*, int, mode_t);
static int openat64Impl(int fd, const char *pathname, int flags, mode_t mode) {
    if (!sigb_maybe_relevant(pathname)) {
        if (old_openat64 == NULL) { errno = ENOSYS; return -1; }
        return old_openat64(fd, pathname, flags, mode);
    }
    if ((flags & O_ACCMODE) == O_RDONLY) {
        int sanitized_fd = serve_sanitized_proc(pathname);
        if (sanitized_fd >= 0) {
            return sanitized_fd;
        }
    }
    if (sigb_resolve(pathname) != pathname){
        XH_LOG_WARN("REDIRECT openat64 %s -> %s", pathname, sigb_get_rep_path());
        return old_openat64(fd, sigb_get_rep_path(), flags, mode);
    }
    return old_openat64(fd, pathname, flags, mode);
}

JNIEXPORT void JNICALL
Java_r_s_sign_KillerApplication_hookApkPath(JNIEnv *env, __attribute__((unused)) jclass clazz, jstring apkPath, jstring repPath) {
    const char *apk_path = (*env)->GetStringUTFChars(env, apkPath, 0);
    const char *rep_path = (*env)->GetStringUTFChars(env, repPath, 0);
    sigb_set_target_paths(apk_path, rep_path);
    XH_LOG_WARN("SIGB_BUILD_MARKER=%s", sigb_build_marker());
    XH_LOG_WARN("SIGB_REP=%s", rep_path);
    (*env)->ReleaseStringUTFChars(env, apkPath, apk_path);
    (*env)->ReleaseStringUTFChars(env, repPath, rep_path);

    xhook_register(".*\\.so$", "openat64", openat64Impl, (void **) &old_openat64);
    xhook_register(".*\\.so$", "dlopen", dlopenImpl, (void **) &old_dlopen);
    xhook_register(".*\\.so$", "android_dlopen_ext", android_dlopen_extImpl, (void **) &old_android_dlopen_ext);
    xhook_register(".*\\.so$", "openat", openatImpl, (void **) &old_openat);
    xhook_register(".*\\.so$", "open64", open64Impl, (void **) &old_open64);
    xhook_register(".*\\.so$", "open", openImpl, (void **) &old_open);

    xhook_register(".*\\.so$", "access", accessImpl, (void **) &old_access);
    xhook_register(".*\\.so$", "readlink", readlinkImpl, (void **) &old_readlink);
    xhook_register(".*\\.so$", "readlinkat", readlinkatImpl, (void **) &old_readlinkat);
    xhook_register(".*\\.so$", "realpath", realpathImpl, (void **) &old_realpath);

    xhook_register(".*\\.so$", "stat", statImpl, (void **) &old_stat);
    xhook_register(".*\\.so$", "lstat", lstatImpl, (void **) &old_lstat);
    xhook_register(".*\\.so$", "stat64", stat64Impl, (void **) &old_stat64);
    xhook_register(".*\\.so$", "lstat64", lstat64Impl, (void **) &old_lstat64);
    xhook_register(".*\\.so$", "statfs", statfsImpl, (void **) &old_statfs);
    xhook_register(".*\\.so$", "statx", statxImpl, (void **) &old_statx);
    xhook_register(".*\\.so$", "fopen", fopenImpl, (void **) &old_fopen);
    xhook_register(".*\\.so$", "__open_2", __open_2Impl, (void **) &old___open_2);
    xhook_register(".*\\.so$", "dl_iterate_phdr", dlIteratePhdrImpl, (void **) &old_dl_iterate_phdr);
    sigb_set_state(SIGB_STATE_REENTRY);
    xhook_refresh(0);
    sigb_set_state(SIGB_STATE_NORMAL);
}

/* ================= Step 4: path family implementations (透传) ================= */

static int accessImpl(const char *pathname, int mode) {
    if (old_access == NULL) { errno = ENOSYS; return -1; }
    return old_access(pathname, mode);
}

static ssize_t readlinkImpl(const char *pathname, char *buf, size_t bufsiz) {
    if (old_readlink == NULL) { errno = ENOSYS; return -1; }
    return old_readlink(pathname, buf, bufsiz);
}

static ssize_t readlinkatImpl(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    if (old_readlinkat == NULL) { errno = ENOSYS; return -1; }
    return old_readlinkat(dirfd, pathname, buf, bufsiz);
}

static char *realpathImpl(const char *pathname, char *resolved_path) {
    if (old_realpath == NULL) { errno = ENOSYS; return NULL; }
    return old_realpath(pathname, resolved_path);
}

/* ================= Step 5: stat family implementations (透传) ================= */

static int statImpl(const char *pathname, struct stat *st) {
    if (old_stat == NULL) { errno = ENOSYS; return -1; }
    return old_stat(pathname, st);
}

static int lstatImpl(const char *pathname, struct stat *st) {
    if (old_lstat == NULL) { errno = ENOSYS; return -1; }
    return old_lstat(pathname, st);
}

static int stat64Impl(const char *pathname, struct stat64 *st) {
    if (old_stat64 == NULL) { errno = ENOSYS; return -1; }
    return old_stat64(pathname, st);
}

static int lstat64Impl(const char *pathname, struct stat64 *st) {
    if (old_lstat64 == NULL) { errno = ENOSYS; return -1; }
    return old_lstat64(pathname, st);
}

static int statfsImpl(const char *pathname, struct statfs *st) {
    if (old_statfs == NULL) { errno = ENOSYS; return -1; }
    return old_statfs(pathname, st);
}

static int statxImpl(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *stx) {
    if (old_statx == NULL) { errno = ENOSYS; return -1; }
    return old_statx(dirfd, pathname, flags, mask, stx);
}

/* ================= Step 6: implementations ================= */

static FILE *fopenImpl(const char *pathname, const char *mode) {
    if (!sigb_maybe_relevant(pathname)) {
        if (old_fopen == NULL) { errno = ENOSYS; return NULL; }
        return old_fopen(pathname, mode);
    }
    if (mode != NULL && mode[0] == 'r' && strchr(mode, '+') == NULL) {
        int sanitized_fd = serve_sanitized_proc(pathname);
        if (sanitized_fd >= 0) {
            FILE *fp = fdopen(sanitized_fd, mode);
            if (fp != NULL) {
                return fp;
            }
            syscall(__NR_close, sanitized_fd);
        }
    }
    int read_only = 0;
    if (mode != NULL && mode[0] == 'r' && strchr(mode, '+') == NULL) {
        read_only = 1;
    }
    if (read_only && sigb_resolve(pathname) != pathname) {
        XH_LOG_WARN("REDIRECT fopen %s -> %s", pathname, sigb_get_rep_path());
        return old_fopen(sigb_get_rep_path(), mode);
    }
    if (old_fopen == NULL) { errno = ENOSYS; return NULL; }
    return old_fopen(pathname, mode);
}

static int __open_2Impl(const char *pathname, int flags) {
    if (!sigb_maybe_relevant(pathname)) {
        if (old___open_2 == NULL) { errno = ENOSYS; return -1; }
        return old___open_2(pathname, flags);
    }
    if ((flags & O_ACCMODE) == O_RDONLY) {
        int sanitized_fd = serve_sanitized_proc(pathname);
        if (sanitized_fd >= 0) {
            return sanitized_fd;
        }
    }
    if (sigb_resolve(pathname) != pathname) {
        XH_LOG_WARN("REDIRECT __open_2 %s -> %s", pathname, sigb_get_rep_path());
        return old___open_2(sigb_get_rep_path(), flags);
    }
    if (old___open_2 == NULL) { errno = ENOSYS; return -1; }
    return old___open_2(pathname, flags);
}

/* ================= Step 7: sanitized proc view ================= */

static int serve_sanitized_proc(const char *pathname) {
    if (pathname == NULL) return -1;
    if (!sigb_should_sanitize_proc(pathname)) return -1;
    if (!sigb_is_normal()) return -1;

    int fd = sigb_raw_open(pathname);
    if (fd < 0) return -1;
    char *content = sigb_raw_read_fd(fd);
    syscall(__NR_close, fd);
    if (content == NULL) return -1;

    int is_smaps = (strstr(pathname, "smaps") != NULL);
    char *clean = sigb_sanitize_maps(content, is_smaps);
    free(content);
    if (clean == NULL) return -1;

    int memfd = sigb_create_memfd("npatch_proc_view", clean, strlen(clean));
    free(clean);
    if (memfd < 0) return -1;

    XH_LOG_WARN("SANITIZED %s -> memfd:npatch_proc_view", pathname);
    return memfd;
}

/* ================= Step 8: dl_iterate_phdr implementations ================= */

static int sanitizedDlCallback(struct dl_phdr_info *info, size_t size, void *data) {
    struct DlIterateCtx *ctx = (struct DlIterateCtx *)data;
    if (ctx == NULL || ctx->callback == NULL) return 0;
    if (info != NULL && sigb_contains_sensitive_word(info->dlpi_name)) {
        return 0;
    }
    return ctx->callback(info, size, ctx->data);
}

static int dlIteratePhdrImpl(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data) {
    if (old_dl_iterate_phdr == NULL) {
        errno = ENOSYS;
        return 0;
    }
    if (!sigb_is_normal() || callback == NULL) {
        if (old_dl_iterate_phdr == NULL) { errno = ENOSYS; return 0; }
        return old_dl_iterate_phdr(callback, data);
    }
    struct DlIterateCtx ctx;
    ctx.callback = callback;
    ctx.data = data;
    if (old_dl_iterate_phdr == NULL) { errno = ENOSYS; return 0; }
    return old_dl_iterate_phdr(sanitizedDlCallback, &ctx);
}

/* ================= Step 9: probe JNI methods ================= */

static char probe_fd_out[8192];
static char probe_dl_out[16384];

#if defined(__aarch64__) || defined(__x86_64__)
#define SIGB_NR_STAT __NR_newfstatat
#else
#define SIGB_NR_STAT __NR_fstatat64
#endif

static int probe_dlcallback(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    size_t *used = (size_t *)data;
    if (info != NULL && info->dlpi_name != NULL && info->dlpi_name[0] != '\0') {
        int n = snprintf(probe_dl_out + *used, sizeof(probe_dl_out) - *used, "%s\n", info->dlpi_name);
        if (n > 0 && (size_t)n < sizeof(probe_dl_out) - *used) *used += (size_t)n;
    }
    return 0;
}

JNIEXPORT void JNICALL
Java_r_s_sign_KillerApplication_refreshHooks(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    sigb_set_state(SIGB_STATE_REENTRY);
    xhook_refresh(0);
    sigb_set_state(SIGB_STATE_NORMAL);
}

JNIEXPORT jbyteArray JNICALL
Java_r_s_sign_KillerApplication_probeFopen(JNIEnv *env, jclass clazz, jstring jpath) {
    (void)clazz;
    if (jpath == NULL) return NULL;
    const char *path = (*env)->GetStringUTFChars(env, jpath, NULL);
    if (path == NULL) return NULL;
    FILE *fp = fopen(path, "r");
    (*env)->ReleaseStringUTFChars(env, jpath, path);
    if (fp == NULL) return NULL;
    size_t cap = 65536, len = 0;
    char *buf = (char *)malloc(cap);
    if (buf == NULL) { fclose(fp); return NULL; }
    while (1) {
        size_t rd = fread(buf + len, 1, cap - len - 1, fp);
        len += rd;
        if (rd == 0) break;
        if (len + 65536 >= cap) {
            cap *= 2;
            char *grown = (char *)realloc(buf, cap);
            if (grown == NULL) { free(buf); fclose(fp); return NULL; }
            buf = grown;
        }
    }
    fclose(fp);
    jbyteArray out = (*env)->NewByteArray(env, (jsize)len);
    if (out != NULL) {
        (*env)->SetByteArrayRegion(env, out, 0, (jsize)len, (const jbyte *)buf);
    }
    free(buf);
    return out;
}

JNIEXPORT jstring JNICALL
Java_r_s_sign_KillerApplication_probeStat(JNIEnv *env, jclass clazz, jstring jpath) {
    (void)clazz;
    if (jpath == NULL) return (*env)->NewStringUTF(env, "ERR:null");
    const char *path = (*env)->GetStringUTFChars(env, jpath, NULL);
    if (path == NULL) return (*env)->NewStringUTF(env, "ERR:oom");

    char out[1024];

    struct stat st;
    memset(&st, 0, sizeof(st));
    if (stat(path, &st) == 0) {
        snprintf(out, sizeof(out), "normal: dev=%lx ino=%lu size=%ld",
                 (unsigned long)st.st_dev, (unsigned long)st.st_ino, (long)st.st_size);
    } else {
        snprintf(out, sizeof(out), "normal: ERR errno=%d", errno);
    }

#if defined(__LP64__)
    struct stat raw_st;
#else
    struct stat64 raw_st;
#endif
    memset(&raw_st, 0, sizeof(raw_st));
    if (syscall(SIGB_NR_STAT, AT_FDCWD, path, &raw_st, 0) == 0) {
        char raw_part[512];
        snprintf(raw_part, sizeof(raw_part), " | raw: dev=%lx ino=%lu size=%ld",
                 (unsigned long)raw_st.st_dev, (unsigned long)raw_st.st_ino, (long)raw_st.st_size);
        strncat(out, raw_part, sizeof(out) - strlen(out) - 1);
    } else {
        strncat(out, " | raw: ERR", sizeof(out) - strlen(out) - 1);
    }

    (*env)->ReleaseStringUTFChars(env, jpath, path);
    return (*env)->NewStringUTF(env, out);
}

JNIEXPORT jstring JNICALL
Java_r_s_sign_KillerApplication_probePaths(JNIEnv *env, jclass clazz, jstring jpath) {
    (void)clazz;
    if (jpath == NULL) return (*env)->NewStringUTF(env, "ERR:null");
    const char *path = (*env)->GetStringUTFChars(env, jpath, NULL);
    if (path == NULL) return (*env)->NewStringUTF(env, "ERR:oom");
    char out[2048];
    int ok = (access(path, F_OK) == 0);
    char *linkbuf = sigb_raw_readlink(path);
    char *realbuf = realpath(path, NULL);
    snprintf(out, sizeof(out), "access=%s raw_readlink=%s normal_realpath=%s",
             ok ? "OK" : "NO",
             linkbuf != NULL ? linkbuf : "?",
             realbuf != NULL ? realbuf : "ERR:realpath");
    free(linkbuf);
    free(realbuf);
    (*env)->ReleaseStringUTFChars(env, jpath, path);
    return (*env)->NewStringUTF(env, out);
}

JNIEXPORT jstring JNICALL
Java_r_s_sign_KillerApplication_probeMaps(JNIEnv *env, jclass clazz, jboolean raw) {
    (void)clazz;
    const char *path = "/proc/self/maps";
    char *content = NULL;
    if (raw == JNI_TRUE) {
        sigb_set_state(SIGB_STATE_PROBE);
        int fd = sigb_raw_open(path);
        if (fd >= 0) {
            content = sigb_raw_read_fd(fd);
            syscall(__NR_close, fd);
        }
        sigb_set_state(SIGB_STATE_NORMAL);
    } else {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            content = sigb_raw_read_fd(fd);
            syscall(__NR_close, fd);
        }
    }
    if (content == NULL) return (*env)->NewStringUTF(env, "ERR:read");
    jstring out = (*env)->NewStringUTF(env, content);
    free(content);
    return out;
}

JNIEXPORT jstring JNICALL
Java_r_s_sign_KillerApplication_probeFds(JNIEnv *env, jclass clazz) {
    (void)clazz;
    char fd_path[64];
    size_t used = 0;
    probe_fd_out[0] = '\0';
    for (int fd = 0; fd < 1024; ++fd) {
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
        char *target = sigb_raw_readlink(fd_path);
        if (target == NULL) continue;
        int n = snprintf(probe_fd_out + used, sizeof(probe_fd_out) - used, "fd=%d -> %s\n", fd, target);
        if (n > 0 && (size_t)n < sizeof(probe_fd_out) - used) used += (size_t)n;
        free(target);
        if (used >= sizeof(probe_fd_out) - 256) break;
    }
    return (*env)->NewStringUTF(env, probe_fd_out);
}

JNIEXPORT jstring JNICALL
Java_r_s_sign_KillerApplication_probeDlIterate(JNIEnv *env, jclass clazz, jboolean raw) {
    (void)clazz;
    size_t used = 0;
    probe_dl_out[0] = '\0';
    if (raw == JNI_TRUE) {
        sigb_set_state(SIGB_STATE_PROBE);
    }
    dl_iterate_phdr(probe_dlcallback, &used);
    if (raw == JNI_TRUE) {
        sigb_set_state(SIGB_STATE_NORMAL);
    }
    return (*env)->NewStringUTF(env, probe_dl_out);
}

JNIEXPORT void JNICALL
Java_r_s_sign_KillerApplication_setThreadBypass(JNIEnv *env, jclass clazz, jboolean bypass) {
    (void)env; (void)clazz;
    sigb_set_thread_bypass(bypass == JNI_TRUE ? 1 : 0);
}

JNIEXPORT jboolean JNICALL
Java_r_s_sign_KillerApplication_isThreadBypass(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return sigb_is_thread_bypass() ? JNI_TRUE : JNI_FALSE;
}
