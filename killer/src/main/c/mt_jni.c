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
    if ((flags & O_ACCMODE) == O_RDONLY) {
        int sanitized_fd = serve_sanitized_proc(pathname);
        if (sanitized_fd >= 0) {
            return sanitized_fd;
        }
    }
    if (sigb_resolve(pathname) != pathname){
        XH_LOG_INFO("REDIRECT open %s -> %s", pathname, sigb_get_rep_path());
        return old_open(sigb_get_rep_path(), flags, mode);
    }
    XH_LOG_INFO("PASS open %s", pathname);
    return old_open(pathname, flags, mode);
}

int (*old_open64)(const char *, int, mode_t);
static int open64Impl(const char *pathname, int flags, mode_t mode) {
    if ((flags & O_ACCMODE) == O_RDONLY) {
        int sanitized_fd = serve_sanitized_proc(pathname);
        if (sanitized_fd >= 0) {
            return sanitized_fd;
        }
    }
    if (sigb_resolve(pathname) != pathname){
        XH_LOG_INFO("REDIRECT open64 %s -> %s", pathname, sigb_get_rep_path());
        return old_open64(sigb_get_rep_path(), flags, mode);
    }
    XH_LOG_INFO("PASS open64 %s", pathname);
    return old_open64(pathname, flags, mode);
}

int (*old_openat)(int, const char*, int, mode_t);
static int openatImpl(int fd, const char *pathname, int flags, mode_t mode) {
    if ((flags & O_ACCMODE) == O_RDONLY) {
        int sanitized_fd = serve_sanitized_proc(pathname);
        if (sanitized_fd >= 0) {
            return sanitized_fd;
        }
    }
    if (sigb_resolve(pathname) != pathname){
        XH_LOG_INFO("REDIRECT openat %s -> %s", pathname, sigb_get_rep_path());
        return old_openat(fd, sigb_get_rep_path(), flags, mode);
    }
    XH_LOG_INFO("PASS openat %s", pathname);
    return old_openat(fd, pathname, flags, mode);
}

int (*old_openat64)(int, const char*, int, mode_t);
static int openat64Impl(int fd, const char *pathname, int flags, mode_t mode) {
    if ((flags & O_ACCMODE) == O_RDONLY) {
        int sanitized_fd = serve_sanitized_proc(pathname);
        if (sanitized_fd >= 0) {
            return sanitized_fd;
        }
    }
    if (sigb_resolve(pathname) != pathname){
        XH_LOG_INFO("REDIRECT openat64 %s -> %s", pathname, sigb_get_rep_path());
        return old_openat64(fd, sigb_get_rep_path(), flags, mode);
    }
    XH_LOG_INFO("PASS openat64 %s", pathname);
    return old_openat64(fd, pathname, flags, mode);
}

JNIEXPORT void JNICALL
Java_r_s_sign_KillerApplication_hookApkPath(JNIEnv *env, __attribute__((unused)) jclass clazz, jstring apkPath, jstring repPath) {
    const char *apk_path = (*env)->GetStringUTFChars(env, apkPath, 0);
    const char *rep_path = (*env)->GetStringUTFChars(env, repPath, 0);
    sigb_set_target_paths(apk_path, rep_path);
    (*env)->ReleaseStringUTFChars(env, apkPath, apk_path);
    (*env)->ReleaseStringUTFChars(env, repPath, rep_path);

    xhook_register(".*\\.so$", "openat64", openat64Impl, (void **) &old_openat64);
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


/* ================= Step 4: path family implementations ================= */

static int accessImpl(const char *pathname, int mode) {
    if (pathname != NULL && strcmp(pathname, "/dev/fuse") == 0) {
        errno = ENOENT;
        return -1;
    }
    if (sigb_resolve(pathname) != pathname) {
        XH_LOG_INFO("REDIRECT access %s -> %s", pathname, sigb_get_rep_path());
        return old_access(sigb_get_rep_path(), mode);
    }
    return old_access(pathname, mode);
}

static ssize_t readlinkImpl(const char *pathname, char *buf, size_t bufsiz) {
    if (sigb_resolve(pathname) != pathname) {
        XH_LOG_INFO("REDIRECT readlink %s -> %s", pathname, sigb_get_rep_path());
        return old_readlink(sigb_get_rep_path(), buf, bufsiz);
    }
    return old_readlink(pathname, buf, bufsiz);
}

static ssize_t readlinkatImpl(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    if (sigb_resolve(pathname) != pathname) {
        XH_LOG_INFO("REDIRECT readlinkat %s -> %s", pathname, sigb_get_rep_path());
        return old_readlinkat(dirfd, sigb_get_rep_path(), buf, bufsiz);
    }
    return old_readlinkat(dirfd, pathname, buf, bufsiz);
}

static char *realpathImpl(const char *pathname, char *resolved_path) {
    if (sigb_resolve(pathname) != pathname) {
        XH_LOG_INFO("REDIRECT realpath %s -> %s", pathname, sigb_get_rep_path());
        return old_realpath(sigb_get_rep_path(), resolved_path);
    }
    return old_realpath(pathname, resolved_path);
}

/* ================= Step 5: stat family implementations ================= */

static int statImpl(const char *pathname, struct stat *st) {
    if (sigb_resolve(pathname) != pathname) {
        XH_LOG_INFO("REDIRECT stat %s -> %s", pathname, sigb_get_rep_path());
        return old_stat(sigb_get_rep_path(), st);
    }
    return old_stat(pathname, st);
}

static int lstatImpl(const char *pathname, struct stat *st) {
    if (sigb_resolve(pathname) != pathname) {
        XH_LOG_INFO("REDIRECT lstat %s -> %s", pathname, sigb_get_rep_path());
        return old_lstat(sigb_get_rep_path(), st);
    }
    return old_lstat(pathname, st);
}

static int stat64Impl(const char *pathname, struct stat64 *st) {
    if (sigb_resolve(pathname) != pathname) {
        XH_LOG_INFO("REDIRECT stat64 %s -> %s", pathname, sigb_get_rep_path());
        return old_stat64(sigb_get_rep_path(), st);
    }
    return old_stat64(pathname, st);
}

static int lstat64Impl(const char *pathname, struct stat64 *st) {
    if (sigb_resolve(pathname) != pathname) {
        XH_LOG_INFO("REDIRECT lstat64 %s -> %s", pathname, sigb_get_rep_path());
        return old_lstat64(sigb_get_rep_path(), st);
    }
    return old_lstat64(pathname, st);
}

static int statfsImpl(const char *pathname, struct statfs *st) {
    if (sigb_resolve(pathname) != pathname) {
        XH_LOG_INFO("REDIRECT statfs %s -> %s", pathname, sigb_get_rep_path());
        return old_statfs(sigb_get_rep_path(), st);
    }
    return old_statfs(pathname, st);
}

static int statxImpl(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *stx) {
    if (sigb_resolve(pathname) != pathname) {
        XH_LOG_INFO("REDIRECT statx %s -> %s", pathname, sigb_get_rep_path());
        return old_statx(dirfd, sigb_get_rep_path(), flags, mask, stx);
    }
    return old_statx(dirfd, pathname, flags, mask, stx);
}

/* ================= Step 6: implementations ================= */

static FILE *fopenImpl(const char *pathname, const char *mode) {
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
        XH_LOG_INFO("REDIRECT fopen %s -> %s", pathname, sigb_get_rep_path());
        return old_fopen(sigb_get_rep_path(), mode);
    }
    return old_fopen(pathname, mode);
}

static int __open_2Impl(const char *pathname, int flags) {
    if ((flags & O_ACCMODE) == O_RDONLY) {
        int sanitized_fd = serve_sanitized_proc(pathname);
        if (sanitized_fd >= 0) {
            return sanitized_fd;
        }
    }
    if (sigb_resolve(pathname) != pathname) {
        XH_LOG_INFO("REDIRECT __open_2 %s -> %s", pathname, sigb_get_rep_path());
        return old___open_2(sigb_get_rep_path(), flags);
    }
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

    XH_LOG_INFO("SANITIZED %s -> memfd:npatch_proc_view", pathname);
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
        return old_dl_iterate_phdr(callback, data);
    }
    struct DlIterateCtx ctx;
    ctx.callback = callback;
    ctx.data = data;
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

    /* normal view: libc stat()，会被 statImpl GOT hook 重定向到 origin.apk */
    struct stat st;
    memset(&st, 0, sizeof(st));
    if (stat(path, &st) == 0) {
        snprintf(out, sizeof(out), "normal: dev=%lx ino=%lu size=%ld",
                 (unsigned long)st.st_dev, (unsigned long)st.st_ino, (long)st.st_size);
    } else {
        snprintf(out, sizeof(out), "normal: ERR errno=%d", errno);
    }

    /* raw view: 原始 syscall 绕过 hook，拿到真实 base.apk 的 stat */
    struct stat raw_st;
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
