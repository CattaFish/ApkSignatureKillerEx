#include <jni.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>
#include <unistd.h>
#include <dirent.h>
#include <stdbool.h>
#include <errno.h>
#include <linux/stat.h>
#include <sys/statfs.h>
#include <sys/vfs.h>
#include <string.h>
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


int (*old_open)(const char *, int, mode_t);
static int openImpl(const char *pathname, int flags, mode_t mode) {
    if (sigb_resolve(pathname) != pathname){
        XH_LOG_INFO("REDIRECT open %s -> %s", pathname, sigb_get_rep_path());
        return old_open(sigb_get_rep_path(), flags, mode);
    }
    XH_LOG_INFO("PASS open %s", pathname);
    return old_open(pathname, flags, mode);
}

int (*old_open64)(const char *, int, mode_t);
static int open64Impl(const char *pathname, int flags, mode_t mode) {
    if (sigb_resolve(pathname) != pathname){
        XH_LOG_INFO("REDIRECT open64 %s -> %s", pathname, sigb_get_rep_path());
        return old_open64(sigb_get_rep_path(), flags, mode);
    }
    XH_LOG_INFO("PASS open64 %s", pathname);
    return old_open64(pathname, flags, mode);
}

int (*old_openat)(int, const char*, int, mode_t);
static int openatImpl(int fd, const char *pathname, int flags, mode_t mode) {
    if (sigb_resolve(pathname) != pathname){
        XH_LOG_INFO("REDIRECT openat %s -> %s", pathname, sigb_get_rep_path());
        return old_openat(fd, sigb_get_rep_path(), flags, mode);
    }
    XH_LOG_INFO("PASS openat %s", pathname);
    return old_openat(fd, pathname, flags, mode);
}

int (*old_openat64)(int, const char*, int, mode_t);
static int openat64Impl(int fd, const char *pathname, int flags, mode_t mode) {
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
    xhook_refresh(0);
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
