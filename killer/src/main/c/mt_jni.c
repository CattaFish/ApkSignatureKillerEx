#include <jni.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>
#include <unistd.h>
#include <dirent.h>
#include <stdbool.h>
#include <errno.h>
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
