#include <jni.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>
#include <unistd.h>
#include <dirent.h>
#include <stdbool.h>
#include <string.h>
#include "xhook.h"
#include "xh_log.h"
#include "sigbypass_core.h"


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

    xhook_refresh(0);
}
