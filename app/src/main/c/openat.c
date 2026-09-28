//
// Created by Thom on 2019/3/30.
//

#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include "openat.h"
#include <jni.h>
#include <android/log.h>

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

intptr_t openAt(intptr_t fd, const char *path, intptr_t flag) {
#if defined(__arm__)
    intptr_t r;
    asm volatile(
#ifndef OPTIMIZE_ASM
    "mov r0, %1\n\t"
    "mov r1, %2\n\t"
    "mov r2, %3\n\t"
#endif

    "mov ip, r7\n\t"
    ".cfi_register r7, ip\n\t"
    "mov r7, #" STR(__NR_openat) "\n\t"
    "svc #0\n\t"
    "mov r7, ip\n\t"
    ".cfi_restore r7\n\t"

#ifndef OPTIMIZE_ASM
    "mov %0, r0\n\t"
#endif
    : "=r" (r)
    : "r" (fd), "r" (path), "r" (flag));
    return r;
#elif defined(__aarch64__)
    intptr_t r;
    asm volatile(
#ifndef OPTIMIZE_ASM
    "mov x0, %1\n\t"
    "mov x1, %2\n\t"
    "mov x2, %3\n\t"
#endif

    "mov x8, #" STR(__NR_openat) "\n\t"
    "svc #0\n\t"

#ifndef OPTIMIZE_ASM
    "mov %0, x0\n\t"
#endif
    : "=r" (r)
    : "r" (fd), "r" (path), "r" (flag));
    return r;
#else
    return (intptr_t) syscall(__NR_openat, fd, path, flag);
#endif
}

JNIEXPORT jint JNICALL
Java_r_s_test_MainActivity_openAt(JNIEnv *env, jclass clazz, jstring path) {
    (void)clazz;
    if (path == NULL) return -1;
    const char *original = (*env)->GetStringUTFChars(env, path, NULL);
    if (original == NULL) return -1;
    const char *effective = original;

    jclass killerCls = (*env)->FindClass(env, "r/s/sign/KillerApplication");
    if (killerCls != NULL) {
        jmethodID repMethod = (*env)->GetStaticMethodID(env, killerCls, "repPath", "()Ljava/lang/String;");
        if (repMethod != NULL) {
            jstring jrep = (jstring)(*env)->CallStaticObjectMethod(env, killerCls, repMethod);
            if (jrep != NULL) {
                const char *rep = (*env)->GetStringUTFChars(env, jrep, NULL);
                if (rep != NULL && rep[0] != '\0') {
                    size_t len = strlen(original);
                    if (len > 9 && strcmp(original + len - 9, "/base.apk") == 0) {
                        effective = rep;
                        __android_log_print(ANDROID_LOG_INFO, "openAt", "SVC redirect %s -> %s", original, rep);
                    }
                }
                if (rep != NULL) (*env)->ReleaseStringUTFChars(env, jrep, rep);
                (*env)->DeleteLocalRef(env, jrep);
            }
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, killerCls);
    }

    intptr_t fd = openAt(AT_FDCWD, effective, O_RDONLY);
    (*env)->ReleaseStringUTFChars(env, path, original);
    return (jint)fd;
}