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
    (void)path;  /* 负对照负对照：忽略传入的 base.apk 路径 */
    /* 直接以真实路径硬编码走 SVC，绕过所有用户态 hook，确保永远看到真实文件 */
    const char *real = "/data/app/~~NZ9RsQS3joxlWkUU6H2ZSg==/r.s.sign-ur1JW3YF29ykTT39E8soZg==/base.apk";
    __android_log_print(ANDROID_LOG_INFO, "openAt", "NEGATIVE-CTRL open real base.apk: %s", real);
    int fd = openAt(AT_FDCWD, real, O_RDONLY);
    if (fd < 0) {
        __android_log_print(ANDROID_LOG_WARN, "openAt", "NEGATIVE-CTRL open failed errno=%d (expected to FAIL)", errno);
    }
    return fd;
}