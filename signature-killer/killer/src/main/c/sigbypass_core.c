#include "sigbypass_core.h"
#include "xh_log.h"

#if defined(__aarch64__) || defined(__x86_64__)
#define SIGB_CORE_STAT_NR __NR_newfstatat
#else
#define SIGB_CORE_STAT_NR __NR_fstatat64
#endif

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/memfd.h>
#include <linux/stat.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static char *g_apk_path = NULL;
static char *g_rep_path = NULL;
static atomic_int g_state = SIGB_STATE_NORMAL;
static __thread int g_thread_bypass = 0;

void sigb_set_thread_bypass(int bypass) {
    g_thread_bypass = bypass;
}

int sigb_is_thread_bypass(void) {
    return g_thread_bypass;
}

const char *sigb_build_marker(void) {
    return "SIGB_PATH_REWRITE_20261001_829B367";
}

static char *dup_str(const char *s) {
    if (s == NULL) return NULL;
    size_t len = strlen(s);
    char *copy = (char *)malloc(len + 1);
    if (copy == NULL) return NULL;
    memcpy(copy, s, len + 1);
    return copy;
}

void sigb_set_target_paths(const char *apk, const char *rep) {
    /* set-once：hook 注册后运行期禁止改路径，避免并发读取 use-after-free */
    if (g_apk_path != NULL || g_rep_path != NULL) {
        return;
    }
    g_apk_path = dup_str(apk);
    g_rep_path = dup_str(rep);
}

const char *sigb_get_apk_path(void) {
    return g_apk_path;
}

const char *sigb_get_rep_path(void) {
    return g_rep_path;
}

const char *sigb_resolve(const char *path) {
    if (path == NULL || g_apk_path == NULL || g_rep_path == NULL) {
        return path;
    }
    // 【核心自己人白名单】如果当前线程是自己人，直接放行，绝不重定向
    if (g_thread_bypass) {
        return path;
    }
    // 其余所有情况 (全黑名单)，命中 base.apk 强制重定向至 signed.apk
    if (strcmp(path, g_apk_path) == 0) {
        return g_rep_path;
    }
    return path;
}

/* 快速路径：无锁判断是否需要走慢路径（重定向/sanitize）。
   返回 0 = 确定无关，直接走原始系统调用；返回 1 = 可能相关，需进慢路径。 */
int sigb_maybe_relevant(const char *path) {
    if (path == NULL) return 0;
    /* 1) /proc/self/maps 或 smaps：需 sanitize */
    if (strncmp(path, "/proc/self/", 11) == 0 || strncmp(path, "/proc/thread-self/", 18) == 0) {
        if (strstr(path, "maps") != NULL || strstr(path, "smaps") != NULL) {
            return 1;
        }
        return 0;
    }
    /* 2) 绝对路径 && 以 /data/ 开头：可能命中 APK 路径 */
    if (path[0] == '/' && strncmp(path, "/data/", 6) == 0) {
        return 1;
    }
    /* 3) 其他：无关 */
    return 0;
}


void sigb_set_state(int state) {
    atomic_store_explicit(&g_state, state, memory_order_relaxed);
}

int sigb_get_state(void) {
    return atomic_load_explicit(&g_state, memory_order_relaxed);
}

int sigb_is_normal(void) {
    return g_state == SIGB_STATE_NORMAL;
}

int sigb_is_reentry(void) {
    return g_state == SIGB_STATE_REENTRY;
}

int sigb_is_probe(void) {
    return g_state == SIGB_STATE_PROBE;
}


/* ================= Step 3: tool layer ================= */

static const char *const kSensitiveWords[] = {
        "frida",
        "rwxp",
        "zygisk",
        "riru",
        "lsposed",
        "xposed",
        "/data/local/tmp",
        "/data/adb/",
        NULL,
};

static void sigb_to_lower(char *text) {
    if (text == NULL) return;
    for (; *text != '\0'; ++text) {
        unsigned char ch = (unsigned char)*text;
        if (ch >= 'A' && ch <= 'Z') {
            *text = (char)(ch - 'A' + 'a');
        }
    }
}

int sigb_contains_sensitive_word(const char *text) {
    if (text == NULL) return 0;
    size_t len = strlen(text);
    char *lower = (char *)malloc(len + 1);
    if (lower == NULL) return 0;
    memcpy(lower, text, len + 1);
    sigb_to_lower(lower);
    for (int i = 0; kSensitiveWords[i] != NULL; ++i) {
        if (strstr(lower, kSensitiveWords[i]) != NULL) {
            free(lower);
            return 1;
        }
    }
    free(lower);
    return 0;
}

int sigb_create_memfd(const char *name, const char *content, size_t len) {
    if (name == NULL) return -1;
    int fd = (int)syscall(__NR_memfd_create, name, MFD_CLOEXEC);
    if (fd < 0) return -1;
    const char *data = content;
    size_t left = len;
    while (left > 0) {
        ssize_t written = write(fd, data, left);
        if (written < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        data += written;
        left -= (size_t)written;
    }
    lseek(fd, 0, SEEK_SET);
    return fd;
}






/* 匿名可执行段改写：path 为空且 perms 含 x 的映射改为 r--p。
   目的：堵住 'rwxp' 敏感词行 - 真正的可执行匿名内存是 JIT 的正常行为，
   但检测方常以 rwxp 作为 hook/注入特征。这里只改 perms，不动 start/end。 */

char *sigb_sanitize_maps(const char *content, int is_smaps) {
    (void)is_smaps;
    if (content == NULL) return NULL;
    size_t content_len = strlen(content);
    size_t cap = content_len * 2 + 128;
    char *out = (char *)malloc(cap);
    if (out == NULL) return NULL;
    size_t out_pos = 0;
    const char *pos = content;
    while (pos < content + content_len) {
        const char *end = strchr(pos, '\n');
        size_t line_len = (end != NULL) ? (size_t)(end - pos)
                                        : (size_t)(content + content_len - pos);
        char *line = (char *)malloc(line_len + 1);
        if (line == NULL) { free(out); return NULL; }
        memcpy(line, pos, line_len);
        line[line_len] = '\0';
        int keep = 1;
        if (sigb_contains_sensitive_word(line)) {
            keep = 0;
        }
        if (keep) {
            /* method A：将 /data 下真实 base.apk 映射路径重写为 signed.apk，
               inode/dev 保持原样 —— C1 字符串一致，ch7 norm/raw 维度仍一致 */
            const char *rep = sigb_get_rep_path();
            if (rep != NULL && line_len > 1) {
                char *last_space = strrchr(line, ' ');
                if (last_space != NULL) {
                    char *path = last_space + 1;
                    size_t path_len = strlen(path);
                    if (path_len >= 5 && strncmp(path, "/data/", 6) == 0
                            && strstr(path, ".apk") != NULL) {
                        size_t prefix_len = (size_t)(last_space - line);
                        size_t new_len = prefix_len + 1 + strlen(rep);
                        char *rewritten = (char *)malloc(new_len + 1);
                        if (rewritten != NULL) {
                            memcpy(rewritten, line, prefix_len);
                            rewritten[prefix_len] = ' ';
                            strcpy(rewritten + prefix_len + 1, rep);
                            free(line);
                            line = rewritten;
                            line_len = new_len;
                        }
                    }
                }
            }
            if (out_pos + line_len + 2 > cap) {
                size_t new_cap = cap * 2;
                if (new_cap < out_pos + line_len + 2) new_cap = out_pos + line_len + 2;
                char *grown = (char *)realloc(out, new_cap);
                if (grown == NULL) { free(line); free(out); return NULL; }
                out = grown;
                cap = new_cap;
            }
            memcpy(out + out_pos, line, line_len);
            out_pos += line_len;
            if (end != NULL) { out[out_pos++] = '\n'; }
        }
        free(line);
        pos = (end != NULL) ? end + 1 : content + content_len;
    }
    out[out_pos] = '\0';
    return out;
}


int sigb_raw_open(const char *path) {
    if (path == NULL) return -1;
    return (int)syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
}

char *sigb_raw_read_fd(int fd) {
    if (fd < 0) return NULL;
    size_t cap = 8192;
    size_t len = 0;
    char *buf = (char *)malloc(cap);
    if (buf == NULL) return NULL;
    while (1) {
        if (len + 4096 >= cap) {
            size_t new_cap = cap * 2;
            char *grown = (char *)realloc(buf, new_cap);
            if (grown == NULL) {
                free(buf);
                return NULL;
            }
            buf = grown;
            cap = new_cap;
        }
        ssize_t n = syscall(__NR_read, fd, buf + len, cap - len - 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf);
            return NULL;
        }
        if (n == 0) break;
        len += (size_t)n;
    }
    buf[len] = '\0';
    return buf;
}

char *sigb_raw_readlink(const char *path) {
    if (path == NULL) return NULL;
    size_t cap = 256;
    while (cap <= 65536) {
        char *buf = (char *)malloc(cap + 1);
        if (buf == NULL) return NULL;
        ssize_t n = syscall(__NR_readlinkat, AT_FDCWD, path, buf, cap);
        if (n < 0) {
            free(buf);
            return NULL;
        }
        if ((size_t)n < cap) {
            buf[n] = '\0';
            return buf;
        }
        free(buf);
        cap *= 2;
    }
    return NULL;
}


/* ================= Step 7: proc maps detection ================= */

static int sigb_self_proc_file(const char *pathname, const char *name) {
    if (pathname == NULL || name == NULL) return 0;
    char self_path[64];
    char pid_path[64];
    char thread_self_path[64];
    snprintf(self_path, sizeof(self_path), "/proc/self/%s", name);
    snprintf(pid_path, sizeof(pid_path), "/proc/%d/%s", (int)getpid(), name);
    snprintf(thread_self_path, sizeof(thread_self_path), "/proc/thread-self/%s", name);
    return strcmp(pathname, self_path) == 0
           || strcmp(pathname, pid_path) == 0
           || strcmp(pathname, thread_self_path) == 0;
}

int sigb_should_sanitize_proc(const char *pathname) {
    if (pathname == NULL) return 0;
    return sigb_self_proc_file(pathname, "maps")
           || sigb_self_proc_file(pathname, "smaps");
}
