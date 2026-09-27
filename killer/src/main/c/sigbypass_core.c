#include "sigbypass_core.h"

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/memfd.h>
#include <linux/stat.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static char *g_apk_path = NULL;
static char *g_rep_path = NULL;
static int g_state = SIGB_STATE_NORMAL;

static char *dup_str(const char *s) {
    if (s == NULL) return NULL;
    size_t len = strlen(s);
    char *copy = (char *)malloc(len + 1);
    if (copy == NULL) return NULL;
    memcpy(copy, s, len + 1);
    return copy;
}

void sigb_set_target_paths(const char *apk, const char *rep) {
    free(g_apk_path);
    free(g_rep_path);
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
    if (strcmp(path, g_apk_path) == 0) {
        return g_rep_path;
    }
    return path;
}

void sigb_set_state(int state) {
    g_state = state;
}

int sigb_get_state(void) {
    return g_state;
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

int sigb_parse_maps_entry(const char *line, sigb_map_entry_t *entry) {
    if (line == NULL || entry == NULL) return 0;
    unsigned long start = 0;
    unsigned long end = 0;
    unsigned long offset = 0;
    unsigned long long inode = 0;
    char perms[8] = {0};
    char dev[32] = {0};
    int consumed = 0;
    int fields = sscanf(line, "%lx-%lx %7s %lx %31s %llu%n",
                        &start, &end, perms, &offset, dev, &inode, &consumed);
    if (fields < 4) return 0;

    memset(entry, 0, sizeof(*entry));
    entry->start = start;
    entry->end = end;
    entry->offset = offset;
    entry->inode = (fields >= 6) ? inode : 0;

    size_t perms_len = strlen(perms);
    if (perms_len >= sizeof(entry->perms)) perms_len = sizeof(entry->perms) - 1;
    memcpy(entry->perms, perms, perms_len);
    entry->perms[perms_len] = '\0';

    if (fields >= 5) {
        size_t dev_len = strlen(dev);
        if (dev_len >= sizeof(entry->dev)) dev_len = sizeof(entry->dev) - 1;
        memcpy(entry->dev, dev, dev_len);
        entry->dev[dev_len] = '\0';
    }

    if (fields >= 6 && consumed > 0) {
        const char *p = line + consumed;
        while (*p == ' ' || *p == '\t') ++p;
        size_t plen = strlen(p);
        while (plen > 0 && (p[plen - 1] == '\n' || p[plen - 1] == '\r')) --plen;
        if (plen > 0) {
            if (plen >= sizeof(entry->path)) plen = sizeof(entry->path) - 1;
            memcpy(entry->path, p, plen);
            entry->path[plen] = '\0';
        }
    }
    return 1;
}

static int sigb_path_matches_apk(const char *path) {
    const char *apk = sigb_get_apk_path();
    if (path == NULL || apk == NULL || path[0] == '\0') return 0;
    if (strcmp(path, apk) == 0) return 1;
    size_t len = strlen(apk);
    return strncmp(path, apk, len) == 0 && strcmp(path + len, " (deleted)") == 0;
}

static int sigb_query_rep_id(char *dev_out, size_t dev_size, unsigned long long *inode_out) {
    const char *rep = sigb_get_rep_path();
    if (rep == NULL || dev_out == NULL || inode_out == NULL || dev_size == 0) return 0;
    struct statx stx;
    memset(&stx, 0, sizeof(stx));
    long rc = syscall(__NR_statx, AT_FDCWD, rep, 0, STATX_BASIC_STATS, &stx);
    if (rc != 0) return 0;
    snprintf(dev_out, dev_size, "%02x:%02x",
             (unsigned int)(stx.stx_dev_major & 0xff),
             (unsigned int)(stx.stx_dev_minor & 0xff));
    *inode_out = (unsigned long long)stx.stx_ino;
    return 1;
}

static int g_rep_id_ready = 0;
static char g_cached_rep[SIGB_MAP_PATH_MAX] = {0};
static char g_rep_dev[32] = {0};
static unsigned long long g_rep_ino = 0;

static int sigb_get_rep_id_cached(char *dev_out, size_t dev_size, unsigned long long *inode_out) {
    const char *rep = sigb_get_rep_path();
    if (rep == NULL || dev_out == NULL || inode_out == NULL || dev_size == 0) return 0;
    if (!g_rep_id_ready || strcmp(g_cached_rep, rep) != 0) {
        if (!sigb_query_rep_id(g_rep_dev, sizeof(g_rep_dev), &g_rep_ino)) {
            return 0;
        }
        size_t rep_len = strlen(rep);
        if (rep_len >= sizeof(g_cached_rep)) rep_len = sizeof(g_cached_rep) - 1;
        memcpy(g_cached_rep, rep, rep_len);
        g_cached_rep[rep_len] = '\0';
        g_rep_id_ready = 1;
    }
    snprintf(dev_out, dev_size, "%s", g_rep_dev);
    *inode_out = g_rep_ino;
    return 1;
}

char *sigb_sanitize_maps(const char *content, int is_smaps) {
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
        if (line == NULL) {
            free(out);
            return NULL;
        }
        memcpy(line, pos, line_len);
        line[line_len] = '\0';

        int keep = 1;
        if (sigb_contains_sensitive_word(line)) {
            keep = 0;
        } else if (!is_smaps) {
            sigb_map_entry_t entry;
            if (sigb_parse_maps_entry(line, &entry) && sigb_path_matches_apk(entry.path)) {
                char dev[32] = {0};
                unsigned long long ino = 0;
                if (sigb_get_rep_id_cached(dev, sizeof(dev), &ino)) {
                    char rewritten[PATH_MAX + 128];
                    snprintf(rewritten, sizeof(rewritten),
                             "%012lx-%012lx %s %08lx %s %llu %s",
                             entry.start, entry.end, entry.perms,
                             entry.offset, dev, ino, entry.path);
                    free(line);
                    line = dup_str(rewritten);
                    if (line == NULL) {
                        free(out);
                        return NULL;
                    }
                    line_len = strlen(line);
                }
            }
        }

        if (keep) {
            if (out_pos + line_len + 2 > cap) {
                size_t new_cap = cap * 2;
                if (new_cap < out_pos + line_len + 2) new_cap = out_pos + line_len + 2;
                char *grown = (char *)realloc(out, new_cap);
                if (grown == NULL) {
                    free(line);
                    free(out);
                    return NULL;
                }
                out = grown;
                cap = new_cap;
            }
            memcpy(out + out_pos, line, line_len);
            out_pos += line_len;
            if (end != NULL) {
                out[out_pos++] = '\n';
            }
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
