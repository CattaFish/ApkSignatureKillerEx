#ifndef SIGBYPASS_CORE_H
#define SIGBYPASS_CORE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 状态：正常对外服务 / hook 自身重入 / 探测函数直读原始数据 */
#define SIGB_STATE_NORMAL   0
#define SIGB_STATE_REENTRY  1
#define SIGB_STATE_PROBE    2

void sigb_set_target_paths(const char *apk, const char *rep);
const char *sigb_get_apk_path(void);
const char *sigb_get_rep_path(void);

/* 命中 apkPath 返回 repPath，否则原样返回（NULL 安全） */
const char *sigb_resolve(const char *path);

void sigb_set_state(int state);
int sigb_get_state(void);
int sigb_is_normal(void);
int sigb_is_reentry(void);
int sigb_is_probe(void);

/* ================= Step 3: tool layer ================= */

#define SIGB_MAP_PATH_MAX 4096

typedef struct {
    unsigned long start;
    unsigned long end;
    unsigned long offset;
    unsigned long long inode;
    char perms[8];
    char dev[32];
    char path[SIGB_MAP_PATH_MAX];
} sigb_map_entry_t;

int sigb_create_memfd(const char *name, const char *content, size_t len);
int sigb_parse_maps_entry(const char *line, sigb_map_entry_t *entry);
int sigb_contains_sensitive_word(const char *text);
char *sigb_sanitize_maps(const char *content, int is_smaps);
int sigb_raw_open(const char *path);
char *sigb_raw_read_fd(int fd);
char *sigb_raw_readlink(const char *path);
int sigb_should_sanitize_proc(const char *path);
int sigb_maybe_relevant(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* SIGBYPASS_CORE_H */
