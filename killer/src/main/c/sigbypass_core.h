#ifndef SIGBYPASS_CORE_H
#define SIGBYPASS_CORE_H

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

#ifdef __cplusplus
}
#endif

#endif /* SIGBYPASS_CORE_H */
