#include "sigbypass_core.h"

#include <stdlib.h>
#include <string.h>

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
