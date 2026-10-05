#define _GNU_SOURCE

//#define NO_INTERCEPT
#define ALLOW_ALL_USERS

#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>

typedef int (*orig_open_f_type)(const char *pathname, int flags, ...);

static orig_open_f_type orig_open = NULL;
static orig_open_f_type orig_open64 = NULL;

#ifndef NO_INTERCEPT

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <stdlib.h>
#include <limits.h>
#include <libgen.h>

#include <getdef.h>
#include <pwd.h>

#include <pthread.h>

#define SERVER_PATH "/tmp/patchmanager-socket"
#define ENV_NO_PRELOAD "NO_PM_PRELOAD"
#define ENV_DEBUG "PM_PRELOAD_DEBUG"

#define FLAG_NOPRELOAD   (1u << 2)  /* 00000100 */
#define FLAG_DEBUG       (1u << 1)  /* 00000010 */
#define FLAG_INITIALIZED (1u << 0)  /* 00000001 */

typedef unsigned char flags_t;
static flags_t pm_flags = 0;

// use pthread "once" inits
static pthread_once_t open64_once = PTHREAD_ONCE_INIT;
static pthread_once_t open_once = PTHREAD_ONCE_INIT;

static void init_from_env(void)
{
    if (getenv(ENV_DEBUG) != NULL)      pm_flags |= FLAG_DEBUG;
    if (getenv(ENV_NO_PRELOAD) != NULL) pm_flags |= FLAG_NOPRELOAD;
}

static void resolve_open64(void)
{
    // avoid "ISO C forbids conversion of object pointer to function pointer type"
    *(void **)(&orig_open64) = dlsym(RTLD_NEXT, "open64");
}

static void resolve_open(void)
{
    // avoid "ISO C forbids conversion of object pointer to function pointer type"
    *(void **)(&orig_open) = dlsym(RTLD_NEXT, "open");
}

static const char *blacklist_paths_startswith[] = {
    "/dev",
    "/sys",
    "/proc",
    "/run",
    "/tmp",
};

static const char *blacklist_paths_equal[] = {
    "/",
};

static int debug_output() {
    if (pm_flags == 0) // not initialized
        init_from_env();
    return pm_flags & FLAG_DEBUG;
}

static void pm_name(char new_name[]) {
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sun_family = AF_UNIX;
    strcpy(serveraddr.sun_path, SERVER_PATH);
    int result = connect(sockfd, (struct sockaddr *)&serveraddr, SUN_LEN(&serveraddr));

    if (result < 0) {
        if (debug_output()) {
            fprintf(stderr, "[pm_name] error connecting to socket\n");
        }
        close(sockfd);
        return;
    }

    int sn = write(sockfd, new_name, strlen(new_name));
    if (sn <= 0) {
        if (debug_output()) {
            fprintf(stderr, "[pm_name] error sending to socket\n");
        }
        close(sockfd);
        return;
    }

    char buf_name[PATH_MAX];
    memset(buf_name, 0, sizeof(buf_name));
    int rn = read(sockfd, buf_name, sizeof(buf_name) - 1);
    if (rn > 0) {
        strcpy(new_name, buf_name);
    } else {
        if (debug_output()) {
            fprintf(stderr, "[pm_name] error reading from socket\n");
        }
    }

    close(sockfd);
}

static int pm_validate_uid(uid_t uid)
{
#ifdef ALLOW_ALL_USERS
    (void)uid; // avoid -Wunused-parameter warning
    return 1;
#else // #ifdef ALLOW_ALL_USERS
    uid_t user_uid = getdef_num("UID_MIN", 100000);
    return uid >= user_uid;
#endif // #ifdef ALLOW_ALL_USERS
}

static int pm_validate_flags(int flags)
{
    return (flags & (O_APPEND | O_WRONLY | O_RDWR | O_TRUNC | O_CREAT | O_NOCTTY | O_TMPFILE | O_SYNC | O_DSYNC | O_DIRECTORY | O_DIRECT)) == 0;
}

static int pm_validate_name(const char *name)
{
    char dir_name[PATH_MAX];
    strcpy(dir_name, name);
    dirname(dir_name);

    for (unsigned int i = 0; i < sizeof(blacklist_paths_equal) / sizeof(*blacklist_paths_equal); i++) {
        const char *blacklisted = blacklist_paths_equal[i];
        if (strcmp(blacklisted, dir_name) == 0) {
            return 0;
        }
    }

    for (unsigned int i = 0; i < sizeof(blacklist_paths_startswith) / sizeof(*blacklist_paths_startswith); i++) {
        const char *blacklisted = blacklist_paths_startswith[i];
        if (strncmp(blacklisted, name, strlen(blacklisted)) == 0) {
            return 0;
        }
    }
    return 1;
}

static int no_preload() {
    if (pm_flags == 0) // not initialized
        init_from_env();
    return pm_flags & FLAG_NOPRELOAD;
}

#endif // #ifndef NO_INTERCEPT

int open64(const char *pathname, int flags, ...)
{
    pthread_once(&open64_once, resolve_open64);

    va_list args;
    va_start(args, flags);
    int mode = va_arg(args, int);
    va_end(args);

#ifndef NO_INTERCEPT

    char new_name[PATH_MAX];
    // suppress -Wunused-result warning, see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66425#c34
    (void) !realpath(pathname, new_name);

    const int d_no_preload = no_preload();
    const int d_pm_validate_uid = pm_validate_uid(getuid());
    const int d_pm_validate_flags = pm_validate_flags(flags);
    const int d_pm_validate_name = pm_validate_name(new_name);

    if (debug_output()) {
        char dir_name[PATH_MAX];
        strcpy(dir_name, new_name);
        dirname(dir_name);

        fprintf(stderr, "[open64] pid: %d, path: %s (%s), dir: %s, flags: %d, mode: %d, no_preload: %d, validate_uid: %d, validate_flags: %d, validate_name: %d\n",
                getpid(), new_name, pathname, dir_name, flags, mode, d_no_preload, d_pm_validate_uid, d_pm_validate_flags, d_pm_validate_name);
    }

    if (!d_no_preload && d_pm_validate_uid && d_pm_validate_flags && d_pm_validate_name) {
        pm_name(new_name);
        if (debug_output()) {
            fprintf(stderr, "[open64] new_name: %s\n", new_name);
        }
        return orig_open64(new_name, flags, mode);
    }

#endif // #ifndef NO_INTERCEPT

    return orig_open64(pathname, flags, mode);
}


int open(const char *pathname, int flags, ...)
{
    pthread_once(&open_once, resolve_open);

    va_list args;
    va_start(args, flags);
    int mode = va_arg(args, int);
    va_end(args);

#ifndef NO_INTERCEPT

    char new_name[PATH_MAX];
    // suppress -Wunused-result warning, see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66425#c34
    (void) !realpath(pathname, new_name);

    const int d_no_preload = no_preload();
    const int d_pm_validate_uid = pm_validate_uid(getuid());
    const int d_pm_validate_flags = pm_validate_flags(flags);
    const int d_pm_validate_name = pm_validate_name(new_name);

    if (debug_output()) {
        char dir_name[PATH_MAX];
        strcpy(dir_name, new_name);
        dirname(dir_name);

        fprintf(stderr, "[open] pid: %d, path: %s (%s), dir: %s, flags: %d, mode: %d, no_preload: %d, validate_uid: %d, validate_flags: %d, validate_name: %d\n",
                getpid(), new_name, pathname, dir_name, flags, mode, d_no_preload, d_pm_validate_uid, d_pm_validate_flags, d_pm_validate_name);
    }

    if (!d_no_preload && d_pm_validate_uid && d_pm_validate_flags && d_pm_validate_name) {
        pm_name(new_name);
        if (debug_output()) {
            fprintf(stderr, "[open] new_name: %s\n", new_name);
        }
        return orig_open(new_name, flags, mode);
    }

#endif // #ifndef NO_INTERCEPT

    return orig_open(pathname, flags, mode);
}
