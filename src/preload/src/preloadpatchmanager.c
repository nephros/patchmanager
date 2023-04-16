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

#define SERVER_PATH "/tmp/patchmanager-socket"
#define ENV_NO_PRELOAD "NO_PM_PRELOAD"
#define ENV_DEBUG "PM_PRELOAD_DEBUG"

static const char *blacklist_paths_startswith[] = {
    "/dev",
    "/sys",
    "/proc",
    "/run",
    "/tmp",
    "/lost+found",
    // firmware and vendor stuff
    "/mnt/vendor",
    "/apex",
    "/data",
    "/linkerconfig",
    "/metadata",
    "/odm",
    "/oem",
    "/system",
    "/system_ext",
    "/vendor",
    // security
    "/etc/pki",            // certificates
    "/usr/lib/security",   // PAM modules
    "/usr/lib64/security", // PAM modules
    // common calls locations:
    "/usr/libexec/droid-hybris/system",
    "/var/cache/fontconfig",
};

static const char *blacklist_paths_equal[] = {
    "/",
    // ourselves
    "/usr/lib/libpreloadpatchmanager.so",
    "/usr/lib64/libpreloadpatchmanager.so",
    // very common open()s, ignore for performance:
    "/etc/ld.so.preload",
    "/etc/ld.so.cache",
    "/lib/libc.so.6",
    "/lib/libdl.so.2",
    "/lib/libgcc_s.so.1",
    "/lib/libm.so.1",
    "/lib/libnss_db.so.2",
    "/lib/libnss_files.so.2",
    "/lib/libpthread.so.0",
    "/lib/libresolv.so.2",
    "/lib/librt.so.1",
    "/lib64/libc.so.6",
    "/lib64/libdl.so.2",
    "/lib64/libgcc_s.so.1",
    "/lib64/libm.so.1",
    "/lib64/libnss_db.so.2",
    "/lib64/libnss_files.so.2",
    "/lib64/libpthread.so.0",
    "/lib64/libresolv.so.2",
    "/lib64/librt.so.1",
    "/usr/lib/libEGL.so.1",
    "/usr/lib/libGLESv2.so.2",
    "/usr/lib/libQt5Core.so.5",
    "/usr/lib/libQt5DBus.so.5",
    "/usr/lib/libQt5Gui.so.5",
    "/usr/lib/libQt5Network.so.5",
    "/usr/lib/libQt5Qml.so.5",
    "/usr/lib/libQt5Quick.so.5",
    "/usr/lib/libQt5WaylandClient.so.5",
    "/usr/lib/libblkid.so.1",
    "/usr/lib/libbz2.so.1",
    "/usr/lib/libcap.so.2",
    "/usr/lib/libcrypto.so.1.1",
    "/usr/lib/libdbus-1.so.3",
    "/usr/lib/libdconf.so.1",
    "/usr/lib/libexpat.so.1",
    "/usr/lib/libffi.so.6",
    "/usr/lib/libfontconfig.so.1",
    "/usr/lib/libfreetype.so.6",
    "/usr/lib/libgcrypt.so.20",
    "/usr/lib/libgio-2.0.so.0",
    "/usr/lib/libglib-2.0.so.0",
    "/usr/lib/libgmodule-2.0.so.0",
    "/usr/lib/libgobject-2.0.so.0",
    "/usr/lib/libgpg-error.so.0",
    "/usr/lib/libgralloc.so.1",
    "/usr/lib/libhardware.so.2",
    "/usr/lib/libhybris-common.so.1",
    "/usr/lib/libhybris-eglplatformcommon.so.1",
    "/usr/lib/libhybris//eglplatform_wayland.so",
    "/usr/lib/libhybris/linker/q.so",
    "/usr/lib/libicudata.so.68",
    "/usr/lib/libicui18n.so.68",
    "/usr/lib/libicuuc.so.68",
    "/usr/lib/liblzma.so.5",
    "/usr/lib/libmdeclarativecache5.so.0",
    "/usr/lib/libmlite5.so.0",
    "/usr/lib/libmount.so.1",
    "/usr/lib/libpcre.so.1",
    "/usr/lib/libpcre16.so.0",
    "/usr/lib/libpng16.so.16",
    "/usr/lib/libpreloadpatchmanager.so",
    "/usr/lib/libproxy.so.1",
    "/usr/lib/libsailfishapp.so.1",
    "/usr/lib/libselinux.so.1",
    "/usr/lib/libssl.so.1.1",
    "/usr/lib/libstdc++.so.6",
    "/usr/lib/libsync.so.2",
    "/usr/lib/libsystemd.so.0",
    "/usr/lib/libuuid.so.1",
    "/usr/lib/libwayland-client.so.0",
    "/usr/lib/libwayland-cursor.so.0",
    "/usr/lib/libwayland-egl.so.1",
    "/usr/lib/libwayland-server.so.0",
    "/usr/lib/libxkbcommon.so.0",
    "/usr/lib/libz.so.1",
    "/usr/lib/locale/locale-archive",
    "/usr/lib/qt5/plugins/platforminputcontexts",
    "/usr/lib/qt5/plugins/platforminputcontexts/libmaliitplatforminputcontextplugin.so",
    "/usr/lib/qt5/plugins/platforms",
    "/usr/lib/qt5/plugins/platforms/libhwcomposer.so",
    "/usr/lib/qt5/plugins/platforms/libqminimal.so",
    "/usr/lib/qt5/plugins/platforms/libqwayland-egl.so",
    "/usr/lib/qt5/plugins/platforms/libqwayland-generic.so",
    "/usr/lib/qt5/plugins/wayland-graphics-integration-client",
    "/usr/lib/qt5/plugins/wayland-graphics-integration-client/libdrm-egl-server.so",
    "/usr/lib/qt5/plugins/wayland-graphics-integration-client/libwayland-egl.so",
    "/usr/lib64/libEGL.so.1",
    "/usr/lib64/libGLESv2.so.2",
    "/usr/lib64/libQt5Core.so.5",
    "/usr/lib64/libQt5DBus.so.5",
    "/usr/lib64/libQt5Gui.so.5",
    "/usr/lib64/libQt5Network.so.5",
    "/usr/lib64/libQt5Qml.so.5",
    "/usr/lib64/libQt5Quick.so.5",
    "/usr/lib64/libQt5WaylandClient.so.5",
    "/usr/lib64/libblkid.so.1",
    "/usr/lib64/libbz2.so.1",
    "/usr/lib64/libcap.so.2",
    "/usr/lib64/libcrypto.so.1.1",
    "/usr/lib64/libdbus-1.so.3",
    "/usr/lib64/libdconf.so.1",
    "/usr/lib64/libexpat.so.1",
    "/usr/lib64/libffi.so.6",
    "/usr/lib64/libfontconfig.so.1",
    "/usr/lib64/libfreetype.so.6",
    "/usr/lib64/libgcrypt.so.20",
    "/usr/lib64/libgio-2.0.so.0",
    "/usr/lib64/libglib-2.0.so.0",
    "/usr/lib64/libgmodule-2.0.so.0",
    "/usr/lib64/libgobject-2.0.so.0",
    "/usr/lib64/libgpg-error.so.0",
    "/usr/lib64/libgralloc.so.1",
    "/usr/lib64/libhardware.so.2",
    "/usr/lib64/libhybris-common.so.1",
    "/usr/lib64/libhybris-eglplatformcommon.so.1",
    "/usr/lib64/libhybris//eglplatform_wayland.so",
    "/usr/lib64/libhybris/linker/q.so",
    "/usr/lib64/libicudata.so.68",
    "/usr/lib64/libicui18n.so.68",
    "/usr/lib64/libicuuc.so.68",
    "/usr/lib64/liblzma.so.5",
    "/usr/lib64/libmdeclarativecache5.so.0",
    "/usr/lib64/libmlite5.so.0",
    "/usr/lib64/libmount.so.1",
    "/usr/lib64/libpcre.so.1",
    "/usr/lib64/libpcre16.so.0",
    "/usr/lib64/libpng16.so.16",
    "/usr/lib64/libpreloadpatchmanager.so",
    "/usr/lib64/libproxy.so.1",
    "/usr/lib64/libsailfishapp.so.1",
    "/usr/lib64/libselinux.so.1",
    "/usr/lib64/libssl.so.1.1",
    "/usr/lib64/libstdc++.so.6",
    "/usr/lib64/libsync.so.2",
    "/usr/lib64/libsystemd.so.0",
    "/usr/lib64/libuuid.so.1",
    "/usr/lib64/libwayland-client.so.0",
    "/usr/lib64/libwayland-cursor.so.0",
    "/usr/lib64/libwayland-egl.so.1",
    "/usr/lib64/libwayland-server.so.0",
    "/usr/lib64/libxkbcommon.so.0",
    "/usr/lib64/libz.so.1",
    "/usr/lib64/qt5/plugins/platforminputcontexts",
    "/usr/lib64/qt5/plugins/platforminputcontexts/libmaliitplatforminputcontextplugin.so",
    "/usr/lib64/qt5/plugins/platforms",
    "/usr/lib64/qt5/plugins/platforms/libhwcomposer.so",
    "/usr/lib64/qt5/plugins/platforms/libqminimal.so",
    "/usr/lib64/qt5/plugins/platforms/libqwayland-egl.so",
    "/usr/lib64/qt5/plugins/platforms/libqwayland-generic.so",
    "/usr/lib64/qt5/plugins/wayland-graphics-integration-client",
    "/usr/lib64/qt5/plugins/wayland-graphics-integration-client/libdrm-egl-server.so",
    "/usr/lib64/qt5/plugins/wayland-graphics-integration-client/libwayland-egl.so",
    "/usr/share/locale/locale.alias",
    // security
    "/etc/sudoers",
    "/etc/passwd",
    "/etc/passwd-",
    "/etc/group",
    "/etc/group-",
    "/etc/shadow",
    "/etc/shadow-",
};

static int debug_output() {
    static int debug_output_read = 0;
    static int debug_output_value = 0;

    if (!debug_output_read) {
        debug_output_value = getenv(ENV_DEBUG) ? 1 : 0;
        debug_output_read = 1;
    }

    return debug_output_value;
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
    static int pm_preload_read = 0;
    static int no_pm_preload = 0;

    if (!pm_preload_read) {
        no_pm_preload = getenv(ENV_NO_PRELOAD) ? 1 : 0;
        pm_preload_read = 1;
    }

    return no_pm_preload;
}

#endif // #ifndef NO_INTERCEPT

int open64(const char *pathname, int flags, ...)
{
    if (!orig_open64) {
        orig_open64 = (orig_open_f_type)dlsym(RTLD_NEXT, "open64");
    }

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
    if (!orig_open) {
        orig_open = (orig_open_f_type)dlsym(RTLD_NEXT, "open");
    }

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
