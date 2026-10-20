/* Non-core Linux test fixture. Pause only after the real fsync of the exact
 * synthetic provider audit's selected completed row. Never install in production.
 * No credential/audit contents leave the process; markers contain one byte. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int (*underlying_fsync)(int);
static atomic_uint completions;

__attribute__((constructor)) static void initialize(void) {
    underlying_fsync = (int (*)(int))dlsym(RTLD_NEXT, "fsync");
    if (!underlying_fsync) _exit(85);
}

static int is_completed_audit(int fd, const char *expected) {
    char descriptor[64], path[PATH_MAX], tail[4097];
    struct stat info;
    snprintf(descriptor, sizeof descriptor, "/proc/self/fd/%d", fd);
    ssize_t length = readlink(descriptor, path, sizeof path - 1);
    if (length < 0) return 0;
    path[length] = 0;
    if (strcmp(path, expected) || fstat(fd, &info) || info.st_size < 1) return 0;
    off_t start = info.st_size > 4096 ? info.st_size - 4096 : 0;
    length = pread(fd, tail, sizeof tail - 1, start);
    if (length < 1 || tail[length - 1] != '\n') return 0;
    tail[length - 1] = 0;
    const char *row = strrchr(tail, '\n');
    row = row ? row + 1 : tail;
    return strstr(row, "\"event\":\"completed\"") != NULL;
}

int fsync(int fd) {
    int result = underlying_fsync(fd);
    int saved_errno = errno;
    const char *audit = getenv("AIVM_TEST_COMPLETION_AUDIT");
    const char *ready = getenv("AIVM_TEST_COMPLETION_READY");
    const char *release = getenv("AIVM_TEST_COMPLETION_RELEASE");
    if (!result && audit && ready && release &&
        is_completed_audit(fd, audit)) {
        const char *configured = getenv("AIVM_TEST_COMPLETION_NUMBER");
        unsigned long number = configured ? strtoul(configured, NULL, 10) : 1;
        if (!number || number > 8) _exit(88);
        if (atomic_fetch_add(&completions, 1) + 1 != number) {
            errno = saved_errno;
            return result;
        }
        int marker = open(ready, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (marker < 0 || write(marker, "1", 1) != 1) _exit(86);
        close(marker);
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 10000000 };
        int attempts;
        for (attempts = 0; attempts < 1000; ++attempts) {
            if (!access(release, F_OK)) break;
            nanosleep(&pause, NULL);
        }
        /* Bound cleanup if the test/controller dies while the broker waits. */
        if (attempts == 1000) _exit(87);
    }
    errno = saved_errno;
    return result;
}
