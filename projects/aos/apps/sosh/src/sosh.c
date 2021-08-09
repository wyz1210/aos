/*
 * Copyright 2019, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(DATA61_GPL)
 */
/* Simple shell to run on SOS */

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <utils/time.h>
#include <syscalls.h>
/* Your OS header file */
#include <sos.h>
#include <ttyout.h>

#include "benchmark.h"

#define BUF_SIZ    (4096 * 1)
#define MAX_ARGS   32

#define SOS_WRITE 10

#define HEADER_SIZE 3

#define SMALL_BUF_SZ 2
#define MEDIUM_BUF_SZ 4096
#define LARGE_BUF_SZ (4096 * 5)

char test_str[] = "Basic test string for read/write";
char small_buf[SMALL_BUF_SZ];

/* test reading into a large on-stack buffer */
char stack_buf[MEDIUM_BUF_SZ];


static int in;
static sos_stat_t sbuf;

static size_t sos_debug_print(const void *vData, size_t count)
{
#ifdef CONFIG_DEBUG_BUILD
    size_t i;
    const char *realdata = vData;
    for (i = 0; i < count; i++) {
        seL4_DebugPutChar(realdata[i]);
    }
#endif
    return count;
}


size_t sos_write(void *vData, size_t count)
{
    return sos_sys_write(0, vData,count);
}

size_t sos_read(void *vData, size_t count)
{
    // use the content of tty test
    assert(!"implement this");
    return sos_sys_read(0, vData,count);
}

static void prstat(const char *name)
{
    /* print out stat buf */
    printf("%c%c%c%c\t%d\t0x%lx\t0x%06lx\t%s\n",
           sbuf.st_type == ST_SPECIAL ? 's' : '-',
           sbuf.st_fmode & FM_READ ? 'r' : '-',
           sbuf.st_fmode & FM_WRITE ? 'w' : '-',
           sbuf.st_fmode & FM_EXEC ? 'x' : '-',
           sbuf.st_size,
           sbuf.st_ctime,
           sbuf.st_atime,
           name);
}

static int cat(int argc, char **argv)
{
    int fd;
    char buf[BUF_SIZ];
    int num_read, stdout_fd, num_written = 0;


    if (argc != 2) {
        printf("Usage: cat filename\n");
        return 1;
    }

    printf("<%s>\n", argv[1]);

    fd = open(argv[1], O_RDONLY);
    stdout_fd = open("console", O_WRONLY);

    assert(fd >= 0);

    do{
        num_read = sos_sys_read(fd, buf, BUF_SIZ);
        num_written = sos_sys_write(stdout_fd, buf, num_read);
    } while (num_read > 0);

    if (num_read == -1 || num_written == -1) {
        printf("error on write\n");
        return 1;
    }

    close(stdout_fd);
    close(fd);

    return 0;
}

static int cp(int argc, char **argv)
{
    int fd, fd_out;
    char *file1, *file2;
    char buf[BUF_SIZ];
    int num_read, num_written = 0;

    if (argc != 3) {
        printf("Usage: cp from to\n");
        return 1;
    }

    file1 = argv[1];
    file2 = argv[2];

    fd = open(file1, O_RDONLY);
    fd_out = open(file2, O_WRONLY);

    assert(fd >= 0);

    while ((num_read = sos_sys_read(fd, buf, BUF_SIZ)) > 0) {
        num_written = sos_sys_write(fd_out, buf, num_read);
    }

    if (num_read == -1 || num_written == -1) {
        printf("error on cp, num_read = %d, num_written = %d\n", num_read, num_written);
        close(fd);
        close(fd_out);
        return 1;
    }

    close(fd);
    close(fd_out);

    return 0;
}

#define MAX_PROCESSES 32

static int ps(int argc, char **argv)
{
    sos_process_t *process;
    int i, processes;

    process = malloc(MAX_PROCESSES * sizeof(*process));

    if (process == NULL) {
        printf("%s: out of memory\n", argv[0]);
        return 1;
    }

    processes = sos_process_status(process, MAX_PROCESSES);

    printf("TID\tSIZE\tSTIME   \tCOMMAND\n");

    for (i = 0; i < processes; i++) {
        printf("%3d\t%4d\t%7d\t%s\n", process[i].pid, process[i].size,
               process[i].stime, process[i].command);
    }

    free(process);

    return 0;
}

static int exec_test(int argc, char **argv)
{
    pid_t pid;
    int r;

    if (argc < 2 || (argc > 2 && argv[2][0] != '&')) {
        printf("Usage: exec_test filename [&]\n");
        return 1;
    }

    pid = sos_process_create(argv[1]);
    if (pid >= 0) {
        printf("Child pid=%d\n", pid);
    } else {
        printf("Failed!\n");
    }
    return 0;
}

static int exec(int argc, char **argv)
{
    pid_t pid;
    int r;
    int bg = 0;

    if (argc < 2 || (argc > 2 && argv[2][0] != '&')) {
        printf("Usage: exec filename [&]\n");
        return 1;
    }

    if ((argc > 2) && (argv[2][0] == '&')) {
        bg = 1;
    }

    if (bg == 0) {
        r = close(in);
        assert(r == 0);
    }

    pid = sos_process_create(argv[1]);
    if (pid >= 0) {
        printf("Child pid=%d\n", pid);
        if (bg == 0) {
            sos_process_wait(pid);
        }
    } else {
        printf("Failed!\n");
    }
    if (bg == 0) {
        printf("%d recover\n", sos_my_id());
        in = open("console", O_RDONLY);
        assert(in >= 0);
    }
    return 0;
}

static int dir(int argc, char **argv)
{
    int i = 0, r;
    char buf[BUF_SIZ];

    if (argc > 2) {
        printf("usage: %s [file]\n", argv[0]);
        return 1;
    }

    if (argc == 2) {
        r = sos_stat(argv[1], &sbuf);
        if (r < 0) {
            printf("stat(%s) failed: %d\n", argv[1], r);
            return 0;
        }
        prstat(argv[1]);
        return 0;
    }

    while (1) {
        r = sos_getdirent(i, buf, BUF_SIZ);
        if (r < 0) {
            printf("dirent(%d) failed: %d\n", i, r);
            break;
        } else if (!r) {
            break;
        }
        r = sos_stat(buf, &sbuf);
        if (r < 0) {
            printf("stat(%s) failed: %d\n", buf, r);
            break;
        }
        prstat(buf);
        i++;
    }
    return 0;
}

static int second_sleep(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage %s seconds\n", argv[0]);
        return 1;
    }
    sleep(atoi(argv[1]));
    return 0;
}

static int milli_sleep(int argc, char *argv[])
{
    struct timespec tv;
    uint64_t nanos;
    if (argc != 2) {
        printf("Usage %s milliseconds\n", argv[0]);
        return 1;
    }
    nanos = (uint64_t)atoi(argv[1]) * NS_IN_MS;
    /* Get whole seconds */
    tv.tv_sec = nanos / NS_IN_S;
    /* Get nanos remaining */
    tv.tv_nsec = nanos % NS_IN_S;
    nanosleep(&tv, NULL);
    return 0;
}

static int second_time(int argc, char *argv[])
{
    printf("%d seconds since boot\n", (int)time(NULL));
    return 0;
}

static int micro_time(int argc, char *argv[])
{
    struct timeval time;
    gettimeofday(&time, NULL);
    uint64_t micros = (uint64_t)time.tv_sec * US_IN_S + (uint64_t)time.tv_usec;
    printf("%lu microseconds since boot\n", micros);
    return 0;
}

static int kill(int argc, char *argv[])
{
    pid_t pid;
    if (argc != 2) {
        printf("Usage: kill pid\n");
        return 1;
    }

    pid = atoi(argv[1]);
    return sos_process_delete(pid);
}

void nfs_test(){
    printf("=== begin nfs_test ===\n");

    int fd = sos_sys_open("test.txt", O_RDWR);
    printf("[open]\tfd = %d\n", fd);
    assert(fd > 3);

    printf("[ls]\n");
    char dir_buf[128];
    int i = 0, r;
    while (1) {
        r = sos_getdirent(i, dir_buf, 128);
        if (r < 0) {
            printf("dirent(%d) failed: %d\n", i, r);
            break;
        } else if (!r) {
            break;
        }
        r = sos_stat(dir_buf, &sbuf);
        if (r < 0) {
            printf("stat(%s) failed: %d\n", dir_buf, r);
            break;
        }
        prstat(dir_buf);
        i++;
    }


    char *buf = malloc(sizeof(char) * (LARGE_BUF_SZ + 1));
    memset(buf, '1', sizeof(char) * LARGE_BUF_SZ);
    buf[LARGE_BUF_SZ] = '\0';
    printf("[write]\tbuf_size = %lu\n", strlen(buf));
    int write_len = sos_sys_write(fd, buf, strlen(buf));
    assert(write_len == strlen(buf));

    int error = sos_sys_close(fd);
    assert(error == 0);
    printf("[close]\tfd = %d\n", fd);

    fd = sos_sys_open("test.txt", O_RDWR);
    printf("[open]\tfd = %d\n", fd);
    assert(fd > 3);

    char *read_buf = malloc(sizeof(char) * (LARGE_BUF_SZ + 1));
    memset(read_buf, 0 , sizeof(char) * (LARGE_BUF_SZ + 1));
    int read_len = sos_sys_read(fd, read_buf, strlen(buf));
    printf("[read]\tbuf_size = %lu\n", strlen(read_buf));
    assert(read_len == strlen(buf));
    assert(strcmp(read_buf, buf) == 0);

    sos_sys_close(fd);

    printf("=== nfs_test passed ===\n");
}

static int benchmark(int argc, char *argv[])
{

    nfs_test();
//    assert(!"no benchmark ready!");

    printf("=== begin benchmark test ===\n");

    if (argc == 2 && strcmp(argv[1], "-d") == 0) {
        printf("Running benchmark in DEBUG mode\n");
        return sos_benchmark(1);
    } else if (argc == 1) {
        printf("Running benchmark\n");
        return sos_benchmark(0);
    } else {
        printf("Unknown option to %s\n", argv[0]);
        return -1;
    }
}

struct command {
    char *name;
    int (*command)(int argc, char **argv);
};

struct command commands[] = { { "dir", dir }, { "ls", dir }, { "cat", cat }, {
        "cp", cp
    }, { "ps", ps }, { "exec", exec },{ "exec_test", exec_test },  {"sleep", second_sleep}, {"msleep", milli_sleep},
    {"time", second_time}, {"mtime", micro_time}, {"kill", kill},
    {"benchmark", benchmark}
};



int test_buffers(int console_fd) {
    /* test a small string from the code segment */
    int result = sos_sys_write(console_fd, test_str, strlen(test_str));
    assert(result == strlen(test_str));

    /* test reading to a small buffer */
    printf("[test_buffers] small_buf = 0x%016lx\n", small_buf);
    result = sos_sys_read(console_fd, small_buf, SMALL_BUF_SZ);
    /* make sure you type in at least SMALL_BUF_SZ */
    assert(result == SMALL_BUF_SZ);

    /* for this test you'll need to paste a lot of data into
       the console, without newlines */
    result = sos_sys_read(console_fd, stack_buf, MEDIUM_BUF_SZ);
    printf("read MEDIUM_BUF_SZ = %d\n", result);
    assert(result == MEDIUM_BUF_SZ);

    result = sos_sys_write(console_fd, stack_buf, MEDIUM_BUF_SZ);
    assert(result == MEDIUM_BUF_SZ);

    /* try sleeping */
    for (int i = 0; i < 5; i++) {
        time_t prev_seconds = sos_sys_time_stamp();
        sos_sys_usleep(1000);
        time_t next_seconds = sos_sys_time_stamp();
        assert(next_seconds > prev_seconds);
        printf("Tick\n");
    }

    int error = sos_sys_close(console_fd);
    assert(error == 0);

    printf("=== test_buffers finished ===\n");

    return 0;
}



int main(void)
{
    sosapi_init_syscall_table();

    char buf[BUF_SIZ];
    char *argv[MAX_ARGS];
    int i, r, done, found, new, argc;
    char *bp, *p;

    in = open("console", O_RDONLY);
    assert(in >= 0);

//    printf("=== begin console tests ===\n");
//    test_buffers(in);

//    printf("=== begin benchmark tests ===\n");
//    sos_benchmark(1);
//    printf("=== finish benchmark tests ===\n");

    bp = buf;
    done = 0;
    new = 1;

    printf("\n[SOS Starting]\n");

//    fflush(stdout);
//    r = read(in, bp, BUF_SIZ - 1 + buf - bp);

    while (!done) {
        if (new) {
            printf("$ ");
        }
        new = 0;
        found = 0;

        while (!found && !done) {
            /* Make sure to flush so anything is visible while waiting for user input */
            fflush(stdout);
            r = read(in, bp, BUF_SIZ - 1 + buf - bp);
            if (r < 0) {
                printf("Console read failed!\n");
                done = 1;
                break;
            }
            bp[r] = 0; /* terminate */
            for (p = bp; p < bp + r; p++) {
                if (*p == '\03') { /* ^C */
                    printf("^C\n");
                    p = buf;
                    new = 1;
                    break;
                } else if (*p == '\04') { /* ^D */
                    p++;
                    found = 1;
                } else if (*p == '\010' || *p == 127) {
                    /* ^H and BS and DEL */
                    if (p > buf) {
                        printf("\010 \010");
                        p--;
                        r--;
                    }
                    p--;
                    r--;
                } else if (*p == '\n') { /* ^J */
                    printf("%c", *p);
                    *p = 0;
                    found = p > buf;
                    p = buf;
                    new = 1;
                    break;
                } else {
                    printf("%c", *p);
                }
            }
            bp = p;
            if (bp == buf) {
                break;
            }
        }

        if (!found) {
            continue;
        }

        argc = 0;
        p = buf;

        while (*p != '\0') {
            /* Remove any leading spaces */
            while (*p == ' ') {
                p++;
            }
            if (*p == '\0') {
                break;
            }
            argv[argc++] = p; /* Start of the arg */
            while (*p != ' ' && *p != '\0') {
                p++;
            }

            if (*p == '\0') {
                break;
            }

            /* Null out first space */
            *p = '\0';
            p++;
        }

        if (argc == 0) {
            continue;
        }

        found = 0;

        for (i = 0; i < sizeof(commands) / sizeof(struct command); i++) {
            if (strcmp(argv[0], commands[i].name) == 0) {
                commands[i].command(argc, argv);
                found = 1;
                break;
            }
        }

        /* Didn't find a command */
        if (found == 0) {
            /* They might try to exec a program */
            if (sos_stat(argv[0], &sbuf) != 0) {
                printf("Command \"%s\" not found\n", argv[0]);
            } else if (!(sbuf.st_fmode & FM_EXEC)) {
                printf("File \"%s\" not executable\n", argv[0]);
            } else {
                /* Execute the program */
                argc = 2;
                argv[1] = argv[0];
                argv[0] = "exec";
                exec(argc, argv);
            }
        }
    }
    printf("[SOS Exiting]\n");
}
