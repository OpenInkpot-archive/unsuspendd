/*
 * Copyright © 2010 Mikhail Gusarov <dottedmag@dottedmag.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#define _GNU_SOURCE 1
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include "unsuspend.h"

#define AUTOSUSPEND "/sys/power/autosuspend"
#define DEFAULT_PIDFILE "/var/run/unsuspendd.pid"

#define UNIX_PATH_MAX 108
#define MAXLENGTH 4096
#define BUFSIZE 256

static int signal_received;
static bool use_syslog;
static bool debug;

/*
 * TODO: as soon as sysvinit is dropped in IPlinux, stop syslogging and use
 * functions from <err.h> to log to stderr
 */

static void
dbg(const char *fmt, ...)
{
    if (debug) {
        va_list ap;
        va_start(ap, fmt);
        if (use_syslog) {
            vsyslog(LOG_DEBUG, fmt, ap);
        } else {
            fprintf(stderr, "D: ");
            vfprintf(stderr, fmt, ap);
            fprintf(stderr, "\n");
        }
        va_end(ap);
    }
}

static void
err(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (use_syslog) {
        vsyslog(LOG_ERR, fmt, ap);
    } else {
        fprintf(stderr, "E: ");
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
    }
    va_end(ap);
}

static void
crit(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (use_syslog) {
        vsyslog(LOG_CRIT, fmt, ap);
    } else {
        fprintf(stderr, "C: ");
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
    }
    va_end(ap);
    exit(1);
}

/* * locks * */

typedef struct _lock {
    char *name;
    struct _lock *next;
} lock;

/*
 * this list contains "fake" entry with name == NULL at the head.
 */
static lock locks;

static bool
have_locks(void)
{
    return locks.next != NULL;
}

static bool
add_lock(const char *name)
{
    lock *cur = locks.next;
    while (cur) {
        if (!strcmp(cur->name, name))
            return false;
        cur = cur->next;
    }
    lock *newlock = calloc(1, sizeof(lock));
    newlock->name = strdup(name);
    newlock->next = locks.next;
    locks.next = newlock;
    return true;
}

static bool
remove_lock(const char *name)
{
    lock *prev = &locks;
    while (prev->next) {
        if (!strcmp(prev->next->name, name)) {
            lock *found = prev->next;
            prev->next = found->next;
            free(found->name);
            free(found);
            return true;
        }
        prev = prev->next;
    }
    return false;
}

/* * clients * */

typedef struct _client {
    int fd;
    char *buf;
    int len;

    struct _client *next;
} client;

/*
 * this list contains "fake" entry at the beginning.
 */
static client clients;

static void
add_client(int fd)
{
    client *newclient = calloc(1, sizeof(client));
    newclient->fd = fd;
    newclient->next = clients.next;
    clients.next = newclient;

    dbg("client %d is connected", fd);
}

static client *
find_client(int fd)
{
    client *cur = clients.next;
    while (cur) {
        if (cur->fd == fd)
            return cur;
        cur = cur->next;
    }
    return NULL;
}

static void
remove_client(client *c)
{
    client *prev = &clients;
    while (prev->next) {
        if (prev->next->fd == c->fd) {
            client *found = prev->next;
            prev->next = found->next;
            return;
        }
        prev = prev->next;
    }
}

static void
free_client(client *c)
{
    dbg("client %d is removed", c->fd);

    close(c->fd);
    free(c->buf);
    free(c);
}

static int
count_clients(void)
{
    int count = 0;
    client *cur = clients.next;
    while (cur) {
        count++;
        cur = cur->next;
    }
    return count;
}

static bool
have_clients(void)
{
    return clients.next != NULL;
}

/* socket stuff */

/* autosuspend */

static bool
can_autosuspend(void)
{
    return !have_clients() && !have_locks();
}

static void
set_autosuspend(void)
{
    char mode = can_autosuspend() ? '1' : '0';

    dbg("autosuspend: %c", mode);

    int fd = open(AUTOSUSPEND, O_WRONLY);
    if (fd == -1)
        err("unable to open autosuspend file: %s", strerror(errno));

    if (fd != -1 && write(fd, &mode, 1) != 1)
        err("unable to write mode to autosuspend file: %s", strerror(errno));

    if (fd != -1 && close(fd) == -1)
        err("unable to close autosuspend file: %s", strerror(errno));
}

/* */

static void
create_pidfile(const char *pid_file)
{
    int fd = creat(pid_file, 0644);
    if (fd == -1)
        crit("unable to open pidfile: %s", strerror(errno));
    char pid[10] = "";
    snprintf(pid, 9, "%d\n", getpid());
    if (write(fd, pid, strlen(pid)) != strlen(pid))
        crit("unable to write pid to pidfile: %s", strerror(errno));
    if (close(fd) == -1)
        crit("unable to close pidfile: %s", strerror(errno));
}

static int
min(int a, int b)
{
    return a < b ? a : b;
}

static int
setup_server_socket(const char* socket_path)
{
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd == -1)
        crit("unable to open socket: %s", strerror(errno));

    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
    };
    memcpy(addr.sun_path, socket_path,
           min(UNIX_PATH_MAX, strlen(socket_path) + 1));

    /*
     * Try to connect and bail out if there is something on another side of
     * socket.
     */
    if (connect(server_fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0) {
        crit("server is already running");
    } else if (errno != ECONNREFUSED) {
        crit("unable to check server presence: %s", strerror(errno));
    }

    /* There may be socket file aready. Remove it. */
    unlink(socket_path);

    if (bind(server_fd, (struct sockaddr *)&addr,
             sizeof(struct sockaddr_un)) == -1)
        crit("unable to bind socket to address: %s", strerror(errno));

    if (listen(server_fd, 5) == -1)
        crit("unable to listen on socket: %s", strerror(errno));

    return server_fd;
}

static struct pollfd *
fill_fdlist(int server_fd, int *count)
{
    *count = 1 + count_clients();
    struct pollfd *fds = calloc(*count, sizeof(struct pollfd));

    fds[0].fd = server_fd;
    fds[0].events = POLLIN;

    client *c = clients.next;
    for(int i = 1; i < *count; ++i) {
        fds[i].fd = c->fd;
        fds[i].events = POLLIN | POLLRDHUP;
        c = c->next;
    }

    return fds;
}

static void
accept_client(int server_fd)
{
    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd == -1)
        err("can't accept client connection: %s", strerror(errno));
    add_client(client_fd);
}

static void
print_peer_info(FILE *out, int fd)
{
    struct ucred cr;
    socklen_t cr_len = sizeof(struct ucred);

    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &cr_len) == -1) {
        /* Okay, we can't say anything about this fd */
        return;
    }

    fprintf(out, " [%5d]", cr.pid);

    char argsfile[BUFSIZE] = "";
    snprintf(argsfile, BUFSIZE - 1, "/proc/%d/cmdline", cr.pid);

    FILE *argsfh = fopen(argsfile, "r");
    if (!argsfh) {
        /* Okay, we can't open cmdline file */
        return;
    }

    char args[BUFSIZE] = "";
    if (fread(args, 1, BUFSIZE-1, argsfh) == 0) {
        /* Okay, we can't read cmdline */
        fclose(argsfh);
        return;
    }

    /* Nice. We've got the cmdline. Let's print first part of it and uid/gid */
    fprintf(out, " %s (uid:%d, gid:%d)", args, cr.uid, cr.gid);

    fclose(argsfh);
}

static FILE *
fork_handler(client *c)
{
    pid_t child = fork();
    if (child)
        return NULL;

    remove_client(c); /* So the current connection won't be counted */

    FILE *out = fdopen(c->fd, "w");
    if (!out)
        err("can't turn fd into FILE for writing info: %s", strerror(errno));

    return out;
}

static void
close_handler(client *c, FILE *out)
{
    fclose(out);
    exit(0);
    /* free_client: handled by exit(3) */
}

static void
emit_info(client *c)
{
    FILE *out = fork_handler(c);
    if (!out)
        return;

    fprintf(out, "Locks held:");

    for (lock *cur = locks.next; cur; cur = cur->next)
        fprintf(out, " %s", cur->name);
    fprintf(out, "\n");

    fprintf(out, "Clients connected:\n");

    for (client *cur = clients.next; cur; cur = cur->next) {
        fprintf(out, " (fd:%d)", cur->fd);
        print_peer_info(out, cur->fd);
        fprintf(out, "\n");
    }

    close_handler(c, out);
}

static void
emit_status(client *c)
{
    FILE *out = fork_handler(c);
    if (!out)
        return;

    fprintf(out, "Autosuspend is %s\n", can_autosuspend() ? "on" : "off");

    close_handler(c, out);
}

static char *
get_command(char *buf, int len)
{
    for (char *c = buf; c < buf + len; c++)
        if (isspace(*c)) {
            char *cmd = malloc(c - buf + 1);
            memcpy(cmd, buf, c - buf);
            cmd[c - buf] = 0;
            return cmd;
        }

    char *cmd = malloc(len + 1);
    memcpy(cmd, buf, len);
    cmd[len] = 0;
    return cmd;
}

static char *
get_arg(char *buf, int len)
{
    for (char *c = buf; c < buf + len; c++) {
        if (isspace(*c)) {
            /* Skip whitespace */
            while (c < buf + len && isspace(*c)) c++;
            if (c == buf + len)
                return NULL;

            char *arg = malloc(len - (c - buf) + 1);
            memcpy(arg, c, len - (c - buf));
            arg[len - (c - buf)] = 0;
            return arg;
        }
    }
    return NULL;
}

static void
process_client_action(client *c)
{
    char *cmd = get_command(c->buf, c->len);
    char *arg = NULL;

    dbg("processing command %s", cmd);

    if (!strcmp(cmd, "lock")) {
        arg = get_arg(c->buf, c->len);
        if (!arg)
            goto out;
        if (add_lock(arg))
            dbg("creating lock %s", arg);
        else
            dbg("duplicate lock %s is skipped", arg);
    } else if (!strcmp(cmd, "unlock")) {
        arg = get_arg(c->buf, c->len);
        if (!arg)
            goto out;
        if (remove_lock(arg))
            dbg("removing lock %s", arg);
        else
            dbg("removing lock %s which is not held is ignored", arg);
    } else if (!strcmp(cmd, "info")) {
        emit_info(c);
    } else if (!strcmp(cmd, "status")) {
        emit_status(c);
    }

out:
    free(arg);
    free(cmd);
}

static void
finish_client(client *c)
{
    if (c->buf)
        process_client_action(c);

    remove_client(c);
    free_client(c);
}

static void
process_client(client *c)
{
    char buf[BUFSIZE];
    int read_ = read(c->fd, buf, BUFSIZE);
    if (read_ == 0)
        finish_client(c);
    else if (read_ == -1) {
        if (errno == EAGAIN || errno == EINTR)
            return;
        err("unable to read data from socket: %s", strerror(errno));
        remove_client(c);
        free_client(c);
        return;
    } else {
        c->buf = realloc(c->buf, c->len + read_);
        memcpy(c->buf + c->len, buf, read_);
        c->len += read_;

        if (c->len > MAXLENGTH) {
            err("overlong line received from client %d, dropping it", c->fd);
            remove_client(c);
            free_client(c);
        }
    }
}

static void
cleanup(int signo)
{
    signal_received = signo;
}

static void
run(int server_fd)
{
    signal(SIGTERM, cleanup);
    signal(SIGINT, cleanup);
    signal(SIGQUIT, cleanup);

    while (!signal_received) {
        int count;
        struct pollfd *fds = fill_fdlist(server_fd, &count);

        if (poll(fds, count, -1) == -1) {
            if (errno != EINTR && errno != EAGAIN)
                err("error waiting for data: %s", strerror(errno));
            free(fds);
            continue;
        }

        if (fds[0].revents) {
            if (fds[0].revents & POLLIN)
                accept_client(server_fd);
            else
                crit("error poll(3)ing on server socket: %s", strerror(errno));
        }

        for (int i = 1; i < count; ++i) {
            client *c = find_client(fds[i].fd);
            if (!c) {
                err("no client with fd %d is registered", fds[i].fd);
                free(fds);
                continue;
            }
            if (fds[i].revents & POLLIN)
                process_client(c);
            else if (fds[i].revents & (POLLRDHUP | POLLHUP))
                finish_client(c);
            else if (fds[i].revents & (POLLERR | POLLNVAL)) {
                err("error trying to process client with fd %d", fds[i].fd);
                remove_client(c);
                free_client(c);
            }
        }

        free(fds);
        set_autosuspend();
    }

    dbg("Terminating due to signal %s", strsignal(signal_received));
}

static void
usage(void)
{
    printf("Usage: unsuspendd [-bdsh] [-p [<path>]] [-f <path>]\n");
    printf("\n");
    printf("  -b   background (daemonize)\n");
    printf("  -d   enable debugging\n");
    printf("  -s   use syslog instead of stderr\n");
    printf("  -h   show help\n");
    printf("  -p   write pid file, defaults to " DEFAULT_PIDFILE "\n");
    printf("  -f   use specified socket instead of " DEFAULT_SOCKET_PATH "\n");
}

int
main(int argc, char **argv)
{
    bool daemonize = false;
    const char *pid_file = NULL;
    const char *socket_path = DEFAULT_SOCKET_PATH;
    int server_fd;
    int opt;

    while ((opt = getopt(argc, argv, "bdsp::f:h")) != -1) {
        switch (opt) {
        case 'b':
            daemonize = true;
            break;
        case 'd':
            debug = true;
            break;
        case 's':
            use_syslog = true;
            break;
        case 'p':
            if (optarg)
                pid_file = optarg;
            else
                pid_file = DEFAULT_PIDFILE;
            break;
        case 'f':
            socket_path = optarg;
            break;
        case 'h':
            usage();
            exit(0);
        default:
            usage();
            exit(1);
        }
    }

    if (optind != argc) {
        usage();
        exit(1);
    }

    /* It does not make sense to log messages to stderr from daemon */
    use_syslog = use_syslog || daemonize;

    if (use_syslog)
        openlog("unsuspendd", LOG_CONS | LOG_PID, LOG_DAEMON);

    /* Reap children */
    struct sigaction sigchld_info = {
        .sa_flags = SA_NOCLDWAIT,
        .sa_sigaction = SIG_DFL,
    };
    if (sigaction(SIGCHLD, &sigchld_info, NULL) == -1)
        crit("unsuspendd: sigaction: %s", strerror(errno));

    server_fd = setup_server_socket(socket_path);

    if (daemonize)
        daemon(0, 0);

    if (pid_file)
        create_pidfile(pid_file);

    set_autosuspend();

    run(server_fd);

    close(server_fd);
    if (pid_file)
        unlink(pid_file);
}
