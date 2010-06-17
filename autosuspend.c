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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>

#include "unsuspend.h"

#define UNIX_PATH_MAX 108
#define MAXFD 16 /* Arbitrary */

static int
min(int a, int b)
{
    return a < b ? a : b;
}

static int
sock_connect(const char *socket_path, int errcode)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
        err(errcode, "unable to open socket");

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    memcpy(addr.sun_path, socket_path,
           min(UNIX_PATH_MAX, strlen(socket_path) + 1));

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        err(errcode, "unable to connect");

    return fd;
}

static void
pwrite(int fd, const char *buf, int len)
{
    while (len) {
        int written = write(fd, buf, len);
        if (written == -1) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            err(1, "unable to write data to server");
        }
        len -= written;
        buf += written;
    }
}

static void
send_cmd(const char *socket_path, const char *cmd, const char *lockname)
{
    int client = sock_connect(socket_path, 1);
    pwrite(client, cmd, strlen(cmd));
    pwrite(client, " ", 1);
    pwrite(client, lockname, strlen(lockname));
    if (close(client) == -1)
        err(1, "unable to close socket");
}

static void
status(const char *socket_path, const char *cmd)
{
    int client = sock_connect(socket_path, 1);
    pwrite(client, cmd, strlen(cmd));
    if (shutdown(client, SHUT_WR) == -1)
        err(1, "unable to shutdown socket");
    for (;;) {
        char buf[256];
        int read_ = read(client, buf, 256);
        if (read_ == -1) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            err(1, "unable to read data from daemon");
        }
        if (read_ == 0)
            break;
        fwrite(buf, read_, 1, stdout);
    }
    if (close(client) == -1)
        err(1, "unable to close socket");
}

static void
run(const char *socket_path, char **argv)
{
    int client = sock_connect(socket_path, 255);

    for (int i= 3; i < MAXFD; ++i)
        if (i != client)
            close(i);

    if (execvp(argv[0], argv) == -1)
        err(255, "unable to run program");
}

static void
usage(int exit_code)
{
    printf("Usage: autosuspend [-f <path>] (lock|unlock) <name> | status | info | runlock <args>\n");
    exit(exit_code);
}

int main(int argc, char **argv)
{
    int opt;
    const char *socket_path = DEFAULT_SOCKET_PATH;

    while ((opt = getopt(argc, argv, "f:h")) != -1) {
        switch(opt) {
        case 'h':
            usage(0);
        case 'f':
            socket_path = optarg;
            break;
        default:
            usage(1);
        }
    }

    if (optind == argc)
        usage(1);

    const char *command = argv[optind];

    if (!strcmp(command, "lock") || !strcmp(command, "unlock")) {
        if (optind + 2 != argc)
            usage(1);
        const char *lockname = argv[optind + 1];
        send_cmd(socket_path, command, lockname);
    } else if (!strcmp(command, "status") || !strcmp(command, "info")) {
        if (optind + 1 != argc)
            usage(1);
        status(socket_path, command);
    } else if (!strcmp(command, "runlock")) {
        if (optind > argc + 2)
            usage(1);
        run(socket_path, argv + optind + 1);
    } else {
        usage(1);
    }

    exit(0);
}
