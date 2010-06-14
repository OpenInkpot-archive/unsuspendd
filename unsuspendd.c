#define _GNU_SOURCE 1
#include <err.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

static const char* autosuspend = "/sys/power/autosuspend";
static const char* pidfile = "/var/run/unsuspendd.pid";
static bool _debug;

int lock=0;

static void
debug(const char *fmt,...)
{
    va_list ap;
    va_start(ap, fmt);
    vsyslog(LOG_INFO, fmt, ap);
    va_end(ap);
}

static void
set_autosuspend(int mode)
{
    FILE* file = fopen(autosuspend, "a+");
    if(!file)
        err(1, "Can't open %s\n", autosuspend);
    fprintf(file, "%d\n", mode);
    fclose(file);
    debug("Set autosuspend to %d", mode);
}

static void
sigusr(int signo)
{
    debug("Got signal: %s, lock == %d", strsignal(signo), lock);
    if(signo == SIGUSR1)
    {
        if(++lock)
            set_autosuspend(0);
    }
    else if(signo == SIGUSR2 && lock) // do nothing if lock==0
    {
        if(--lock==0)
            set_autosuspend(1);
    }
    debug("set lock counter = %d", lock);
}

static void
sighup(int signo)
{
    debug("Got signal: %s, lock == %d", strsignal(signo), lock);
}

static void
cleanup(int signo)
{
    debug("Got signal: %s, exitting", strsignal(signo));
    unlink(pidfile);
    exit(1);
}

int
main(int argc, char **argv)
{
    _debug = (bool) getenv("UNSUSPEND_DEBUG");
    if(access(autosuspend, R_OK))
        err(1, "unsuspendd: Autosuspend unsupported, exitting...\n");
    if(!access(pidfile, R_OK))
        err(1, "unsuspendd: Already run\n");
    if(!_debug)
        daemon(0, 0);
     FILE *pidf = fopen(pidfile, "w");
     if(!pidf)
        err(1, "unsuspend: can't write to pid file\n");
     fprintf(pidf, "%d", getpid());
     fclose(pidf);

     int flags = LOG_NDELAY | LOG_PID;
     if(_debug)
        flags |= LOG_PERROR;
     openlog("unsuspendd", flags, LOG_DAEMON);

     signal(SIGUSR1, sigusr);
     signal(SIGUSR2, sigusr);
     signal(SIGHUP, sighup);
     signal(SIGTERM, cleanup);
     signal(SIGINT, cleanup);
     set_autosuspend(1);
     while(true)
        sleep(INT_MAX);
}
