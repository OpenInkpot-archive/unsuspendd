#!/bin/sh

DESC="autosuspend arbiter"
NAME="unsuspendd"
PID=/var/run/unsuspendd.pid

case "$1" in
  start)
    echo -n "Starting $DESC: "
    /sbin/start-stop-daemon --start --quiet --pidfile $PID \
      --exec /usr/sbin/unsuspendd -- -b -s -p
    echo "$NAME."
    ;;
  stop)
    echo -n "Stopping $DESC: "
    start-stop-daemon --stop --quiet --pidfile $PID --oknodo
    echo "$NAME."
    ;;
  restart)
    $0 stop
    $0 start
    ;;
  *)
    echo "Usage: $NAME {start|stop|restart}" >&2
    exit 1
    ;;
esac

exit 0
