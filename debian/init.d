#! /bin/sh

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
DESC="unsuspend daemon"
NAME="unsuspendd"
PID="/var/run/unsuspendd.pid"

[ -f /etc/default/unsuspendd ] && . /etc/default/unsuspendd

case "$1" in
	start)
		echo -n "Starting ${DESC}: "
		start-stop-daemon --start --quiet \
            --pidfile ${PID} \
            --exec /usr/sbin/unsuspendd 
		echo "unsuspendd."
		;;
	stop)
		echo -n "Stopping $DESC: "
		start-stop-daemon --stop --quiet --pidfile ${PID} --oknodo
		echo "$NAME."
		;;
	restart)
		$0 stop
		sleep 1
		$0 start
		;;
	*)
		N=/etc/init.d/$NAME
		echo "Usage: $N {start|stop}" >&2
		exit 1
	;;
esac

exit 0
