#! /bin/sh

### BEGIN INIT INFO
# Provides:          sshcanary
# Required-Start:    
# Required-Stop:
# X-Start-Before:    rmnologin
# Default-Start:     2 3 4 5
# Default-Stop:
# Short-Description: start sshcanary
# Description: Log ssh bruteforce activity
### END INIT INFO

. /lib/lsb/init-functions

N=/etc/init.d/sshcanary
CANARY=/usr/local/bin/sshcanaryd
PORT=2222
UNAME=sshcanary
GNAME=sshcanary
LOG=/var/log/sshcanary/sshcanary.log
KEY=/var/log/sshcanary/sshcanary.rsa.key
TRAP=1000
PID=/var/run/sshcanaryd.pid

set -e

case "$1" in
  start)
	$CANARY -p $PORT -u $UNAME -g $GNAME -l $LOG -k $KEY -t $TRAP
	;;

  force-reload|reload)
	kill -HUP $(cat $PID)
	;;

  stop)
        if [ -f $PID ]; then
		kill $(cat $PID)
		sleep 1
		kill -9 $(cat $PID) 
		rm -f $PID
	else
		pkill $CANARY
		sleep 1
		pkill -9 $CANARY
	fi
	;;

  restart)
        if [ -f $PID ]; then
		kill $(cat $PID)
		sleep 1
		kill -9 $(cat $PID) 
		rm -f $PID
	else
		pkill $CANARY
		sleep 1
		pkill -9 $CANARY
	fi
	$CANARY -p $PORT -u $UNAME -g $GNAME -l $LOG -k $KEY -t $TRAP
	;;

  status)
	;;

  *)
	echo "Usage: $N {start|stop|restart|force-reload|status}" >&2
	exit 1
	;;
esac

exit 0
