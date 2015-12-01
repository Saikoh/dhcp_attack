#!/bin/sh

BASEDIR=./log
APLNAME1=dhcp_attack
APLNAME2=dhcpd
APLNAME3=gapl

# GetMemLog()
# $1 : プロセスID
# $2 : Node名
# $3 : Log出力の Dir名
GetMemLog()
{
  cat /proc/$1/status > $BASEDIR/$3/$2_status_$1
  cat /proc/$1/smaps  > $BASEDIR/$3/$2_smaps_$1
}

# GetCpuLog()
# $1 : プロセスID
# $2 : Node名
# $3 : Log出力の Dir名
GetCpuLog()
{
  cat /proc/$1/sched > $BASEDIR/$3/$2_sched_$1
  cat /proc/$1/stat  > $BASEDIR/$3/$2_stat_$1
}

# GetSysLog()
# $1 : Node名
# $2 : Log出力の Dir名
GetSysLog()
{
  cat /proc/meminfo > $BASEDIR/$2/$1_meminfo
  cat /proc/stat  > $BASEDIR/$2/$1_stat
  cat /proc/softirqs > $BASEDIR/$2/$1_softirqs
  netstat -s > $BASEDIR/$2/$1_netstat-s
  netstat -i > $BASEDIR/$2/$1_netstat-i
}


NODEID=`ifconfig eth0 | awk '/inet addr:/{ split($2,a,"."); printf("%s\n",a[4]) }'`

if [ X$1 != X ] ;
then
  LOGDIR_BASE=$1
else
  LOGDIR_BASE=`date '+%y%m%d/%H%M'`
fi

  LOGDIR=${LOGDIR_BASE}
  
  echo $LOGDIR
  
  mkdir -p $BASEDIR/$LOGDIR/${NODEID}
  
  for PID in `ps -o pid -C $APLNAME1 -C $APLNAME2 -C $APLNAME3 --no-headers`
  do
    GetMemLog $PID $NODEID $LOGDIR
    GetCpuLog $PID $NODEID $LOGDIR
  done
  GetSysLog $NODEID $LOGDIR

chmod 777 $BASEDIR
chmod -R 777 $BASEDIR/$LOGDIR
