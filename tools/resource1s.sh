#!/bin/sh

BASEDIR=./log
APLNAME1=dhcp_attack
APLNAME2=dhcpd
APLNAME3=gapl

########
#IF=br0
IF=bond0
ETHTOOL_IFs="eth3 eth4"
: ${ETHTOOL_IFs:=$IF}


NETSTAT_i=`netstat -i | grep ${IF}`
NETSTAT_s=`netstat -s | egrep 'packet receive errors|packets to unknown port received|SndbufErrors'`
FIFO=`cat /proc/net/dev | grep ${IF}: `
echo "rmem_max    : "`cat /proc/sys/net/core/rmem_max`
echo "rmem_default: "`cat /proc/sys/net/core/rmem_default`
echo "wmem_max    : "`cat /proc/sys/net/core/wmem_max`
echo "wmem_default: "`cat /proc/sys/net/core/wmem_default`

for ETHTOOL_IF in $ETHTOOL_IFs
do
  eval ${ETHTOOL_IF}='`ethtool -S ${ETHTOOL_IF} | grep flow_control`'
  FLOW_CTL=`echo ${FLOW_CTL}$'\n'${ETHTOOL_IF} ${!ETHTOOL_IF}`
  
  eval ${ETHTOOL_IF}='`ethtool -S ${ETHTOOL_IF} | grep rx_no_dma_resources`'
  NO_DMA=`echo ${NO_DMA}$'\n'${ETHTOOL_IF} ${!ETHTOOL_IF}`
  
  ethtool -S ${ETHTOOL_IF} > before_${ETHTOOL_IF}.txt
done

SOFTIRQ_TX=`cat /proc/softirqs | egrep NET_TX`
SOFTIRQ_RX=`cat /proc/softirqs | egrep NET_RX`

egrep ${ETHTOOL_IFs// /|} /proc/interrupts  | sed -e 's/  */\t/g' > before_interrupts.txt

########

TRAPCMD()
{
    egrep ${ETHTOOL_IFs// /|} /proc/interrupts  | sed -e 's/  */\t/g' > after_interrupts.txt
    
    for ETHTOOL_IF in $ETHTOOL_IFs
    do
      echo
      echo "==== " ${ETHTOOL_IF} " ===="
      echo "$ ethtool -n ${ETHTOOL_IF} rx-flow-hash udp4"
      ethtool -n ${ETHTOOL_IF} rx-flow-hash udp4
      
      echo "$ ethtool -k ${ETHTOOL_IF}"
      ethtool -k ${ETHTOOL_IF}
      
      echo "$ ethtool -a ${ETHTOOL_IF}"
      ethtool -a ${ETHTOOL_IF}
    done
    
    if [ "$ETHTOOL_IFs" != "$IF" ]
    then
      echo
      echo "==== " ${IF} " ===="
      echo "$ ethtool -k ${IF}"
      ethtool -k ${IF}
    fi
    
    echo "rmem_max    : "`cat /proc/sys/net/core/rmem_max`
    echo "rmem_default: "`cat /proc/sys/net/core/rmem_default`
    
    echo
    echo "netstat -i"
    echo "${NETSTAT_i}"
    echo "`netstat -i | grep ${IF}`"
    
    echo
    echo "netstat -s"
    echo $NETSTAT_s
    echo `netstat -s | egrep 'packet receive errors|packets to unknown port received|SndbufErrors'`
    
    echo
    echo "/proc/net/dev"
    echo $FIFO
    echo `cat /proc/net/dev | grep ${IF}:`
    
    echo
    echo "flow Control"
    echo "${FLOW_CTL}"
    for ETHTOOL_IF in $ETHTOOL_IFs
    do
      echo ${ETHTOOL_IF} `ethtool -S ${ETHTOOL_IF} | grep flow_control`
    done
    
    echo
    echo "rx_no_dma_resources"
    echo "${NO_DMA}"
    for ETHTOOL_IF in $ETHTOOL_IFs
    do
      echo ${ETHTOOL_IF} `ethtool -S ${ETHTOOL_IF} | grep rx_no_dma_resources`
      ethtool -S ${ETHTOOL_IF} > after_${ETHTOOL_IF}.txt
    done
    
    echo
    echo "SoftIRQ"
    echo $SOFTIRQ_TX
    echo `cat /proc/softirqs | egrep NET_TX`
    echo
    echo $SOFTIRQ_RX
    echo `cat /proc/softirqs | egrep NET_RX`
    
    ./rps.sh  ${IF} "${ETHTOOL_IFs}"
    
    mv after_* before_* log/${LOGDIR_BASE%/*}/.
    
    exit
}

trap "TRAPCMD " INT








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
  cat /proc/softirqs | sed -e 's/  */\t/g' -e 's/CPU0/\tCPU0/' -e 's/^BLOCK_IOPOLL/\tBLOCK_IOPOLL/' > $BASEDIR/$2/$1_softirqs_
  netstat -s > $BASEDIR/$2/$1_netstat-s
  netstat -i > $BASEDIR/$2/$1_netstat-i
}


NODEID=`ifconfig eth1 | awk '/inet addr:/{ split($2,a,"."); printf("%s\n",a[4]) }'`

if [ X$1 != X ] ;
then
  LOGDIR_BASE=$1
else
  LOGDIR_BASE=`date '+%y%m%d/%H%M'`
fi


cnt=0
while :
do
  LOGDIR=${LOGDIR_BASE}_${cnt}
  
  echo $LOGDIR
  
  mkdir -p $BASEDIR/$LOGDIR/${NODEID}
  
  for PID in `ps -o pid -C $APLNAME1 -C $APLNAME2 -C $APLNAME3 --no-headers`
  do
    GetMemLog $PID $NODEID $LOGDIR
    GetCpuLog $PID $NODEID $LOGDIR
  done
  GetSysLog $NODEID $LOGDIR
  
  cnt=`expr $cnt + 1`
  usleep 1000000 # 1Sec
done

chmod -R 777 $BASEDIR/$LOGDIR
