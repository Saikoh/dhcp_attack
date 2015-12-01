#!/bin/sh
IF=$1
ETHTOOL_IFs=$2

: ${IF:=br0}
: ${ETHTOOL_IFs:="eth3 eth4"}

rps_sock_flow_entries=32768
br0_rps_flow_cnt=0
br0_rps_cpus=0000   # cpu:9
#br0_rps_flow_cnt=4096
#br0_rps_cpus=0200   # cpu:9

#smp_affinity=3fff
smp_affinity=1000

eth_rps_flow_cnt=4096
#eth_rps_cpus=0800  # cpu:11
#eth_rps_cpus=0008  # cpu:3
eth_rps_cpus=1000  # cpu:12




if test $rps_sock_flow_entries != `cat /proc/sys/net/core/rps_sock_flow_entries`
then
  echo "rps_sock_flow_entries:" `cat /proc/sys/net/core/rps_sock_flow_entries`
fi

if [ $br0_rps_flow_cnt != `cat /sys/class/net/${IF}/queues/rx-0/rps_flow_cnt` ]
then
  echo "br0_rps_flow_cnt:" `cat /sys/class/net/${IF}/queues/rx-0/rps_flow_cnt`
fi

if [ $br0_rps_cpus != `cat /sys/class/net/${IF}/queues/rx-0/rps_cpus` ]
then
  echo "br0_rps_cpus:" `cat /sys/class/net/${IF}/queues/rx-0/rps_cpus`
fi


for irq in `egrep ${ETHTOOL_IFs// /|} /proc/interrupts | cut -d: -f1`; do \
  if [ $smp_affinity != `cat /proc/irq/$irq/smp_affinity` ]
  then
    echo "smp_affinity($irq) :" `cat /proc/irq/$irq/smp_affinity`
  fi
done


grep -v $eth_rps_flow_cnt /sys/class/net/eth[34]/queues/rx-*/rps_flow_cnt
grep -v $eth_rps_cpus     /sys/class/net/eth[34]/queues/rx-*/rps_cpus



