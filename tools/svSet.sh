#!/bin/sh

echo 4194304 > /proc/sys/net/core/rmem_max
echo 4194304 > /proc/sys/net/core/rmem_default

echo 4194304 > /proc/sys/net/core/wmem_max
echo 4194304 > /proc/sys/net/core/wmem_default

ethtool -N eth3 rx-flow-hash udp4 sdfn
ethtool -N eth4 rx-flow-hash udp4 sdfn

# Set protocol offload (checksum‚Ì§ŒäH)
ethtool -K eth3 rx off tx off
ethtool -K eth4 rx off tx off

# Set pause options (Xon/Xoff‚Ì§ŒäH)
ethtool -A eth3 rx off tx off
ethtool -A eth4 rx off tx off

ifconfig br0 down
ifconfig br0 up


ethtool -n eth3 rx-flow-hash udp4
ethtool -n eth4 rx-flow-hash udp4

ethtool -k eth3
ethtool -k eth4
ethtool -k br0

ethtool -a eth3
ethtool -a eth4



for irq in `egrep 'eth3|eth4' /proc/interrupts | cut -d: -f1`; do \
  echo "1000" > /proc/irq/$irq/smp_affinity
done

echo 32768 > /proc/sys/net/core/rps_sock_flow_entries
for irq in `ls /sys/class/net/eth[34]/queues/rx-*/rps_flow_cnt`;
do
  echo 4096 > $irq
done

for irq in `ls /sys/class/net/eth[34]/queues/rx-*/rps_cpus`;
do
  echo "1000" > $irq
done


ethtool -G eth3 rx 4096
ethtool -G eth4 rx 4096
ethtool -G eth3 tx 4096
ethtool -G eth4 tx 4096

ethtool -g eth3
ethtool -g eth4


cat /proc/sys/net/core/rps_sock_flow_entries

cat /sys/class/net/eth[34]/queues/rx-*/rps_flow_cnt
cat /sys/class/net/eth[34]/queues/rx-*/rps_cpus

for irq in `egrep 'eth3|eth4' /proc/interrupts | cut -d: -f1`; do \
  cat /proc/irq/$irq/smp_affinity
done


# 
for irq in `ls /sys/class/net/eth[34]/queues/tx-*/xps_cpus`;
do
  echo "0010" > $irq
done
