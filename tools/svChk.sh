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
  
  eval ${ETHTOOL_IF}='`ethtool -S ${ETHTOOL_IF} | grep rx_missed_errors`'
  MISSED_ERR=`echo ${MISSED_ERR}$'\n'${ETHTOOL_IF} ${!ETHTOOL_IF}`
  
  ethtool -S ${ETHTOOL_IF} > before_${ETHTOOL_IF}.txt
done

SOFTIRQ_TX=`cat /proc/softirqs | egrep NET_TX`
SOFTIRQ_RX=`cat /proc/softirqs | egrep NET_RX`

egrep ${ETHTOOL_IFs// /|} /proc/interrupts > before_interrupts.txt

#echo  -e "I'm waiting... Please hit any key!" ; read
top -d 1

egrep ${ETHTOOL_IFs// /|} /proc/interrupts > after_interrupts.txt


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
echo "${MISSED_ERR}"
for ETHTOOL_IF in $ETHTOOL_IFs
do
  echo ${ETHTOOL_IF} `ethtool -S ${ETHTOOL_IF} | grep rx_no_dma_resources`
  echo ${ETHTOOL_IF} `ethtool -S ${ETHTOOL_IF} | grep rx_missed_errors`
  ethtool -S ${ETHTOOL_IF} > after_${ETHTOOL_IF}.txt
done

echo
echo "SoftIRQ"
echo $SOFTIRQ_TX
echo `cat /proc/softirqs | egrep NET_TX`
echo
echo $SOFTIRQ_RX
echo `cat /proc/softirqs | egrep NET_RX`

./rps.sh ${IF} "${ETHTOOL_IFs}"
