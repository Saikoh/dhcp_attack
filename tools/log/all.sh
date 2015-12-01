#!/bin/sh

if [ $# -ne 1 ]
then
  echo "Usage : $0 <DirName>"
  exit 1
fi

cd $1

ls -1trd */*stat | xargs grep cpu | sed -e 's/  */\t/g' -e 's/:/\t/' > ./stat.txt

AWK=awk

if [ "`echo -n`" == "-n" ]; then
	ECHO_C='\c'
	ECHO_N=
else
	ECHO_C=
	ECHO_N='-n'
fi

# MemPrint()
#  $1 : プロセスID
#  $2 : タイトル
#  $3 : Node ID
MemPrint()
{
	SMAPS_FN="$3_smaps_$1"
	STATUS_FN="$3_status_$1"
	
	echo $ECHO_N "$2	$3	$ECHO_C" >> $4
	
	cat $STATUS_FN | $AWK '
	BEGIN{
		NAME=""
		PID=0
		VmPeak=0
		VmSize=0
		VmRSS=0
		VmHWM=0
		VmData=0
		VmStk=0
		VmSwap=0
		Threads=0
	}
	/^Name:/{ NAME=$2 }
	/^Pid:/{ PID=$2 }
	/^VmPeak:/{ VmPeak=$2 }
	/^VmSize:/{ VmSize=$2 }
	/^VmRSS:/{ VmRSS=$2 }
	/^VmHWM:/{ VmHWM=$2 }
	/^VmData:/{ VmData=$2 }
	/^VmStk:/{ VmStk=$2 }
	/^VmSwap:/{ VmSwap=$2 }
	/^Threads:/{ Threads=$2 }
	END{
		printf("%s	%d	%d	%d	%d	%d	%d	%d	%d	%d	",
		       NAME, PID, VmPeak, VmSize, VmRSS, VmHWM, VmData, VmStk, VmSwap, Threads)
	}' >> $4
	
	cat $SMAPS_FN | $AWK '
	BEGIN{
		Size = 0
		Rss = 0
		Shared_Clean = 0
		Shared_Dirty = 0
		Private_Clean = 0
		Private_Dirty = 0
		Swap = 0
		Pss  = 0
		LibSize = 0
		LibRss = 0
		LibShared_Clean = 0
		LibShared_Dirty = 0
		LibPrivate_Clean = 0
		LibPrivate_Dirty = 0
		LibSwap = 0
		LibPss  = 0
		ShmSize = 0
		ShmRss = 0
		ShmShared_Clean = 0
		ShmShared_Dirty = 0
		ShmPrivate_Clean = 0
		ShmPrivate_Dirty = 0
		ShmSwap = 0
		ShmPss  = 0
		HeapSize = 0
		HeapRss = 0
		HeapShared_Clean = 0
		HeapShared_Dirty = 0
		HeapPrivate_Clean = 0
		HeapPrivate_Dirty = 0
		HeapSwap = 0
		HeapPss  = 0
		StackSize = 0
		StackRss = 0
		StackShared_Clean = 0
		StackShared_Dirty = 0
		StackPrivate_Clean = 0
		StackPrivate_Dirty = 0
		StackSwap = 0
		StackPss  = 0
		LibSizeFlag = 0
		LibRssFlag = 0
		LibShared_CleanFlag = 0
		LibShared_DirtyFlag = 0
		LibPrivate_CleanFlag = 0
		LibPrivate_DirtyFlag = 0
		LibSwapFlag = 0
		LibPssFlag  = 0
		ShmSizeFlag = 0
		ShmRssFlag = 0
		ShmShared_CleanFlag = 0
		ShmShared_DirtyFlag = 0
		ShmPrivate_CleanFlag = 0
		ShmPrivate_DirtyFlag = 0
		ShmSwapFlag = 0
		ShmPssFlag  = 0
		HeapSizeFlag = 0
		HeapRssFlag = 0
		HeapShared_CleanFlag = 0
		HeapShared_DirtyFlag = 0
		HeapPrivate_CleanFlag = 0
		HeapPrivate_DirtyFlag = 0
		HeapSwapFlag = 0
		HeapPssFlag  = 0
		StackSizeFlag = 0
		StackRssFlag = 0
		StackShared_CleanFlag = 0
		StackShared_DirtyFlag = 0
		StackPrivate_CleanFlag = 0
		StackPrivate_DirtyFlag = 0
		StackSwapFlag = 0
		StackPssFlag  = 0
		Error = 0
	}
	/^Size:/{
		if ( LibSizeFlag == 1 )
		{
			LibSize += $2
			LibSizeFlag = 0
		}
		else if ( ShmSizeFlag == 1 )
		{
			ShmSize += $2
			ShmSizeFlag = 0
		}
		else if ( HeapSizeFlag == 1 )
		{
			HeapSize += $2
			HeapSizeFlag = 0
		}
		else if ( StackSizeFlag == 1 )
		{
			StackSize += $2
			StackSizeFlag = 0
		}
		else { Size+=$2 }
	}
	/^Rss:/{
		if ( LibRssFlag == 1 )
		{
			LibRss += $2
			LibRssFlag = 0
		}
		else if ( ShmRssFlag == 1 )
		{
			ShmRss += $2
			ShmRssFlag = 0
		}
		else if ( HeapRssFlag == 1 )
		{
			HeapRss += $2
			HeapRssFlag = 0
		}
		else if ( StackRssFlag == 1 )
		{
			StackRss += $2
			StackRssFlag = 0
		}
		else { Rss+=$2 }
	}
	/^Shared_Clean:/{
		if ( LibShared_CleanFlag == 1 )
		{
			LibShared_Clean += $2
			LibShared_CleanFlag = 0
		}
		else if ( ShmShared_CleanFlag == 1 )
		{
			ShmShared_Clean += $2
			ShmShared_CleanFlag = 0
		}
		else if ( HeapShared_CleanFlag == 1 )
		{
			HeapShared_Clean += $2
			HeapShared_CleanFlag = 0
		}
		else if ( StackShared_CleanFlag == 1 )
		{
			StackShared_Clean += $2
			StackShared_CleanFlag = 0
		}
		else { Shared_Clean+=$2 }
	}
	/^Shared_Dirty:/{
		if ( LibShared_DirtyFlag == 1 )
		{
			LibShared_Dirty += $2
			LibShared_DirtyFlag = 0
		}
		else if ( ShmShared_DirtyFlag == 1 )
		{
			ShmShared_Dirty += $2
			ShmShared_DirtyFlag = 0
		}
		else if ( HeapShared_DirtyFlag == 1 )
		{
			HeapShared_Dirty += $2
			HeapShared_DirtyFlag = 0
		}
		else if ( StackShared_DirtyFlag == 1 )
		{
			StackShared_Dirty += $2
			StackShared_DirtyFlag = 0
		}
		else { Shared_Dirty+=$2 }
	}
	/^Private_Clean:/{
		if ( LibPrivate_CleanFlag == 1 )
		{
			LibPrivate_Clean += $2
			LibPrivate_CleanFlag = 0
		}
		else if ( ShmPrivate_CleanFlag == 1 )
		{
			ShmPrivate_Clean += $2
			ShmPrivate_CleanFlag = 0
		}
		else if ( HeapPrivate_CleanFlag == 1 )
		{
			HeapPrivate_Clean += $2
			HeapPrivate_CleanFlag = 0
		}
		else if ( StackPrivate_CleanFlag == 1 )
		{
			StackPrivate_Clean += $2
			StackPrivate_CleanFlag = 0
		}
		else { Private_Clean+=$2 }
	}
	/^Private_Dirty:/{
		if ( LibPrivate_DirtyFlag == 1 )
		{
			LibPrivate_Dirty += $2
			LibPrivate_DirtyFlag = 0
		}
		else if ( ShmPrivate_DirtyFlag == 1 )
		{
			ShmPrivate_Dirty += $2
			ShmPrivate_DirtyFlag = 0
		}
		else if ( HeapPrivate_DirtyFlag == 1 )
		{
			HeapPrivate_Dirty += $2
			HeapPrivate_DirtyFlag = 0
		}
		else if ( StackPrivate_DirtyFlag == 1 )
		{
			StackPrivate_Dirty += $2
			StackPrivate_DirtyFlag = 0
		}
		else { Private_Dirty+=$2 }
	}
	/^Swap:/{
		if ( LibSwapFlag == 1 )
		{
			LibSwap += $2
			LibSwapFlag = 0
		}
		else if ( ShmSwapFlag == 1 )
		{
			ShmSwap += $2
			ShmSwapFlag = 0
		}
		else if ( HeapSwapFlag == 1 )
		{
			HeapSwap += $2
			HeapSwapFlag = 0
		}
		else if ( StackSwapFlag == 1 )
		{
			StackSwap += $2
			StackSwapFlag = 0
		}
		else { Swap+=$2 }
	}
	/^Pss:/{
		if ( LibPssFlag  == 1 )
		{
			LibPss  += $2
			LibPssFlag  = 0
		}
		else if ( ShmPssFlag  == 1 )
		{
			ShmPss  += $2
			ShmPssFlag  = 0
		}
		else if ( HeapPssFlag  == 1 )
		{
			HeapPss  += $2
			HeapPssFlag  = 0
		}
		else if ( StackPssFlag  == 1 )
		{
			StackPss  += $2
			StackPssFlag  = 0
		}
		else { Pss+=$2 }
	}
	$6~/\/dev\/shm\// {  
		if ( ShmSizeFlag == 1 ) { Error++ }
		if ( ShmRssFlag == 1 ) { Error++ }
		if ( ShmShared_CleanFlag == 1 ) { Error++ }
		if ( ShmShared_DirtyFlag == 1 ) { Error++ }
		if ( ShmPrivate_CleanFlag == 1 ) { Error++ }
		if ( ShmPrivate_DirtyFlag == 1 ) { Error++ }
		if ( ShmSwapFlag == 1 ) { Error++ }
		if ( ShmPssFlag  == 1 ) { Error++ }
		ShmSizeFlag = 1
		ShmRssFlag = 1
		ShmShared_CleanFlag = 1
		ShmShared_DirtyFlag = 1
		ShmPrivate_CleanFlag = 1
		ShmPrivate_DirtyFlag = 1
		ShmSwapFlag = 1
		ShmPssFlag  = 1
	}
	$6~/\// && $6!~/\/dev\/shm\// {  
		if ( LibSizeFlag == 1 ) { Error++ }
		if ( LibRssFlag == 1 ) { Error++ }
		if ( LibShared_CleanFlag == 1 ) { Error++ }
		if ( LibShared_DirtyFlag == 1 ) { Error++ }
		if ( LibPrivate_CleanFlag == 1 ) { Error++ }
		if ( LibPrivate_DirtyFlag == 1 ) { Error++ }
		if ( LibSwapFlag == 1 ) { Error++ }
		if ( LibPssFlag  == 1 ) { Error++ }
		LibSizeFlag = 1
		LibRssFlag = 1
		LibShared_CleanFlag = 1
		LibShared_DirtyFlag = 1
		LibPrivate_CleanFlag = 1
		LibPrivate_DirtyFlag = 1
		LibSwapFlag = 1
		LibPssFlag  = 1
	}
	$6~/\[heap\]/ {
		if ( HeapSizeFlag == 1 ) { Error++ }
		if ( HeapRssFlag == 1 ) { Error++ }
		if ( HeapShared_CleanFlag == 1 ) { Error++ }
		if ( HeapShared_DirtyFlag == 1 ) { Error++ }
		if ( HeapPrivate_CleanFlag == 1 ) { Error++ }
		if ( HeapPrivate_DirtyFlag == 1 ) { Error++ }
		if ( HeapSwapFlag == 1 ) { Error++ }
		if ( HeapPssFlag  == 1 ) { Error++ }
		HeapSizeFlag = 1
		HeapRssFlag = 1
		HeapShared_CleanFlag = 1
		HeapShared_DirtyFlag = 1
		HeapPrivate_CleanFlag = 1
		HeapPrivate_DirtyFlag = 1
		HeapSwapFlag = 1
		HeapPssFlag  = 1
	}
	$6~/\[stack\]/ {
		if ( StackSizeFlag == 1 ) { Error++ }
		if ( StackRssFlag == 1 ) { Error++ }
		if ( StackShared_CleanFlag == 1 ) { Error++ }
		if ( StackShared_DirtyFlag == 1 ) { Error++ }
		if ( StackPrivate_CleanFlag == 1 ) { Error++ }
		if ( StackPrivate_DirtyFlag == 1 ) { Error++ }
		if ( StackSwapFlag == 1 ) { Error++ }
		if ( StackPssFlag  == 1 ) { Error++ }
		StackSizeFlag = 1
		StackRssFlag = 1
		StackShared_CleanFlag = 1
		StackShared_DirtyFlag = 1
		StackPrivate_CleanFlag = 1
		StackPrivate_DirtyFlag = 1
		StackSwapFlag = 1
		StackPssFlag  = 1
	}
	END{
		printf("%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d	%d\n",
		    Size, Rss, Shared_Clean, Shared_Dirty,
		    Private_Clean, Private_Dirty, Swap, Pss,
		    LibSize, LibRss, LibShared_Clean, LibShared_Dirty,
		    LibPrivate_Clean, LibPrivate_Dirty, LibSwap, LibPss,
		    ShmSize, ShmRss, ShmShared_Clean, ShmShared_Dirty,
		    ShmPrivate_Clean, ShmPrivate_Dirty, ShmSwap, ShmPss,
		    HeapSize, HeapRss, HeapShared_Clean, HeapShared_Dirty,
		    HeapPrivate_Clean, HeapPrivate_Dirty, HeapSwap, HeapPss,
		    StackSize, StackRss, StackShared_Clean, StackShared_Dirty,
		    StackPrivate_Clean, StackPrivate_Dirty, StackSwap, StackPss,
		    Error )
	}' >> $4
}

FuncCollect()
{
#	for NodeId in 11 60
	for NodeId in `find . -maxdepth 1 -type d  -a ! -name "."`
	do
		for PID in `\ls ${NodeId}_smaps_* | sed 's/.*smaps_//g'`
		do
			if [ -f "${NodeId}_smaps_$PID" ] && [ -f "${NodeId}_status_$PID" ]
			then
				MemPrint $PID $1 $NodeId $2
			fi
		done
	done
}


echo "Test	NodeID	Process	PID	VmPeak	VmSize	VmRSS	VmHWM	VmData	VmStk	VmSwap	Threads	Size	Rss	Shared_Clean	Shared_Dirty	Private_Clean	Private_Dirty	Swap	Pss	LibSize	LibRss	LibShared_Clean	LibShared_Dirty	LibPrivate_Clean	LibPrivate_Dirty	LibSwap	LibPss	ShmSize	ShmRss	ShmShared_Clean	ShmShared_Dirty	ShmPrivate_Clean	ShmPrivate_Dirty	ShmSwap	ShmPss	HeapSize	HeapRss	HeapShared_Clean	HeapShared_Dirty	HeapPrivate_Clean	HeapPrivate_Dirty	HeapSwap	HeapPss	StackSize	StackRss	StackShared_Clean	StackShared_Dirty	StackPrivate_Clean	StackPrivate_Dirty	StackSwap	StackPss	Error" > $1.csv

BASE_DIR=`basename $PWD`

for DN in `\ls -tr`
do
	if [ -d $DN ]
	then
		(cd $DN ; FuncCollect ${BASE_DIR}_${DN} ../$1.csv )
	fi
done


