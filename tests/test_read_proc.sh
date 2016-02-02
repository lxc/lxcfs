#/bin/bash -eux
#./lxcfs -s -f -d -o allow_other -o direct_io ${DIR}

red_c() {
     echo -e $2 "\e[31;1m${1}\e[0m"
}
DIR=${LXCFSDIR:-/var/lib/lxcfs}

if ! mountpoint -q $DIR; then
    echo "lxcfs isn't mounted on ${DIR}"
    exit 1
fi


PWD=`pwd`
COUNT=3

for i in test-read
do
	BIN=$PWD/$i

	red_c "$BIN test cpuinfo"
	$BIN $DIR/proc/cpuinfo $COUNT

	red_c "$BIN test stat"
	$BIN $DIR/proc/stat $COUNT

	red_c "$BIN test meminfo"
	$BIN $DIR/proc/meminfo $COUNT
done
exit 0
