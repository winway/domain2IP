#! /bin/bash
#

SCRIPT=$(readlink -f "$BASH_SOURCE")

cd $(dirname $SCRIPT) || { echo "cd $(dirname $SCRIPT) failed"; exit 1; }

node=$1
url=$2

nameservers=($(cat ${node}_nameservers.txt | grep '[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*' | sort -u))

N=300

ts=$(date '+%s')

for nameserver in ${nameservers[*]}
do
    { dig -t AAAA +noquestion +noadditional +noauthority @$nameserver $url | awk '/IN[ \t]+AAAA/{print $NF}' > /tmp/.${url}.${ts}.${nameserver}.txt; } &

    joblist=($(jobs -p))
    while (( ${#joblist[*]} > $N ))
    do
        echo "######## rest for a while ########"
        sleep 0.1
        joblist=($(jobs -p))
    done
done

wait

cat /tmp/.${url}.${ts}.*.txt | sort -u >${node}_ip.txt
find /tmp/ -name ".${url}.*.txt" | xargs rm -f
