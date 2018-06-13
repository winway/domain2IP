#! /bin/bash
#

CONFDIR=./conf/
RESULTDIR=./result/

if [[ $# -ne 1 ]]
then
    echo "Usage: sh $0 <url>"
    exit
fi
url=$1

nameservers=($(cat ${CONFDIR}/nameservers.txt | grep '[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*' | sort -u))

N=300

ts=$(date '+%s')

for dns_server in ${nameservers[*]}
do
    { dig -t AAAA +noquestion +noadditional +noauthority @$dns_server $url | awk '/IN[ \t]+AAAA/{print $NF}' > /tmp/.${url}.${ts}.${dns_server}.txt; echo "dig @$dns_server $url done"; } &

    joblist=($(jobs -p))
    while (( ${#joblist[*]} > $N ))
    do
        echo "######## rest for a while ########"
        sleep 0.1
        joblist=($(jobs -p))
    done
done

wait

cat /tmp/.${url}.${ts}.*.txt | sort -u >${RESULTDIR}/${url}.ip.txt
find /tmp/ -name ".${url}.${ts}.*.txt" | xargs rm -f
