#! /bin/bash
#

CONFDIR=./conf/
RESULTDIR=./result/
TMPDIR=./tmp/

if [[ $# -ne 1 ]]
then
    echo "Usage: sh $0 <url>"
    exit 1
fi
url=$1

# get work node
work_nodes=($(cat ${CONFDIR}/work_nodes.txt | grep '[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*' | sort -u))
work_nodes_num=${#work_nodes[@]}

# split nameservers
nameservers=($(cat ${CONFDIR}/nameservers.txt | grep '[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*' | sort -u))
nameservers_num=${#nameservers[@]}
chunk=$(($nameservers_num/$work_nodes_num+1))

work_node_index=0
counter=1
: > ${TMPDIR}/${work_nodes[$work_node_index]}_nameservers.txt
for nameserver in ${nameservers[@]}
do
    if (($counter > $chunk))
    then
        ((work_node_index++))
        counter=1
        : > ${TMPDIR}/${work_nodes[$work_node_index]}_nameservers.txt
    fi
    echo "$nameserver" >> ${TMPDIR}/${work_nodes[$work_node_index]}_nameservers.txt
    ((counter++))
done

# distribute and run
for node in ${work_nodes[@]}
do
    echo "$node, count: $(wc -l ${TMPDIR}/${node}_nameservers.txt)"
    { scp job.sh ${TMPDIR}/${node}_nameservers.txt $node:/tmp/ && ssh $node "sh /tmp/job.sh $node $url" && scp $node:/tmp/${node}_ip.txt $TMPDIR && echo "[$(date)] $node done"; } &
done

wait

for node in ${work_nodes[@]}
do
    cat $TMPDIR/${node}_ip.txt >> $TMPDIR/${url}.ip.txt
done

sort -u $TMPDIR/${url}_ip.txt >${RESULTDIR}/${url}.ip.txt
