#!/bin/bash

# Capture SCYTHE variables
#SCYTHE_THREAT=${cat FIN6_Phase1_scythe_threat.json | jq '.threat}'}
SCYTHE_THREAT_DESCRIPTION=$(cat FIN6_Phase1_scythe_threat.json | jq '.threat | .description')
SCYTHE_THREAT_NAME=$(cat FIN6_Phase1_scythe_threat.json | jq '.threat | .name')
SCYTHE_TTP_PAYLOAD=$(cat FIN6_Phase1_scythe_threat.json | jq '.threat.script[] | select(.module == "downloader") | .request')
SCYTHE_TTP=$(cat FIN6_Phase1_scythe_threat.json | jq '.threat.script[] | select(.module == "run") | .request')

# Create some vars for Operator TTPS
OPERATOR_TTP=$(uuidgen)




#while IFS= read -r line ; do 
#(echo $line >> ${OPERATOR_TTP}.yml; done <<< "${SCYTHE_THREAT_DESCRIPTION}, ${SCYTHE_TTP}"

#for LINE in "${SCYTHE_TTP}"
#do
#    echo "$LINE"
#done


#SPLIT_TTPS=($SCYTHE_TTP)

IFS=$'\n'






#for (( i=0; i<${#SPLIT_TTPS[@]}; i++ ));
#for (( i=0; i<${#SPLIT_TTPS[@]}; i++ ))
#do
echo "${SCYTHE_TTP}"
#done
    #echo "
#${OPERATOR_TTP}
#metadata:
#  version: 1
#  authors:
#    - scythe-io
#name: ${SCYTHE_THREAT_NAME}
#description: |
#  ${SCYTHE_THREAT_DESCRIPTION}
#platforms:
#  windows:
#    cmd:
#      command: "${SPLIT_TTPS}"
#" > ${OPERATOR_TTP}.yml
#done