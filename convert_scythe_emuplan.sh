#!/bin/bash

# Capture SCYTHE variables
#SCYTHE_THREAT=${cat FIN6_Phase1_scythe_threat.json | jq '.threat}'}
SCYTHE_THREAT_DESCRIPTION=$(cat FIN6_Phase1_scythe_threat.json | jq '.threat | .description')
SCYTHE_THREAT_NAME=$(cat FIN6_Phase1_scythe_threat.json | jq '.threat | .name')
SCYTHE_TTP_PAYLOAD=$(cat FIN6_Phase1_scythe_threat.json | jq '.threat.script[] | select(.module == "downloader") | .request')
SCYTHE_TTP=$(cat FIN6_Phase1_scythe_threat.json | jq '.threat.script[] | select(.module == "run") | .request')

# Create some vars for Operator TTPS
OPERATOR_TTP=$(uuidgen)



# Example code for converting multi line string to array. 
# https://stackoverflow.com/questions/24628076/convert-multiline-string-to-array

#IFS=$'\n'
#for (( i=0; i<${#SPLIT_TTPS[@]}; i++ ));

# Another example

#while IFS= read -r line ; do 
#(echo $line >> ${OPERATOR_TTP}.yml; done <<< "${SCYTHE_THREAT_DESCRIPTION}, ${SCYTHE_TTP}"

#for LINE in "${SCYTHE_TTP}"
#do
#    echo "$LINE"
#done


# To test to make sure variable is correct
#echo "${SCYTHE_TTP}"

# Pulls all the correct key/values from JSON file and converts over to YAML.

for LINE in "${SCYTHE_TTP}"
do
    echo "
${OPERATOR_TTP}
metadata:
  version: 1
  authors:
    - scythe-io
name: ${SCYTHE_THREAT_NAME}
description: |
  ${SCYTHE_THREAT_DESCRIPTION}
platforms:
  windows:
    cmd:
      command: "${SCYTHE_TTP}"
" > ${OPERATOR_TTP}.yml
done