#!/bin/bash

# Capture SCYTHE variables
#SCYTHE_THREAT=${cat FIN6_Phase1_scythe_threat.json | jq '.threat}'}
SCYTHE_THREAT_DESCRIPTION=$(cat FIN6_Phase1_scythe_threat.json | jq --raw-output '.threat | .description')
SCYTHE_THREAT_NAME=$(cat FIN6_Phase1_scythe_threat.json | jq --raw-output '.threat | .name')
SCYTHE_TTP_PAYLOAD=$(cat FIN6_Phase1_scythe_threat.json | jq --raw-output '.threat.script[] | select(.module == "downloader") | .request')
SCYTHE_TTP=$(cat FIN6_Phase1_scythe_threat.json | jq --raw-output '.threat.script[] | select(.module == "run") | .request')


# Example code for converting multi line string to array. 
# https://stackoverflow.com/questions/24628076/convert-multiline-string-to-array


# Set delimeter for IFS to newline and define SCYTHE var as an array
IFS=$'\n'
SPLIT_TTPS=($SCYTHE_TTP)


for (( i=0; i<${#SPLIT_TTPS[@]}; i++))
do
OPERATOR_TTP=$(uuidgen)
SCYTHE_TTP_COUNTER=$((SCYTHE_TTP_COUNTER+1))
SCYTHE_TTP_NAME=${SCYTHE_THREAT_NAME}-${SCYTHE_TTP_COUNTER}
#SCYTHE_TTP_NAME=$((SCYTHE_THREAT_NAME))

echo "id: ${OPERATOR_TTP}
metadata:
  chains:
    - ${SCYTHE_THREAT_NAME}
  authors:
    - scythe-io
  tags: 
    - ${SCYTHE_THREAT_NAME} 
    - scythe-io
name: ${SCYTHE_TTP_NAME}
description: |
  ${SCYTHE_THREAT_DESCRIPTION}
tactic: discovery
platforms:
  windows:
    cmd:
      command: ${SPLIT_TTPS[$i]}"> "${OPERATOR_TTP}.yml"
done
 
# Make sure to give the chain plan an ID as well so that it can be imported into Operator
CHAIN_PLAN_ID=$(uuidgen)

PLAN_TTP_COLLECTION=$(ls | egrep '[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{8,12}' | cut -d "." -f1)

PLAN_TTP_CONCAT="-"
PLAN_TTP_FINISH="- "${PLAN_TTP_COLLECTION}


echo "id: ${CHAIN_PLAN_ID}
name: ${SCYTHE_THREAT_NAME}-Chain
ttps: 
  ${PLAN_TTP_FINISH}
ordered: true
summary: false
platforms: []
executors: cmd
payloads: []
metadata: {}
variables: []
reports: []">> CHAIN_PLAN.yml

mv CHAIN_PLAN.yml CHAIN_PLAN-${CHAIN_PLAN_ID}.yml



echo "Conversion done! Make sure to move the TTP's into the correct folder!"
