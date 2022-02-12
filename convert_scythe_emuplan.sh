#!/bin/bash

# Capture SCYTHE variables
#SCYTHE_THREAT=${cat FIN6_Phase1_scythe_threat.json | jq '.threat}'}
SCYTHE_THREAT_DESCRIPTION=$(cat FIN6_Phase1_scythe_threat.json | jq --raw-output '.threat | .description')
SCYTHE_THREAT_NAME=$(cat FIN6_Phase1_scythe_threat.json | jq --raw-output '.threat | .name')
SCYTHE_TTP_PAYLOAD=$(cat FIN6_Phase1_scythe_threat.json | jq --raw-output '.threat.script[] | select(.module == "downloader") | .request')
SCYTHE_TTP=$(cat FIN6_Phase1_scythe_threat.json | jq --raw-output '.threat.script[] | select(.module == "run") | .request')

# Create some vars for Operator TTPS
#OPERATOR_TTP=$(uuidgen)



# Example code for converting multi line string to array. 
# https://stackoverflow.com/questions/24628076/convert-multiline-string-to-array


# This writes all 11 JSON objects to one YAML file. Want one file per JSON object.

IFS=$'\n'
SPLIT_TTPS=($SCYTHE_TTP)


#if  [ -f "${OPERATOR_TTP}" ]; then
#   unset ${OPERATOR_TTP};
#fi

for (( i=0; i<${#SPLIT_TTPS[@]}; i++))
do
OPERATOR_TTP=$(uuidgen)
echo "
id: ${OPERATOR_TTP}
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
    command: ${SPLIT_TTPS[$i]}" > "${OPERATOR_TTP}.yml"
done
