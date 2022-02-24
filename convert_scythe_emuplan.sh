#!/bin/bash

# Capture SCYTHE variables

SCYTHE_THREAT_DESCRIPTION=$(cat FIN6_Phase1_scythe_threat.json | jq --raw-output '.threat | .description')

SCYTHE_THREAT_NAME=$(cat FIN6_Phase1_scythe_threat.json | jq --raw-output '.threat | .name')

SCYTHE_TTP_PAYLOAD=$(cat FIN6_Phase1_scythe_threat.json | jq --raw-output '.threat.script[] | select(.module == "downloader") | .request' | cut -d " " -f2 | cut -d '"' -f2)

#SCYTHE_TTP_PAYLOAD_DEST=$(cat FIN6_Phase1_scythe_threat.json | jq --raw-output '.threat.script[] | select(.module == "downloader") | .request' | cut -d '"' -f4)

SCYTHE_TTP=$(cat FIN6_Phase1_scythe_threat.json | jq --raw-output '.threat.script[] | select(.module == "run") | .request')

SCYTHE_MITRE_TECHNIQUE_ID=$(cat FIN6_Phase1_scythe_threat.json | jq --raw-output '.threat.script[] | select(.module == "run") | .rtags | .[]' | grep -E 'T[0-9]{4}.?|[0-9]{3}' | cut -d ":" -f2)

SCYTHE_MITRE_TECHNIQUE_ID_PAYLOAD=$(cat FIN6_Phase1_scythe_threat.json | jq --raw-output '.threat.script[] | select(.module == "downloader") | .rtags | .[]' | grep -E 'T[0-9]{4}.?|[0-9]{3}' | cut -d ":" -f2)




# Example code for converting multi line string to array. 
# https://stackoverflow.com/questions/24628076/convert-multiline-string-to-array

# Set delimeter for IFS to newline and prepare SCYTHE vars for arrays
IFS=$'\n'

SPLIT_SCYTHE_PAYLOAD=($SCYTHE_TTP_PAYLOAD)
SPLIT_MITRE_TECH_ID_PAYLOAD=($SCYTHE_MITRE_TECHNIQUE_ID_PAYLOAD)
for ((i=0, j=0, i<${#SPLIT_SCYTHE_PAYLOAD[@]}; j<${#SPLIT_MITRE_TECH_ID_PAYLOAD[@]}; i++, j++))
do

OPERATOR_TTP=$(uuidgen)
SCYTHE_TTP_COUNTER=$((SCYTHE_TTP_COUNTER+1))
SCYTHE_TTP_NAME=${SCYTHE_THREAT_NAME}-${SCYTHE_TTP_COUNTER}

MITRE_ATTACK_TECHNIQUE_NAME=$(cat enterprise-attack.json | jq --raw-output --arg technique_id ${SPLIT_MITRE_TECH_ID_PAYLOAD[$j]} '.objects[] | select(.type == "attack-pattern") | select(.external_references[0].external_id == $technique_id) | .name')

MITRE_ATTACK_TACTIC_NAME=$(cat enterprise-attack.json | jq --raw-output --arg technique_id ${SPLIT_MITRE_TECH_ID_PAYLOAD[$j]} '.objects[] | select(.type == "attack-pattern") | select(.external_references[0].external_id == $technique_id) | .kill_chain_phases[].phase_name')

SCYTHE_TTP_PAYLOAD_DEST=$(cat FIN6_Phase1_scythe_threat.json | jq --raw-output '.threat.script[] | select(.module == "downloader") | .request' | cut -d '"' -f4)

echo $SCYTHE_TTP_PAYLOAD_DEST

SPLIT_MITRE_TECH_NAME=($MITRE_ATTACK_TECHNIQUE_NAME)
SPLIT_MITRE_TACTIC_NAME=($MITRE_ATTACK_TACTIC_NAME)
SPLIT_SCYTHE_PAYLOAD_DEST=($SCYTHE_TTP_PAYLOAD_DEST)

echo $SPLIT_SCYTHE_PAYLOAD_DEST[$m]

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
tactic: ${SPLIT_MITRE_TACTIC_NAME[$l]}
technique:
  id: ${SPLIT_MITRE_TECH_ID_PAYLOAD[$j]}
  name: ${SPLIT_MITRE_TECH_NAME[$k]}
platforms:
  windows:
    psh:
      command: IWR -Uri '${SPLIT_SCYTHE_PAYLOAD[$i]}' -OutFile ${SPLIT_SCYTHE_PAYLOAD_DEST[$i]}"> "${OPERATOR_TTP}.yml"
done

echo ${SPLIT_SCYTHE_PAYLOAD_DEST[$i]}

SPLIT_TTPS=($SCYTHE_TTP)
SPLIT_MITRE_TECH_ID=($SCYTHE_MITRE_TECHNIQUE_ID)
#SPLIT_SCYTHE_PAYLOAD=($SPLIT_SCYTHE_PAYLOAD)
for ((i=0, j=0, i<${#SPLIT_TTPS[@]}; j<${#SPLIT_MITRE_TECH_ID[@]}; i++, j++))

do
OPERATOR_TTP=$(uuidgen)
SCYTHE_TTP_COUNTER=$((SCYTHE_TTP_COUNTER+1))
SCYTHE_TTP_NAME=${SCYTHE_THREAT_NAME}-${SCYTHE_TTP_COUNTER}

MITRE_ATTACK_TECHNIQUE_NAME=$(cat enterprise-attack.json | jq --raw-output --arg technique_id ${SPLIT_MITRE_TECH_ID[$j]} '.objects[] | select(.type == "attack-pattern") | select(.external_references[0].external_id == $technique_id) | .name')

MITRE_ATTACK_TACTIC_NAME=$(cat enterprise-attack.json | jq --raw-output --arg technique_id ${SPLIT_MITRE_TECH_ID[$j]} '.objects[] | select(.type == "attack-pattern") | select(.external_references[0].external_id == $technique_id) | .kill_chain_phases[].phase_name')

#SCYTHE_TTP_PAYLOAD=$(cat FIN6_Phase1_scythe_threat.json | jq --raw-output '.threat.script[] | select(.module == "downloader") | .request' | cut -d " " -f2)


SPLIT_MITRE_TECH_NAME=($MITRE_ATTACK_TECHNIQUE_NAME)
SPLIT_MITRE_TACTIC_NAME=($MITRE_ATTACK_TACTIC_NAME)
SPLIT_SCYTHE_PAYLOAD=($SCYTHE_TTP_PAYLOAD)



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
tactic: ${SPLIT_MITRE_TACTIC_NAME[$l]}
technique:
  id: ${SPLIT_MITRE_TECH_ID[$j]} 
  name: ${SPLIT_MITRE_TECH_NAME[$k]}
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
