#!/bin/bash
export KOVANICA_DATA_DIR=/root/Projects/kvnc/node-data
export KOVANICA_LISTEN_ADDR=0.0.0.0:8000
export KOVANICA_BOOTNODES=seed2.kovanica.online:8000,seed3.kovanica.online:8000
export KOVANICA_VALIDATOR_KEY=/root/Projects/kvnc/node-data/v.dat
export KOVANICA_MINE=0
export KOVANICA_FAUCET=0
export KOVANICA_ALLOW_RESET=0
export KOVANICA_OPERATOR=0
exec /usr/local/bin/kovanica-node "$@"
