#!/bin/bash

RUNTIME_DIR=/tmp
LOG_DIR=`pwd`
cp input ${RUNTIME_DIR}/
cp gogo.go ${RUNTIME_DIR}/

pushd ${RUNTIME_DIR}
cat input | ssadump -run -interp=T gogo.go 2>${LOG_DIR}/trace.log
popd
