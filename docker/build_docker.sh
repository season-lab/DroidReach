#!/bin/bash

docker build -t droidreach              \
    --build-arg USER_ID=$(id -u $USER)  \
    --build-arg GROUP_ID=$(id -g $USER) \
    .
