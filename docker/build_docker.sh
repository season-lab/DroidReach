#!/bin/bash

docker build -t android-paths           \
    --build-arg USER_ID=$(id -u $USER)  \
    --build-arg GROUP_ID=$(id -g $USER) \
    .
