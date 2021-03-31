#!/bin/bash

SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`

function pull_submodules {
    pushd "$SCRIPTPATH"

    git submodule init
    git submodule update

    popd
}

function compile_demangler {
    pushd "$SCRIPTPATH/native_finder/bin"

    if [ ! -f "./JavaDemangler.class" ]; then
        make
    fi

    popd
}

function setup_and_activate_venv {
    if [ -d "$SCRIPTPATH/venv" ]; then
        source "$SCRIPTPATH/venv/bin/activate"
        return;
    fi

    virtualenv -p python3 "$SCRIPTPATH/venv"
    source "$SCRIPTPATH/venv/bin/activate"

    pip install -r "$SCRIPTPATH/cex/requirements.txt"
    pip install pyyaml

    git clone https://github.com/androguard/androguard.git /tmp/androguard
    pushd /tmp/androguard
    pip install .
    popd
    rm -rf /tmp/androguard
}

pull_submodules
compile_demangler
setup_and_activate_venv
