#! /usr/bin/env bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

function command_exists {
    hash "$1" 2>/dev/null
}

if ! command_exists pip; then
    echo "Please install pip to run this script."
    exit 1
fi

if ! command_exists git; then
    echo "Please install git to run this script"
    exit 1
fi

echo -e ">>> Installing python moudules ...\n"
pip install -r "$SCRIPT_DIR/requirements.txt"

echo -e "\n>>> Pulling submodule source code, wait ...\n"
git submodule update --init --recursive

echo -e "\n [OK] please run sudo python tcpdns.py -f tcpdns.json.example"

