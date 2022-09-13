#!/bin/bash

script_path="$(realpath ${0})"
script_dir="$(dirname "${script_path}")"

unshare -r -n sh -c "sh ${script_dir}/ifconfig.sh up && ip link set dev lo up && sh ${script_dir}/run.sh $*"
