#!/bin/bash

usage()
{
cat << EOF
usage: $0 [-r <number>] [-c <string>]

This script execute a simulation comparing two different techniques 
(i.e., CVSS and FRAPE) for fix vulnerability in computer networks.

OPTIONS:
    -r Number of repetitions
    -c config file
EOF
}


while getopts "r:c:" OPTION
do
    case "${OPTION}" in
        r)
            r=${OPTARG}
            ;;
        c)
            c=${OPTARG}
            ;;
        *)
            usage
            exit
            ;;
    esac
done

if [ -z "${r}" ] || [ -z "${c}" ]
then
    usage
    exit
fi

rm -rf output/

for i in $(seq 1 $r)
do
    echo "${i}/${r} Running..."
    OUTPUT=$(python main.py ${c})
    clear
done

echo "${r}/${r} Done!"