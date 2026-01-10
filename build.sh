#!/bin/bash

NPROC=$(which nproc)
CPU=$($NPROC)

echo -e "\033[36mClearing previous build with $CPU cores\033[m"
make -j $CPU distclean
cd src/secp256k1/
make -j $CPU distclean
echo -e "\033[36m---> done!!!\033[m"

echo -e "\033[36mBuilding Secp256k1 with $CPU cores\033[m"
./autogen.sh
./configure
make -j $CPU
echo -e "\033[36m---> done!!!\033[m"

echo -e "\033[36mBuilding Qtwallet with $CPU cores\033[m"
cd ../..
qmake
make -j $CPU
echo -e "\033[36m---> done!!!\033[m"