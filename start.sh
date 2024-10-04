#!/bin/bash

# change the directory into singlefile-FS and do make all, make load, make create and make mnt
cd singlefile-FS || { echo "Directory singlefile-FS non trovata"; exit 1; }
make all
make load
make create
make mnt

# Back to the main directory
cd ..
# change the directory into user and do make clean and make
cd user || { echo "Directory user non trovata"; exit 1; }

make clean
make

#  Back to the main directory
cd ..

# Do make clean, make and make mount in the main directory
make clean
make
make mount