#!/bin/bash

# change the directory into singlefile-FS and do make clean and make remove
cd singlefile-FS || { echo "Directory singlefile-FS non trovata"; exit 1; }
make clean
make remove

# Go back to the main directory
cd ..

# change the directory into user and do make clean
cd user || { echo "Directory user non trovata"; exit 1; }

make clean

# Go back to the main directory
cd ..

# Do make unmount and make clean in the main directory
make unmount
make clean