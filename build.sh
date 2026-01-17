#!/bin/bash

set -e 

mkdir -p build
cd build

cmake ..
make 

mv -f adiatron ..
echo "Done."
