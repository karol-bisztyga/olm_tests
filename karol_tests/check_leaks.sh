#!/bin/bash

g++ -std=c++11 -I../include -I../lib -o build/out.out main.cpp \
../build/release/src/*.o \
../build/release/lib/crypto-algorithms/*.o \
../build/release/lib/curve25519-donna/curve25519-donna.o \
&& valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         --verbose \
         --log-file=./build/valgrind-out.txt \
         ./build/out.out

