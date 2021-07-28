#!/bin/bash

g++ -std=c++11 -I../include -I../lib -o build/out.out tools.cpp user.cpp session.cpp main.cpp  \
../build/release/src/*.o \
../build/release/lib/crypto-algorithms/*.o \
../build/release/lib/curve25519-donna/curve25519-donna.o \
&& ./build/out.out
