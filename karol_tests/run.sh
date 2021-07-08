#!/bin/bash

g++ -std=c++11 -I../include -I../lib -o build/out.out publish_prekey_bundle.cpp \
../build/release/src/*.o \
../build/release/lib/crypto-algorithms/*.o \
../build/release/lib/curve25519-donna/curve25519-donna.o \
&& ./build/out.out
