#!/bin/bash

cd ..

rm -rf build
make && cmake . -Bbuild && cmake --build build

cd -
