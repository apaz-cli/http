#!/bin/sh

if [ "$1" = "full" ]; then
  git submodule init
  cd llhttp
  npm install
  make
  cd ..
fi

cc -O3 -march=native -pthread http.c llhttp/build/libllhttp.a
