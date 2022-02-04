#!/bin/sh

if [ "$1" = "full" ]; then
  git submodule init
  cd llhttp
  npm install
  make
  cd ..
fi

cc http.c -O3 -march=native -pthread -lssl -lcrypto llhttp/build/libllhttp.a
