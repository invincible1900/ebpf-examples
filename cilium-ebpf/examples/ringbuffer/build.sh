#!/bin/bash
export BPF_CLANG=clang
go generate -x
go build
