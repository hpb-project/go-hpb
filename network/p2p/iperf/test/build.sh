#!/bin/bash
gcc client.c -static -liperf -o client.exe
gcc server.c -static -liperf -o server.exe



