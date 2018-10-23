#!/bin/sh

sed -r -e '
1 i bits 32\
\
section .text\
    global _start\
\
_start:

s/([0-9A-F]+\s+){2}/    /g
'
