#!/bin/bash
for n in `cat ip.txt`; do echo $n; telnet $n 22 |grep SSH; done
