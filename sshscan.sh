#!/bin/bash
for n in `cat ip.txt`; do echo $n; timeout --signal=9 2 telnet $n 22 |grep SSH; done
