#!/bin/bash

for i in `cat usuarios.txt`
do
        echo $i
        python script.py $1 --port 22 $i
done
