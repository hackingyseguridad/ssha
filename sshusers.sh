#!/bin/bash

for i in `cat usuarios.txt`
do
        echo $i
        python usuariossh.py $1 --port 22 $i
done
