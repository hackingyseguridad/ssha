find / -maxdepth 5 -name .ssh -exec grep -rnw {} -e 'PRIVATE' \; 2> /dev/null
