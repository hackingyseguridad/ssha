sudo cat /var/log/auth* | grep Accepted | awk '{print $1 " " $2 "\t" $3 "\t" 
