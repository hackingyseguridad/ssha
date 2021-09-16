  
#!/bin/bash
# ver log de IP remotas que han establecido conexion SSH
#
sudo cat /var/log/auth* | grep Accepted | awk '{print $1 " " $2 "\t" $3 "\t" 
