


nmap -p 22 --script ssh2-enum-algos -sV -iL ip.txt -oG - | grep '22/open' 
