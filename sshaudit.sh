# 
#
# audit ssh (R) hackingyseguridad,.   2024
echo
ssh-audit $1 -p 22
echo
nmap -Pn -sT -p22 $1 -sC # Send default nmap scripts for SSH
nmap -Pn -sT -p22 $1 -sV # Retrieve version
nmap -Pn -sT -p22 $1 --script ssh2-enum-algos # Retrieve supported algorythms
nmap -Pn -sT -p22 $1 --script ssh-hostkey --script-args ssh_hostkey=full # Retrieve weak keys
nmap -Pn -sT -p22 $1 --script ssh-auth-methods  --script-args="ssh.user=root"  # Check authentication methods
