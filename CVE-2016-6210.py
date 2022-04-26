import paramiko
import time
user=raw_input("user: ")
p='A'*25000
ssh = paramiko.SSHClient()
starttime=time.clock()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
        ssh.connect('127.0.0.1', username=user,
        password=p)
except:
        endtime=time.clock()
total=endtime-starttime
print(total)
