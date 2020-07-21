import paramiko
import time
import sys
def realtime_config():
	nbytes = 4096
	hostname1 = 'ipaddress here'
	port = 22
	username = 'username here' 
	password = 'password here'
	command1 = 'set terminal length 0'
	command2 = 'sh configuration commands'
	command3 = 'sh ip route'

	ssh=paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	ssh.connect(hostname1,port,username,password)
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	chan = ssh.invoke_shell()
	#send terminal length 0 command
	chan.send('set terminal length 0\n')
	time.sleep(1)
	resp = chan.recv(9999)
	print ('terminal output')
	print resp
	#send show configuration commands

	chan.send('show configuration commands\n')
	time.sleep(5)
	resp1 = chan.recv(999999)
	print ('config output')
	print resp1

	f1= open('vyatta.txt',"w+")
	f1.write(resp1)
	f1.close()
	print 'vyatta.txt created'
	chan.send('sh ip route\n')
	time.sleep(2)
	resp2 = chan.recv(999999)
	print ('routes')
	print resp2
	f2= open('vyatta-routes.txt',"w+")
	f2.write(resp2)
	f2.close()
	print 'vyatta-routes.txt created'
	chan.close()
	ssh.close()
