#!/usr/bin/env python3

from os import system, name 
import subprocess
import sys


def clean_out(output):
	out=output.split('\n')
	ret=""
	x=False
	for line in out:
		if x==True and line!="\n":
			field=line.split(":")[0]
			value=line.split(":")[1]
			ret+=" \033[37;1m"+field+":\033[0m"+value+"\n"
		else:
			ret+=" "+line+"\n"
			x=True
	return ret


def check_h(output):
	print(" \033[37;1mSecurity fields:\033[32;1m")
	if "Strict-Transport-Security".lower() not in output.lower():
		print("\t\033[33;1m<!>\033[0m Missing \033[33;1m Strict-Transport-Security \033[0m field")
	if "X-Content-Type-Options".lower() not in output.lower():
		print("\t\033[33;1m<!>\033[0m Missing \033[33;1m X-Content-Type-Options \033[0m field")
	if "Content-Security-Policy".lower() not in output.lower():
		print("\t\033[33;1m<!>\033[0m Missing \033[33;1m Content-Security-Policy \033[0m field")
	if "X-XSS-Protection".lower() not in output.lower():
		print("\t\033[33;1m<!>\033[0m Missing \033[33;1m X-XSS-Protection \033[0m field")
	if "X-Frame-Options".lower() not in output.lower() and "frame-ancestors" not in output.lower():
		print("\t\033[33;1m<!>\033[0m Missing \033[33;1m X-Frame-Options \033[0m field or \033[33;1m frame-ancestors \033[0m value from CSP")
	print()
	print(" \033[37;1mInformation leaks:\033[32;1m")
	if "Server".lower() in output.lower():
		print("\t\033[33;1m<?>\033[0m Found \033[33;1m Server \033[0m field")
	if "X-Powered-By".lower() in output.lower():
		print("\t\033[33;1m<?>\033[0m Found \033[33;1m X-Powered-By \033[0m field")
	if "Powered-By".lower() in output.lower():
		print("\t\033[33;1m<?>\033[0m Found \033[33;1m Powered-By \033[0m field")
	if "X-AspNet".lower() in output.lower():
		print("\t\033[33;1m<?>\033[0m Found \033[33;1m X-AspNet \033[0m field")
	if "X-AspNet-Version".lower() in output.lower():
		print("\t\033[33;1m<?>\033[0m Found \033[33;1m X-AspNet-Version \033[0m field")
	if "X-AspNetMvc-Version".lower() in output.lower():
		print("\t\033[33;1m<?>\033[0m Found \033[33;1m X-AspNetMvc-Version \033[0m field")
	print()
	
	
		

if len(sys.argv) != 2:
	print("\nUsage:\n\t-> python3 literesph.py <url/IP>\n\t-> ./literesph.py <url/IP>\n")
	exit(1)
	
bashCommand = "curl -s -I -i " + sys.argv[1]
process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
output,error = process.communicate()

output=output.decode("UTF-8").strip()

output = clean_out(output)







print("\n\033[34;1m#################### HEADER FIELDS #####################\033[0m\n")
print("\t~~~ \033[37;1mRequest to \033[32;1m"+sys.argv[1]+"\033[0m ~~~\n")
print(output)
print("\033[34;1m########################################################\033[0m\n")


check_h(output)
