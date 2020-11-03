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
	if "\nPowered-By".lower() in output.lower():
		print("\t\033[33;1m<?>\033[0m Found \033[33;1m Powered-By \033[0m field")
	if "X-AspNet:".lower() in output.lower():
		print("\t\033[33;1m<?>\033[0m Found \033[33;1m X-AspNet \033[0m field")
	if "X-AspNet-Version".lower() in output.lower():
		print("\t\033[33;1m<?>\033[0m Found \033[33;1m X-AspNet-Version \033[0m field")
	if "X-AspNetMvc-Version".lower() in output.lower():
		print("\t\033[33;1m<?>\033[0m Found \033[33;1m X-AspNetMvc-Version \033[0m field")
	if "MicrosoftSharePointTeamServices".lower() in output.lower():
		print("\t\033[33;1m<?>\033[0m Found \033[33;1m MicrosoftSharePointTeamServices \033[0m field")
	print()


def chk_options(output):
	print(" \033[37;1mAllowed HTTP methods (using OPTIONS):\033[32;1m")
	ret="\033[33;1m-> \033[0m"
	if "not allowed" in output.lower():
		print("\t\033[31;1m Method OPTIONS Not Allowed... \033[0m\n")
	elif "allow" not in output.lower():
		print("\t\033[31;1m Can't find allowed methods... \033[0m\n")
	else:
		out=output.split('\n')
		for line in out:
			if "allow" in line.lower():
				l=line.split(" ")
				for e in l:
					if "allow" not in e.lower():
						if "GET" in e.upper() or "POST" in e.upper():
							ret+="\033[37;1m"+e+"\033[0m "
						elif "TRACE" in e.upper() or "OPTIONS" in e.upper() or "PROPFIND" in e.upper() or "PROPPATCH" in e.upper() or "PUT" in e.upper() or "DELETE" in e.upper() or "MOVE" in e.upper() or "COPY" in e.upper():
							ret+="\033[31;1m"+e+"\033[0m "
						else:
							ret+="\033[33;1m"+e+"\033[0m "
						
				print("\t"+ret+"\n")
				return
	return
	
		

if len(sys.argv) != 2:
	print("\nUsage:\n\t-> python3 literesph.py <url/IP>\n\t-> ./literesph.py <url/IP>\n")
	exit(1)
	


bashCommand = "curl --connect-timeout 1 -s -I -i " + sys.argv[1]
process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
output,error = process.communicate()

output=output.decode("UTF-8").strip()
if output=="":
	print("\033[31;1m While performing HEAD: Connection problem... \033[0m")
else:
	output = clean_out(output)
	print("\n\033[34;1m#################### HEADER FIELDS #####################\033[0m\n")
	print("\t~~~ \033[37;1mRequest to \033[32;1m"+sys.argv[1]+"\033[0m ~~~\n")
	print(output)
	print("\033[34;1m########################################################\033[0m\n")
	check_h(output)



bashCommand = "curl  --connect-timeout 1 -s -I -i -X OPTIONS " + sys.argv[1]
process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
output,error = process.communicate()

output = output.decode("UTF-8").strip()
if output=="":
	print("\033[31;1m While performing OPTIONS: Connection problem... \033[0m")
else:
	chk_options(output)
