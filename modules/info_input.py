import os
import subprocess
import time

from pwn import *

from utils.logger import logger
from modules.ltrace_method import Trace_lenght
from modules.gen_input import *
from modules.execute import *
from modules.analyse_type_input import analyse as analyse_input

context.log_level = 'critical'

def execmd(cmd):
	return subprocess.Popen(cmd,shell=True,stderr=subprocess.PIPE,stdout=subprocess.PIPE,stdin=subprocess.PIPE).communicate()


def determine_len_input(config,t=1.5):

	logger(' [>] Generating input wordlist ...','log',0,1)
	wordlist = Gen_wordlist(config)
	logger(' [>] Done ! %s inputs created'%str(len(wordlist)),'log',0,1)


	## Ltrace 
	logger(' [>] Trying Trace technique ...','info',1,0)
	len_Trace = Trace_lenght(config,wordlist)

	for _ in len_Trace:
		if(not _.endswith(':-1')):
			logger(' [+] Trace technique have found : %s '%str(len_Trace) ,'info',1,0)
			return len_Trace
	logger(' [>] Trace technique did not work','info',1,0)	
					

	## Gdb 

	# logger(' [>] Trying BruteForce using GDB ...','info',1,0)
	# lenth_gdb = None #gdb_length(config,charset)
	# if(-1 in len_Trace):
	# 	logger(' [>] GDB technique did not work','info',0,0)
	# 	return [-1 for _ in range(len(len_Trace))]
	# else:
	# 	logger(' [+] GDB technique seems to have found the lenght of the input : %s '%str(lenth_ltrace) ,'info',0,0)


	return -1

def check_endpoint(input):
	try:		
		l = list(eval(input))
		if(len([l[i] for i in range(len(l)) if(l[i] == 'args:digit' or 'stdin:digit' or 'args:ascii' or 'stdin:ascii' )]) == len(l) and len(l) != 0):
			return True
		else:
			return False
	except:
		return False



def determine_Endpoint(config,t=1):
	path 	= config['path_file']
	result 	= []
	all_res = []

	logger(' [>] Opening Binary without data : [normal|ltrace|strace|gdb]','log',0,1)
	ref = execute(path,t,[],[])
	logger(' [*] Result : normal: %s | ltrace: %s | strace: %s\n'%(ref['normal'],ref['ltrace'],ref['strace']),'warning',0,2)

	logger(' [>] Generating input wordlist ...','log',0,1)
	wordlist = gen_wordlist_endpoint()
	logger(' [>] Done ! %s inputs created\n'%str(len(wordlist)),'log',0,1)

	logger(' [>] Opening Binary With data : %s data'%(len(wordlist)),'log',0,1)
	for inp in wordlist:
		res = execute(path,t,inp[0],inp[1])
		if(res not in all_res):
			all_res.append(res)
			logger(' [*] [Stdin: %s | Args: %s] >> Result : normal: %s | ltrace: %s | strace: %s'%(len(inp[0]),len(inp[1]),res['normal'],res['ltrace'],res['strace']),'warning',0,2)
		result.append([inp,res])

	return analyse_input([ref],result,4)
