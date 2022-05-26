import subprocess
import re
import os

from utils.logger import logger

def execmd(cmd):
	return subprocess.Popen(cmd,shell=True,stderr=subprocess.PIPE,stdout=subprocess.PIPE,stdin=subprocess.PIPE).communicate()

def determine_arch(config):
	## Exec 3 cmd ##
	resp_file 		= execmd('file %s'%config['path_file'])[0].decode().strip()
	resp_checksec 	= execmd('checksec %s'%config['path_file'])[1].decode().strip()
	resp_od			= execmd('od -An -t x1 -j 4 -N 1 %s'%config['path_file'])[0].decode().strip()
	
	## Is Dynamic ? 
	config["dynamic"] = True if 'dynamically linked' in resp_file else False

	# RESP 1 
	b_od 			= '32' if '01' in resp_od else '64'
	
	# RESP 2 
	b_file 			= ''
	b_file_match 	= re.search(r'ELF (.*?)-bit',resp_file)
	if b_file_match != None: 
		b_file 		= b_file_match.group(1)
	
	# RESP 3 
	b_checksec 			= ''
	b_checksec_match 	= re.search(r'Arch:     (.*?)\n',resp_checksec)
	if b_checksec_match != None:
		b_checksec = '32' if('32' in b_checksec_match.group(1)) else '64'
		
	

	if(b_od == b_file == b_checksec):
		return b_od,config
	else:
		logger(' [*] Waiting .. Unable to determine the architecture of the binary . Enter it manually : ','warning',1,0)
		while(True):
			resp = input(' [>] ').strip()			
			if(resp == '32'):
				return '32',config
			elif resp == '64':
				return '64',config
			else:
				logger(' [-] Invalid Architecture , please choose between \'64\' and \'32\' !','error',1,0)

def is_executable(path):
	if('.bin' in path) or 'executable' in execmd('file %s'%path)[0].decode().strip() :
		return True
	else:
		return False

def info_executable(path):
	resp_checksec 	= '\n'.join(execmd('checksec %s'%path)[1].decode().strip().split('\n')[1:])
	logger(' [*] CheckSec :\n\n'+resp_checksec+'\n','warning',0,0)