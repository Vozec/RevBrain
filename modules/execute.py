import os
import subprocess
import time
import itertools
import string
import logging
from pwn import *
from utils.logger import logger

context.log_level = 'error'
logging.getLogger('pwnlib').setLevel('ERROR')

def gen_wordlist_endpoint(max_input=4,len_input=5):
	all_ = []
	charset = string.ascii_letters
	charset2 = '012456789'
	for i in range(max_input+1):
		for j in range(max_input+1):
			stdin = [[''.join(random.choice(charset) for i in range(len_input))][0] for _ in range(i)]
			args  = [[''.join(random.choice(charset) for i in range(len_input))][0] for _ in range(j)]

			stdin2 = [[''.join(random.choice(charset2) for i in range(len_input))][0] for _ in range(i)]
			args2  = [[''.join(random.choice(charset2) for i in range(len_input))][0] for _ in range(j)]
			
			all_.append((stdin,args))
			all_.append((stdin2,args2))

	return all_[1:]


def count_line(data):
	return data.decode().count('\n')

def trace_run(path,t,input_stdin=[],input_arg=[],mode='ltrace'):
	try:
		input_stdin = 'echo \'%s\' | '%('\n'.join(input_stdin)[1:]) if(input_stdin!=[]) else ''
		input_arg   = ' '.join(input_arg)
		cmd = '%s%s %s %s'%(input_stdin,mode,path,input_arg)
		p = process(cmd, shell=True)
		buff = p.recvall(timeout=t)
		p.close()
		return count_line(buff)
	except Exception as ex:
		logger(' [-] Error: %s'%str(ex),'error',0,1)
		return -1

def normal_run(path,t,input_stdin=[],input_arg=[]):
	try:
		input_stdin = 'echo \'%s\' | '%('\n'.join(input_stdin)[1:]) if(input_stdin!=[]) else ''
		input_arg   = ' '.join(input_arg)
		cmd = '%s./%s %s'%(input_stdin,path,input_arg)
		p = process(cmd, shell=True)
		buff = p.recvall(timeout=t)
		p.close()
		return count_line(buff)
	except Exception as ex:
		logger(' [-] Error: %s'%str(ex),'error',0,1)
		return -1

def execute(path,t,input_stdin=[],input_arg=[]):
	result = {'normal':-1,'ltrace':-1,'strace':-1}
	try:
		result['normal'] = normal_run(path,t,input_stdin,input_arg)
		result['ltrace'] = trace_run(path,t,input_stdin,input_arg)
		result['strace'] = trace_run(path,t,input_stdin,input_arg,'strace')
		return result
	except Exception as ex:
		logger(' [-] Error: %s'%str(ex),'error',0,1)
		return result

