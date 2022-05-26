from pwn import *
import re
import random

from utils.logger import logger
from modules.execute import *

context.log_level = 'critical'

def Trace_lenght(config,wordlist,t=1.5):

	wordlist = wordlist[:50]


	path 	= config['path_file']
	result 	= []
	all_res = []

	stdin = args = []
	for i in range(len(config['type_input'])):
		if('stdin' in config['type_input'][i]):
			stdin.append(wordlist[0][i])
		else:
			args.append(wordlist[0][i])

	ref = execute(path,t,stdin,args)
	
	for k in range(len(wordlist[1:])):
		inp = wordlist[1:][k]
		stdin = []
		args  = []
		for i in range(len(config['type_input'])):
			if('stdin' in config['type_input'][i]):
				stdin.append(inp[i])
			else:
				args.append(inp[i])
		res = execute(path,t,stdin,args)
		if(res not in all_res):
			all_res.append(res)
			logger(' [*] [Stdin: %s | Args: %s] >> Result : normal: %s | ltrace: %s | strace: %s'%(len(stdin),len(args),res['normal'],res['ltrace'],res['strace']),'warning',0,2)
		
		elif(k%(len(wordlist[1:])//10)==0 and k+1 > len(wordlist[1:])//10 and k > 100):
			logger(' [?] Progress: %s/%s'%(k,len(wordlist[1:])),'progress',0,3)

		result.append([inp,res])

	return analyse(config,ref,result)


def remove_params(result):
	normal = []
	ltrace = []
	strace = []

	for element in result:
		if(element[1]['normal'] not in normal):normal.append(element[1]['normal'])
		if(element[1]['ltrace'] not in ltrace):ltrace.append(element[1]['ltrace'])
		if(element[1]['strace'] not in strace):strace.append(element[1]['strace'])

	return [['normal','ltrace','strace'][i] for i in range(3) if len([normal,ltrace,strace][i]) > 1]



def analyse(config,ref,result,error_diff=2):
	new = [result[i] for i in range(len(result)) if result[i][1] != ref]

	if(len(new)==0):return [elem + ':-1' for elem in config['type_input']]

	index_max_normal = index_max_ltrace = index_max_strace= 0

	for i in range(len(new)):
		if(new[i][1]['normal'] > new[index_max_normal][1]['normal'] + error_diff):
			index_max_normal = i
		if(new[i][1]['ltrace'] > new[index_max_ltrace][1]['ltrace'] + error_diff):
			index_max_ltrace = i
		if(new[i][1]['strace'] > new[index_max_strace][1]['strace'] + error_diff):
			index_max_strace = i

	best_index = [index_max_normal,index_max_ltrace,index_max_strace]
	usefull_param = remove_params(new)

	final_index = [best_index[i] for i in range(len(best_index)) if list(ref.keys())[i] in usefull_param]

	if(final_index==[]):final_index = best_index

	if(all(elem == final_index[0] for elem in final_index)):
		return [config['type_input'][i] + ':%s'%(len(new[final_index[0]][0][i])) for i in range(len(config['type_input']))]
	else:
		#all_sum = [sum([x for x in list(new[_][1].values())]) for _ in final_index]
		#print(all_sum,final_index,best_index)
		return [config['type_input'][i] + ':-1' for i in range(len(config['type_input']))]
	# else:
	# 	return -1

	return -1