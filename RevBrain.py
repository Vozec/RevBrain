import argparse
import os
import logging

from utils.logger import logger
from modules.info_binary import *
from modules.info_input import *
from modules.get_valid_result import *
from modules.angr_solver import *


logging.getLogger('pwntools').setLevel('ERROR')


## header
def header():
	logger(r"""
    ____            ____             _     
   / __ \___ _   __/ __ )_________ _(_)___ 
  / /_/ / _ \ | / / __  / ___/ __ `/ / __ \
 / _, _/  __/ |/ / /_/ / /  / /_/ / / / / /
/_/ |_|\___/|___/_____/_/   \__,_/_/_/ /_/
""",'log',0,0)




def parse_args():
	parser = argparse.ArgumentParser(add_help=True, description='This tool automates the recognition phase & solve a crackme binary. Mainly useful for CTFs')
	parser.add_argument("-f",dest="file",type=str,required=True, help="Path of the binary")
	parser.add_argument("-w",dest="formatflag",type=str,required=False, help="Format Flag (default= 'flag{}' )")
	parser.add_argument("-g",dest="win_word",type=str,required=False, help="Valid string/address result (ex: 'Here is the flag' ) | ex: -g \"you win\" or -g \"['win','0x00000835']\"")
	parser.add_argument("-b",dest="fail_word",type=str,required=False,help="Fail  string/address result (ex: 'Invalid Password' ) | ex: -g \"failed \" or -g \"['nop','invalid',0x00000872]\"")
	parser.add_argument("-a",dest="arch",type=str,choices=["32","64"],required=False, help="Type of architecture")
	parser.add_argument("-i",dest="type_input",type=str,required=False, help="Type of Input: (ex: ['stdin:digit','args:ascii','args:ascii'])")
	parser.add_argument("-t",dest="timeout",type=int,help="Set Timeout (minutes) (default=5min)")
	args = parser.parse_args()
	return args



################################################################################################################################
#######################################################   SETUP    #############################################################
################################################################################################################################

def Setup_FormatFlag(config,args):
	## Change format flag
	if(args.formatflag != None):
		config['formatflag'] = args.formatflag.replace('{','').replace('}','')
		logger(' [+] Setting the formatflag to : %s , input will start with it'%config['formatflag'],'info',1,0)
	else:
		config['formatflag'] = ""
		#logger(' [+] Setting the default formatflag to : flag{-}','info',1,0)
	return config

def Setup_Timeout(config,args):
	## Change Timeout
	if(args.timeout != None):
		config['timeout'] = args.timeout
		logger(' [+] Setting the timeout to : %smin'%str(config['timeout']),'info',1,0)
	else:
		config['timeout'] = 5
		logger(' [+] Setting the default timeout to : 5min','info',1,0)
	return config

def Setup_Arch(config,args):
	## Change architecture
	if(args.arch != None):
		config['type_arch'] = args.arch
		logger(' [+] Setting the architecture to : %s'%config['type_arch'],'info',1,0)
	else:
		logger(' [+] Determining valid architecture ...','info',1,0)
		arch_found,config = determine_arch(config)		
		logger(' [+] Architecture found : %s bits'%arch_found,'info',0,0)
		config['type_arch'] = arch_found
	return config

def Setup_TypeInput(config,args):
	## Change Type of input
	if(args.type_input != None and check_endpoint(args.type_input)):
		config['type_input'] = eval(args.type_input)
		logger(' [+] Setting the endpoint to : %s\n'%config['type_input'],'info',1,0)
	else:
		logger(' [+] Determining Endpoint ...','info',1,0)
		type_input = determine_Endpoint(config)
		logger(' [+] Endpoint found : %s \n'%type_input,'info',0,0)
		config['type_input'] = type_input
	return config

def Setup_Words(config,args):
	## Change Type of input
	win_word  = []
	fail_word = []

	if(args.win_word != None):
		try:	
			r = eval(args.win_word)
		except:
			pass
		if(type(r) == list):
			for elem in r:
				win_word.append(elem)
				logger(' [+] Adding %17s to the "good result" wordlist '%('\033[95m'+str(elem)+'\033[0m\033[93m'),'info',0,0)
		else:
			win_word.append(args.win_word)
			logger(' [+] Adding %17s to the "good result" wordlist '%('\033[95m'+str(args.win_word)+'\033[0m\033[93m'),'info',0,0)

		
	if(args.fail_word != None):
		try:	
			r = eval(args.fail_word)
		except:
			pass
		if(type(r) == list):
			for elem in r:
				fail_word.append(elem)
				logger(' [+] Adding %17s to the "bad result" wordlist '%('\033[95m'+str(elem)+'\033[0m\033[93m'),'info',0,0)
		else:
			fail_word.append(args.fail_word)
			logger(' [+] Adding %17s to the "bad result" wordlist '%('\033[95m'+str(args.fail_word)+'\033[0m\033[93m'),'info',0,0)
	

	logger(' [+] Getting Interesting Address ...','info',1,0)
	good_res,bad_res = Determine_end_addr(config,win_word,fail_word)

	config['fail_word'] = bad_res
	config['win_word']  = good_res

	return config
################################################################################################################################
################################################################################################################################
################################################################################################################################

def parse_config(args):
	config = {}

	## Check if file exist
	if not os.path.isfile(args.file):
		logger(" [-] Error : File not found ! %s"%args.file,'error',1,0)
		return None
	else:
		config['path_file'] = args.file

	## If executable > Show info
	if(not is_executable(config['path_file'])):
		logger(" [-] Error : File don't seems to be executable ! %s"%args.file,'error',1,0)
		return None
	else:
		logger(' [+] Getting infos about binary ...','info',0,0)
		info_executable(config['path_file'])

	config = Setup_FormatFlag(config,args)
	config = Setup_Timeout(config,args)
	config = Setup_Arch(config,args)
	config = Setup_TypeInput(config,args)	
	config = Setup_Words(config,args)

	return config



def main():
	header()
	config = parse_config(parse_args())	

	if(config == None):return None

	logger(' [+] Determining Lenght of input ...\n','info',1,0)

	config['len_input'] = len_input = determine_len_input(config)
	if(len_input == -1):
		logger(' [+] No input Lenght has been found ','info',1,0)


	if len(config['type_input']) == 1 :
		logger(' [+] Trying to Solve using Angr ...','info',1,0)

		if(solver_angr(config,angr.options.symbolic,'symbolic')):return
		if(solver_angr(config,angr.options.unicorn,'unicorn')):return
		if(solver_angr(config,angr.options.approximation,'approximation')):return

if __name__ == '__main__': 
	main()
