import os
import subprocess
import r2pipe

from utils.logger import logger

wordlist_good_string	= ['good','jobs','gg','here is','nice','welcome admin','success','valid','congrat','found the','correct','you did it','ok.','bravo','well','granted','here we go','jackpot']
wordlist_bad_string		= ['bad password','invalid','try','again','bye','wrong','not correct','incorrect','fail','keep trying','denied','not authorized','not the admin','username/password','go back']
wordlist_good_function	= ['win ','flag','getflag','bufinit','print_flag','show_flag','get_flag','printflag','showflag','getflag']
wordlist_bad_function	= ['loose','bad ',' fail ']

def Get_addr_int(addr):
	try:
		return int(addr,16)
	except:
		return None

def Determine_end_addr(config,win_word,fail_word):
	path = config['path_file']

	good_res_text	= [address for address in win_word  if Get_addr_int(address) == None]
	bad_res_text 	= [address for address in fail_word if Get_addr_int(address) == None]
	good_res_addr	= [Get_addr_int(address) for address in win_word  if Get_addr_int(address) != None ]
	bad_res_addr	= [Get_addr_int(address) for address in fail_word if Get_addr_int(address) != None ]

	good_res_text_1,  good_res_addr_1  ,bad_res_text_1  ,bad_res_addr_1 = Radare2_functions(path,good_res_text.copy(),bad_res_text.copy(),good_res_addr.copy(),bad_res_addr.copy())
	good_res_text_2,  good_res_addr_2  ,bad_res_text_2  ,bad_res_addr_2 = Radare2_strings(path,good_res_text.copy(),bad_res_text.copy(),good_res_addr.copy(),bad_res_addr.copy())

	return (good_res_addr_1+good_res_addr_2),(bad_res_addr_1+bad_res_addr_2)

def Radare2_functions(path,good_res_text,bad_res_text,good_res_addr,bad_res_addr):
	
	# Wordlist
	word_g = wordlist_good_function+good_res_text
	word_b = wordlist_bad_function+bad_res_text

	other  = []		

	r = r2pipe.open(path, flags=['-2'])
	result_functions = r.cmd('aaa;afl').strip().split('\n')
	for l in result_functions:
		w = list(filter(None, l.split(' ')))
		address  = int(w[0],16)
		function = w[-1]

		for good in word_g:
			if good in function.lower() or address in good_res_addr :
				if not any(bad in function.lower() for bad in bad_res_text) and address not in bad_res_addr:
					good_res_text.append(function)
					good_res_addr.append(address)
					logger(' [>] GOOD RESULT | Found at %s (FUNCTION) : "%s"'%(hex(address),function),'log',0,1)
					break

		for bad in word_b:
			if bad in function.lower() or address in bad_res_addr :
				if not any(good in function.lower() for good in good_res_text) and address not in good_res_addr :
					bad_res_text.append(function)
					bad_res_addr.append(address)					
					logger(' [>] BAD  RESULT | Found at %s (FUNCTION) : "%s"'%(hex(address),function),'log',0,1)
					break

	return good_res_text,good_res_addr,bad_res_text,bad_res_addr


def Radare2_strings(path,good_res_text,bad_res_text,good_res_addr,bad_res_addr):
	word_g = wordlist_good_string+good_res_text
	word_b = wordlist_bad_string+bad_res_text
	other  = []

	r = r2pipe.open(path, flags=['-2'])
	result_strings = r.cmd('!!rabin2 -z %s'%path).split('\n')

	## Result for strings
	for l in result_strings:
		if('ascii' in l):

			## Get Result | Parse
			w = list(filter(None, l.split(' ')))

			address = int(w[2] if(Get_addr_int(int(w[1],16)) == None) else w[1],16)
			text = ' '.join([t for t in w[w.index('ascii')+1:]]) if("ascii" in w) else w[-1]


			## IF text in wordlist or address in args valid adress + not already add in other result list => can't be valid+invalid ..
			for good in word_g:
				if good in text.lower() or address in good_res_addr :
					if not any(bad in text.lower() for bad in bad_res_text) and address not in bad_res_addr:
						good_res_text.append(text)
						good_res_addr.append(address)
						logger(' [>] GOOD RESULT | Found at %s (STRING) : "%s"'%(hex(address),text),'log',0,1)
						break

			for bad in word_b:
				if bad in text.lower() or address in bad_res_addr :
					if not any(good in text.lower() for good in good_res_text) and address not in good_res_addr :
						bad_res_text.append(text)
						bad_res_addr.append(address)
						logger(' [>] BAD  RESULT | Found at %s (STRING) : "%s"'%(hex(address),text),'log',0,1)
						break
		

			## Else > only print
			if(text not in bad_res_text+good_res_text):
				other.append((address,text))

	## Print Other text
	for res in other:
		logger(' [>] OTHER TEXT  | Found at %s (STRING) : "%s"'%(hex(res[0]),res[1]),'log',0,1)


	return good_res_text,good_res_addr,bad_res_text,bad_res_addr
