import string
import random

all_lenght = []

def combi(res=[],n=10,m=1):
	global all_lenght
	_ = []
	_.extend(res)
	if m==1:
		_.append(n)
		all_lenght.append(_)
		return
	for i in range(1,n):
		if n - i > 0:
			_.append(i)
			combi(_,n-i,m-1)
			del _[-1]


def gen_str(all_lenght,charset_ascii,charset_digit,config):
	all_ = []
	for combi in all_lenght:
		final = []
		for i in range(len(combi)):
			charset = charset_ascii			
			final.append(''.join(random.choices(charset,k=combi[i])))
		all_.append(final)
	return all_

def replace_charset(wordlist,config):
	for k in range(len(config['type_input'])):
		if(config['type_input'][k].split(':')[1] == 'digit'):
			for i in range(len(wordlist)):
				wordlist[i][k] = ''.join(random.choices('123456789',k=len(wordlist[i][k] )))
	return wordlist


def Gen_wordlist(config):
	global all_lenght
	wordlist = []
	splitter	= len(config['type_input'])
	charset_ascii 	= string.ascii_letters
	charset_digit 	= '123456789'
	old = 0
	for length in range(len(config['type_input']),20):
		combi([],length,splitter)
		words   	= gen_str(all_lenght[old:],charset_ascii,charset_digit,config)
		old 		= len(all_lenght)
		wordlist 	+= words
	return replace_charset(wordlist,config)