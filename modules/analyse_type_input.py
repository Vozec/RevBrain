from utils.logger import logger

def analyse(ref,result,ecart_max=0):
	new = [result[i] for i in range(len(result)) if result[i][1] != ref[0]]

	index_max_normal = index_max_ltrace = index_max_strace= 0

	for i in range(len(new)):
		if(new[i][1]['normal'] > new[index_max_normal][1]['normal'] + ecart_max):
			index_max_normal = i
		if(new[i][1]['ltrace'] > new[index_max_ltrace][1]['ltrace'] + ecart_max):
			index_max_ltrace = i
		if(new[i][1]['strace'] > new[index_max_strace][1]['strace'] + ecart_max):
			index_max_strace = i

	best_index = [index_max_normal,index_max_ltrace,index_max_strace]
	usefull_param = remove_params(new)
	final_index = [best_index[i] for i in range(len(best_index)) if list(ref[0].keys())[i] in usefull_param]

	if(final_index==[]):final_index = best_index

	if(all(elem == final_index[0] for elem in final_index)):
		input_list = []
		for e in new[final_index[0]][0][0]:
			if(e.isdecimal()):
				input_list.append('stdin:digit')
			else:
				input_list.append('stdin:ascii')
		for e in new[final_index[0]][0][1]:
			if(e.isdecimal()):
				input_list.append('args:digit')
			else:
				input_list.append('args:ascii')
		return input_list
	else:
		return ask_endpoint()

def remove_params(result):
	normal = []
	ltrace = []
	strace = []

	for element in result:
		if(element[1]['normal'] not in normal):normal.append(element[1]['normal'])
		if(element[1]['ltrace'] not in ltrace):ltrace.append(element[1]['ltrace'])
		if(element[1]['strace'] not in strace):strace.append(element[1]['strace'])

	return [['normal','ltrace','strace'][i] for i in range(3) if len([normal,ltrace,strace][i]) > 1]

def ask_endpoint():
	logger(' [*] Waiting .. Unable to determine the endpoint (ex: [stdin,args,args]) . Enter it manually : ','warning',1,0)
	while(True):
		resp = input(' [>] ').strip()
		if(check_endpoint(resp)):
			print()
			return list(eval(resp))
		else:
			logger(' [-] Invalid Endpoint , please choose with \'args\' and \'stdin\' !','error',1,0)