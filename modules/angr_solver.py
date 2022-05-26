import angr
import claripy
import logging

from utils.logger import logger

logging.getLogger('angr').setLevel('ERROR')


def solver_angr(config,mode,mode_text):
	logger(' [+] Fuzzing using %s mode'%mode_text,'log',0,1)
	for input_len in range(1,30):
		logger(' 	[*] Fuzzing using input of lenght: %s'%input_len,'warning',0,1)

		proj = angr.Project(config['path_file'],main_opts = {'base_addr': 0x0},auto_load_libs = False)

		flag_chars = [claripy.BVS('flag_%i' % i, 8) for i in range(input_len)]
		inp = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')])
	
		st = proj.factory.full_init_state(args = [config['path_file'], inp],stdin=inp, add_options=mode)

		st.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

		if("ascii" in config['type_input'][0]):
			for byte in flag_chars:
				st.solver.add(byte >= b"\x20")
				st.solver.add(byte <= b"\x7e")
		else:
			for byte in flag_chars:
				st.solver.add(byte >= 48)
				st.solver.add(byte <= 57)

		format_flag = config['formatflag']
		if(format_flag != ''):
			for i in range(len(format_flag)):
				if(i < len(flag_chars)):
					st.solver.add(flag_chars[i] == bytes(format_flag[i],'utf-8'))

		sm = proj.factory.simulation_manager(st)

		sm.explore(find = config['win_word'], avoid = config['fail_word'])

		if len(sm.found) > 0:
			logger(" [+] Flag found: " + sm.found[0].posix.dumps(0).decode("utf-8"),'flag',1,0)
			logger(' [+] Bye Bye ! ','info',1,0)
			return True
		
	return False
	