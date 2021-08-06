# DETECTING INFINITE LOOPS/HANGS
from subprocess import Popen, PIPE
import signal
import time
import os
def time_out_handler(signum, frame):
    print("Infinite loop detected. Exiting program.")
    exit()

binary = './Test/hang'
testInput = 'Test/hang.txt'
trace = Popen(['strace ' + binary + '<' + testInput], shell=True, stdout = open(os.devnull, 'wb'), stderr = PIPE)
print('Running trace, pid: ', trace.pid)

# TIMEOUT APPROACH
signal.signal(signal.SIGALRM, time_out_handler)
signal.alarm(10)

with open(testInput) as f:
	text = f.read()
if not isinstance(text, bytearray):
    text = bytes(text, 'utf-8')

# COVERAGE BASED
with open('out.txt', 'w') as f:
	syscalls = []
	start = time.time()
	while trace.stderr.readable():
		line = trace.stderr.readline()
		if not line:
			break
		# Add to list of syscalls 
		syscalls.append(line)

		# write to file
		f.write(str(line))
		
		# After 2 seconds has passed if strace still executing, 	
		# Check to see if pattern can be found from last found syscalls
		if(time.time() - start > 1):	
			syscall = syscalls[-1] # last element
			print(syscalls)
			# Get a list of indexes that match the last recieved element
			index_pos_list = []
			index_pos = 0
			while True:
				try:
					# Search for item in list from indexPos to the end of list
					index_pos = syscalls.index(syscall, index_pos)
					# Add the index position in list
					index_pos_list.append(index_pos)
					index_pos += 1
				except ValueError:
					start = time.time() # return to while loop for another 2 seconds
					print('All unique syscalls. Returning to trace...')
					print(syscall)
					break
			print('list', index_pos_list)
			
			# With this list of indexes, we can check for syscall loops	
			for el in range(len(index_pos_list) - 1):
				prev = index_pos_list[el]
				next = index_pos_list[el + 1] 

				i = 0
				check1 = syscalls[prev + i]
				check2 = syscalls[next + i]

				# If we find 10 loops in a row, probable infinite loop	
				loops = 0
				while(check1 ==  check2):
					if(loops > 10):
						print("Infinite loop detected. Exiting program.")
						exit()
					i += 1
					# If we loop back to the beginning 
					print(prev, next, i)
					if(prev + i == next):
						prev = next
						next = next + i
						loops += 1
						i = 0
						continue
					check1 = syscalls[prev + i]
					check2 = syscalls[next + i]

