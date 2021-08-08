# DETECTING INFINITE LOOPS/HANGS
from subprocess import Popen, PIPE
import signal
import time
import os
timeout = 0

def infLoop(buf):
	# COVERAGE BASED
	with open('out.txt', 'w') as f:
		syscalls = []
		timeElapsed = time.time()
		while buf.readable() and not timeout:
			line = buf.readline()
			if not line or line == b'+++ exited with 0 +++\n':
				break
			# Add to list of syscalls
			syscalls.append(line)
			# After 2 seconds has passed if strace still executing,
			# Check to see if pattern can be found from last found syscalls
			if(time.time() - timeElapsed > 0.05):
				syscall = syscalls[-1] # last element
				#print('callin')
				timeElapsed = time.time()
				#print(syscalls)
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
						#print('All unique syscalls. Returning to trace...')
						#print(syscall)
						break
				#print('list', index_pos_list)

				# With this list of indexes, we can check for syscall loops
				for el in range(len(index_pos_list) - 1, -1, -1):
					# We dont need to check the actual syscalls
					# Check distance between each index. If a pattern can be found for > 10
					# Then it is an infinite loop. We start from the last element (most recently recieved)
					# and count back
					start = el
					posA = index_pos_list[start]
					if(start == 0):
						print('reached 0')
						return 1
					posB = index_pos_list[start - 1]
					dist = posA - posB
					loop = 0
					while posA - posB == dist:
						if(loop > 10):
							return 1337
						loop += 1
						start -= 1
						posA = index_pos_list[start]
						posB = index_pos_list[start - 1]
	return 1
