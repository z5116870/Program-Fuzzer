import sys
from pwn import *
import json
import imghdr
import pipe
import subprocess
import os
import re
from getFileType import FileType

# JSON
'''
if(inputtype == TYPE_JSON):
	payload += '{'
	# Repeat first key/val pair
	with open(testInput) as f:
		text = f.read()
		res = 0
		for i in range(0, len(text)):
			if text[i] == ',':
				res = i + 1
				break
		# add the repeat
		payload += text[1:res] * 2
		# put the rest of the payload
		payload += text[res:]
	print(payload)
'''
# CSV
def repeatedParts(inputtype, testInput):
	# Fuzz depending on input type
	payload = ''
	val = 0
	badstr = []
	badpload = []
	codes = []
	crashes = 0
	if(inputtype == FileType.csv or inputtype == FileType.json):
		with open(testInput) as f:
			text = f.read()

			# Header stays intact
			i = 1
			while i < len(text):
				for x in range(1, len(text) - i):
					string = text[i:i+x]
					payload += text[0:i] + string*14 + text[i:]
					print(payload)
					retCode = runFuzzedInput(payload, binary)
					if(retCode != 0):
						crashes += 1
						val = 1337
						badstr.append(string)
						badpload.append(payload)
						codes.append(retCode)
					payload = ''
				i += 1

		print("---STATS---")
		print("CRASHES: ", crashes)
		print("CAUGHT REPEATED STRINGS:")
		i = 0
		x = 0
		for string in badstr:
			print(i, ': ', string)
			i += 1
		print("CAUGHT PAYLOADS:")
		for pload in badpload:
			print(x,': ', pload)
			x += 1

		# print only unique codes
		u = []
		for i in codes:
			if i not in u:
				u.append(i)
		print("CAUGHT CODES: ", u)
