import sys
# from pwn import *
import json
import imghdr
import pipe
import subprocess
import os
import re
from getFileType import FileType

def runFuzzedInput(text, binary):
	proc = subprocess.Popen([binary], shell=True, stdin = PIPE, stdout = PIPE, stderr = PIPE)
	output, error = proc.communicate(bytes(text, 'utf-8'))
	return(proc.returncode)

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
def repeatedParts(testInput, inputtype):

	# Fuzz depending on input type
	payload = ''
	payloads = []
	if(inputtype == FileType.csv or inputtype == FileType.json):
		with open(testInput) as f:
			text = f.read()

			# Header stays intact
			i = 1
			while i < len(text):
				for x in range(1, len(text) - i):
					string = text[i:i+x]
					payload += text[0:i] + string*14 + text[i:]
					payloads.append(payload)
					payload = ''
				i += 1
	# Below line is my version of a harness, prints payloads that cause
	# errors while using repeated parts method.
	return payloads

def run(binary, testInput):
	print("making fuzzed inputs...")
	payloads = repeatedParts(testInput)
	print("Done.")
	badpload = []
	codes = []
	crashes = 0
	# p = process(binary)
	print("running fuzzed inputs...: " + binary)
	for payload in payloads:
		retCode = runFuzzedInput(payload, binary)
		if(retCode != 0):
			crashes += 1
			badpload.append(payload)
			codes.append(retCode)
	printStats(crashes, badpload, codes)

def printStats(crashes, badpload, codes):
	print("---STATS---")
	print("CRASHES: ", crashes)
	print("CAUGHT PAYLOADS:")
	i = 0
	x = 0
	for pload in badpload:
		print(x,': ', pload)
		x += 1

	# print only unique codes
	u = []
	for i in codes:
		if i not in u:
			u.append(i)
	print("CAUGHT CODES: ", u)
