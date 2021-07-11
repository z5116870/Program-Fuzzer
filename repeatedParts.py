import sys
from pwn import *
import json
import imghdr
import pipe
import subprocess
import os
import re

# Define input types
TYPE_JPEG = 0
TYPE_CSV = 1
TYPE_JSON = 2
TYPE_XML = 3
TYPE_PLAIN_TEXT = 4
global inputtype

def setInputType(x):
	global inputtype 
	inputtype = x

def r(p):
	log.info(p.recvS(timeout=0.5))

def s(p, a):
	p.sendline(a)
	log.warn(str(a))

# Check for input types
def checkInput(testInput):
	if(checkJPEG(testInput)):
		print("input type: JPEG")
		setInputType(TYPE_JPEG)
		return
	
	if(checkCSV(testInput)):
		print("input type: CSV")
		setInputType(TYPE_CSV)
		return

	# rest of files can be read using open
	with open(testInput) as f:
		text = f.read()
		print(len(text))
		print(text)

	if(checkJSON(text)):
		print("input type: JSON")
		setInputType(TYPE_JSON)
		return

	if(checkXML(text)):
		print("input type: XML")
		setInputType(TYPE_XML)
		return
	
	print("input type: plain text")
	setInputType(TYPE_PLAIN_TEXT)
	return

# JSON
def checkJSON(text):
	try:
		obj = json.loads(text)
	except ValueError as e:
		return 0
	return 1

# XML
def checkXML(text):
	if(text[0] != '<'):
		return 0
	return 1

# JPEG

def checkJPEG(testInput):
	if(imghdr.what(testInput) == 'jpeg'):
		return 1
	return 0

# CSV
def checkCSV(testInput):
	separators = [',', ' ', ':', ';']
	countSeparators = []
	x = 0
	i = 1
	with open(testInput) as f:
		lines = f.readlines()
		for separator in separators: 
			for line in lines:
				# count amount of separators per line
				countSeparators.append(line.count(separator))
				i += 1
			print(countSeparators)
			# check that the amount of separators per line is equal
			result = all(element == countSeparators[0] for element in countSeparators)
			if(result and countSeparators != []):
				# if so, and elements non-zero, then type is XML
				element = countSeparators[0]
				if(element != 0):
					return 1
			# if not, clear the list, increment separator and run again
			countSeparators.clear()
			print(separator)
	return 0

def runFuzzedInput(text, binary):
	proc = subprocess.Popen([binary], shell=True, stdin = PIPE, stdout = PIPE, stderr = PIPE)
	output, error = proc.communicate(bytes(payload, 'utf-8')) 
	return(proc.returncode)
# get binary and input
binary = sys.argv[1]
testInput = sys.argv[2]
p = process(binary)
print("running: " + binary)
		
# Get input type
checkInput(testInput)
print(inputtype)

# Fuzz depending on input type
payload = ''
with open(testInput) as f:
	text = f.read()
# JSON
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

# CSV
val = 0
badstr = []
badpload = []
codes = []
crashes = 0
if(inputtype == TYPE_CSV):
	with open(testInput) as f:
		text = f.read()

		# Header stays intact
		i = 24
		while i < len(text) - 10:
			for x in range(1, len(text)):
				string = text[i:i+x]
				payload += text[0:i] + string*60 + text[i:]
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
# print("CAUGHT STRINGS: ", badstr)
# print("CAUGHT PAYLOADS: ", badpload)

# print only unique codes
u = []
for i in codes:
	if i not in u:
		u.append(i)
print("CAUGHT CODES: ", u)
