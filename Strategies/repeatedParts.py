# from pwn import *
import sys
from subprocess import Popen, PIPE
from getFileType import FileType, getFileType
from bs4 import BeautifulSoup as BS
import re

def runFuzzedInput(text, binary):
	proc = Popen([binary], shell=True, stdin = PIPE, stdout = PIPE, stderr = PIPE)
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
	with open(testInput) as f:
		text = f.read()
	if(inputtype == FileType.csv or inputtype == FileType.json):
			# Header stays intact
			i = 1
			while i < len(text):
				for x in range(1, len(text) - i):
					string = text[i:i+x]
					payload += text[0:i] + string*14 + text[i:]
					payloads.append(payload)
					payload = ''
				i += 1

	if(inputtype == FileType.xml):
		with open(testInput) as f:
			soup = BS(f, features='lxml')
		# First, find all the tags in the xml		
		tags = []
		for tag in soup.find_all(True):
			print(tag.name)
			tags.append(tag.name)

		# Method 1, repeat everything between the tags
		for tag in tags:
			text = str(soup)
			x = text.find(tag)

			# Get the entire tag and contents
			xmlstr = str(soup.find(tag))		

			# add the repeated text just after the tag
			y = len(xmlstr)
			index = x + y
			payload = text[:index] + xmlstr*2 + text[index:]
			
			# add it to the payloads
			print(payload)
			payloads.append(payload)
			payload = ''

		# Method 2, repeat the tag text, within the tag itself
		for tag in tags:
			tagtext = soup.find(tag).text
			print('-------')
			print(tagtext)
	if(inputtype == FileType.plaintext):
		payload = text*10000
		payloads.append(payload)
	return payloads

def run(binary, testInput):
	print("making fuzzed inputs...")
	inputtype = getFileType(testInput)
	payloads = repeatedParts(testInput, inputtype)
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

run(sys.argv[1], sys.argv[2])
