import sys
from pwn import *
import json
import imghdr

# Define input types
TYPE_JPEG = 0
TYPE_CSV = 1
TYPE_JSON = 2
TYPE_XML = 3
TYPE_PLAIN_TEXT = 4
global inputtype

def setInputType(x):
	print("yalla")
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

# get binary and input
binary = sys.argv[1]
testInput = sys.argv[2]
p = process(binary)
print("running: " + binary)
		
# Get input type
checkInput(testInput)
print(inputtype)

# Fuzz depending on input type
# JSON
if(inputtype == TYPE_JSON):
	# read from " to : to get key
	with open(testInput) as f:
		lines = f.readlines()
		for line in lines:
			# get the first key
			c1 = '"'
			c2 = ':'
			print(line[line.find(c1):line.find(c2)])
p.interactive()

