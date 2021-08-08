# from pwn import *
import sys
from subprocess import Popen, PIPE
from Strategies.getFileType import FileType, getFileType
from bs4 import BeautifulSoup as BS
from PIL import Image, ExifTags
import base64
import os,binascii
import PyPDF2
import random
import string

randString = string.ascii_letters + string.punctuation
PDF_KEYWORDS = ['/CreationDate', '/Creator', '/Keywords', '/Producer', '/Title']

def runFuzzedInput(text, binary, inputtype):
	proc = Popen([binary], shell=True, stdin = PIPE, stdout = PIPE, stderr = PIPE)
	if(inputtype == FileType.jpeg or inputtype == FileType.pdf):
		try:
			output, error = proc.communicate(text.tobytes())
		except:
			output, error = proc.communicate(text)
	else:
		output, error = proc.communicate(bytes(text, 'utf-8'))
	return(proc.returncode, error)

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

	if(inputtype == FileType.xml):
		with open(testInput) as f:
			soup = BS(f, features='lxml')
		# First, find all the tags in the xml
		tags = []
		for tag in soup.find_all(True):
			# print(tag.name)
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
			# print(payload)
			payloads.append(payload)
			payload = ''

		# Method 2, repeat the tag text, within the tag itself
		for tag in tags:
			tagtext = soup.find(tag).text
			# print('-------')
			# print(tagtext)
	if(inputtype == FileType.plaintext):
		payload = text*10000
		payloads.append(payload)

	if(inputtype == FileType.jpeg):
		# Using Pillow (PIL)
		img = Image.open(testInput)
		# print(img.info)
		keys = []
		values = []
		for k, v in img.info.items():
			#print(k, ':', v)
			keys.append(k)
			values.append(v)
		# Repeat each key, value
		for i in range(len(keys)):
			for j in range(10):
				img.info.__setitem__(keys[i]*j, values[i]*j*2)
				#print(img.info)
				payloads.append(img)

		# Using b64 method
		with open(testInput, "rb") as f:
			b64str = base64.b64encode(f.read())
		i = 0
		for c in str(b64str):
			if c == '/':
				# generate random 8 byte hex number and insert
				# after every slash
				rpt = binascii.b2a_hex(os.urandom(8))
				payload = b64str[:i] + rpt + b64str[i:]
				# Assert b64 string is 4 byte aligned
				if(len(payload) % 4 != 0):
					payload += b'='
				payload = base64.b64decode(b"data:image/jpeg;base64," + payload)
				payloads.append(payload)
			i += 1
		# print(i)
		# print(b64str)

	if(inputtype == FileType.pdf):
		# read input as PDF file
		pdf_writer = PyPDF2.PdfFileWriter()
		mDict = {}
		with open(testInput, 'rb') as f:
			pdf = PyPDF2.PdfFileReader(f)
			# get dictionary of doc info values
			info = pdf.getDocumentInfo()

		for i in range(100):
			# repeat metadata
			for k, v in info.items():
				# print(k, ':', v)
				# repeat existing keywords
				mDict.__setitem__(k, v*5)

			# repeat random data
			for kword in PDF_KEYWORDS:
				if kword not in mDict:
					v = ''.join(random.choice(randString) for x in range(8))
					mDict.__setitem__(kword, v*5)
			# print(mDict)
			pdf_writer.addMetadata(mDict)
			with open('out.pdf', "wb") as f:
				pdf_writer.write(f)

			with open('out.pdf', 'rb') as f:
				payload = f.read()
			payloads.append(payload)

		# print(payload)
	return payloads

def run(binary, testInput):
	print("making fuzzed inputs...")
	inputtype = getFileType(testInput)
	payloads = repeatedParts(testInput, inputtype)
	print("Done.")
	badpload = []
	codes = []
	errors = []
	crashes = 0
	# p = process(binary)
	print("running fuzzed inputs...: " + binary)
	for payload in payloads:
		retCode, error = runFuzzedInput(payload, binary, inputtype)
		if(retCode != 0):
			crashes += 1
			badpload.append(payload)
			codes.append(retCode)
			errors.append(error)
	printStats(crashes, badpload, codes, errors)

def printStats(crashes, badpload, codes, errors):
	print("---STATS---")
	print("CRASHES: ", crashes)
	print("CAUGHT PAYLOADS:")
	i = 0
	x = 0
	#for pload in badpload:
		#print(x,': ', pload)
		#x += 1

	# print only unique codes
	u = []
	for i in codes:
		if i not in u:
			u.append(i)
	print("CAUGHT CODES: ", u)
	print("CAUGHT ERRORS: ", errors)
