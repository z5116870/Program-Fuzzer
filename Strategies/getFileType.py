from enum import Enum
import json
import imghdr
import magic
import csv
import Strategies.csv_delimiter as csv_delimiter

class FileType(Enum):
	plaintext = 0
	json = 1
	xml = 2
	csv = 3
	jpeg = 4
	elf = 5
	pdf = 6
	unhandled = 7

def customFileTypeCheck(filename):
	if(checkJPEG(filename)):
		return FileType.jpeg

	# rest of files can be read using open
	try:
		with open(filename) as f:
			text = f.read()
			# print(len(text))
			# print(text)
		# treat single digit input as plaintext
		if (text.isnumeric()):
			return FileType.plaintext

		if(checkJSON(text)):
			return FileType.json

		if(checkXML(text)):
			return FileType.xml

		if(csvSniffer(filename)):
			return FileType.csv
	except:
		return FileType.unhandled
	else:
		return FileType.plaintext

# Check for input types
def getFileType(filename):
	fileTypeStr = magic.from_file(filename)

	# For some reason my version of magic 
	# cant identify the difference between 
	# csv, plaintext and json so we need to 
	# check those manually
	if (fileTypeStr.startswith("ASCII")):
		return customFileTypeCheck(filename)
	elif (fileTypeStr.startswith("HTML")):
		return FileType.xml
	elif (fileTypeStr.startswith("ELF")):
		return FileType.elf
	elif (fileTypeStr.startswith("PDF")):
		return FileType.pdf
	elif (fileTypeStr.startswith("JPEG")):
		return FileType.jpeg
	else:
		return customFileTypeCheck(filename)

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
			# check that the amount of separators per line is equal
			result = all(element == countSeparators[0] for element in countSeparators)
			if(result and countSeparators != []):
				# if so, and elements non-zero, then type is XML
				element = countSeparators[0]
				if(element != 0):
					return 1
			# if not, clear the list, increment separator and run again
			countSeparators.clear()
	return 0

def csvSniffer(filename):
	lowercase = [chr(x) for x in range(ord('a'), ord('z') + 1)]
	uppercase = [chr(x) for x in range(ord('A'), ord('Z') + 1)]
	numbers = [chr(x) for x in range(ord('0'), ord('9')+1)]

	invalidDelimiters = lowercase + uppercase + numbers
	try:
		with open(filename) as f:
			dialect = csv.Sniffer().sniff(f.read(2048))
			if dialect.delimiter in invalidDelimiters:
				return 0
			else:
				csv_delimiter.init(dialect.delimiter)
				# csv_delimiter.CSV_DELIMETER = dialect.delimiter
				return 1
	except:
		return 0
	else:
		return 0