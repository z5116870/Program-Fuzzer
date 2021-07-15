from enum import Enum
import json
import imghdr

class FileType(Enum):
    plaintext = 0
    json = 1
    xml = 2
    csv = 3
    jpeg = 4
    elf = 5
    pdf = 6

# Check for input types
def getFileType(testInput):
	if(checkJPEG(testInput)):
		return FileType.jpeg

	if(checkCSV(testInput)):
		return FileType.csv

	# rest of files can be read using open
	with open(testInput) as f:
		text = f.read()
		# print(len(text))
		# print(text)

	if(checkJSON(text)):
		return FileType.json

	if(checkXML(text)):
		return FileType.xml

	return FileType.plaintext

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
			countSeparators = []
	return 0