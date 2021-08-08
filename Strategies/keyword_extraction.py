import json
import random
from Strategies.getFileType import FileType
import Strategies.csv_delimiter as csv_delimiter
from xmljson import badgerfish as bf
# https://pypi.org/project/xmljson/
from xml.etree.ElementTree import Element, tostring, fromstring
import re
from exif import Image
# https://pypi.org/project/exif/
from PyPDF2 import PdfFileReader, PdfFileWriter
# https://pypi.org/project/PyPDF2/
from makeelf.elf import *
# https://github.com/v3l0c1r4pt0r/makeelf
import os

RUN_COUNT = 0

def keyword_extract(data, delimiter):
    dictionary = []
    file_data = []
    for line in data:
        dictionary += line.strip().split(delimiter)
        file_data += line.split(delimiter)

    return dictionary, file_data

def xmlfile_to_json(data_str):
    json_text = bf.data(fromstring(data_str))
    json_text = json.dumps(json_text)
    return json.loads(json_text)

# reference: https://www.geeksforgeeks.org/turning-a-dictionary-into-xml-in-python/
def json_dict_to_xml(dict):
    elem = Element('root')

    for key, val in dict.items():
        child = Element(key)
        child.text = str(val)
        elem.append(child)

    return tostring(elem).decode('utf-8')

def add_xml_prologue(data_str):
    # Use bad encoding that contains security vulns if read as html in browsers
    data = '<?xml version="1.0" encoding="JIS_C6226-1983"?>\n' + data_str
    return data

def xml_remove_closing_tags(data_str):
    new_str = re.sub('</.*?>', '', data_str)
    return new_str

def xml_format_str_insert(data_str):
    # print(data_str)
    new_str = re.sub('\"(.*?)\"', "'%n'", data_str)
    return new_str

def deeply_nested_xml_no_closing_brace():
    data_str = ""
    for i in range(0, 100):
        data_str += "\t"*i + "<a>\n"
    return data_str


def json_keyword_extract(data):
    return list(data.keys())

def json_mutate_input(data, dictionary, dict=False):
    random_keyword = dictionary[random.randint(0, len(dictionary)-1)]
    random_json_location = random.randint(0, len(list(data.keys()))-1)
    random_json_keyword = ""
    i = 0
    for key in data.keys():
        if i == random_json_location:
            random_json_keyword = key
        i += 1
    # while (random_keyword == random_json_keyword):
    #     random_json_location = random.randint(0, len(list(data.keys()))-1)
    #     i = 0
    #     for key in data.keys():
    #         if i == random_json_location:
    #             random_json_keyword = key;
    #         i += 1

    random_keyword_value = data[random_keyword]
    random_json_keyword_value = data[random_json_keyword]

    # replace random_json_keyword with random_keyword
    data.pop(random_keyword)
    if (random_keyword != random_json_keyword):
        data.pop(random_json_keyword)

    data[random_keyword] = random_json_keyword_value
    if (random_keyword != random_json_keyword):
        data[random_json_keyword] = random_keyword_value

    if dict == True:
        return data

    return json.dumps(data)

def csv_keyword_extract(data):
    # print(csv_delimiter.CSV_DELIMITER)
    return keyword_extract(data, csv_delimiter.CSV_DELIMITER)

def csv_mutate_input(data, dictionary):
    if (len(data) < 1 or len(dictionary) < 1):
        return ""
    random_keyword_index = random.randint(0, len(dictionary)-1)
    random_csv_keyword_index = random.randint(0, len(data)-1)

    # 1 in 4 runs don't do a random mutation
    global RUN_COUNT
    if (RUN_COUNT % 4 == 0  and len(dictionary) >= 2):
        random_keyword_index = 1

    if (len(data) == 1):
        print(data, dictionary)
        data[0] = dictionary[random_keyword_index]

    words_to_replace = random.randint(0, len(data) -1)
    for i in range(0, words_to_replace):
        if ("\n" in data[random_csv_keyword_index]):
            data[random_csv_keyword_index] = dictionary[random_keyword_index] + "\n"
        else:
            data[random_csv_keyword_index] = dictionary[random_keyword_index]

        random_keyword_index = random.randint(0, len(dictionary)-1)
        random_csv_keyword_index = random.randint(0, len(data)-1)

    new_output = ""
    for word in data:
        if (new_output != "" and new_output[-1] == "\n") or new_output == "":
            new_output += word
        else:
            new_output += ("," + word)
    return new_output

# def jpegMutateInput(file, dictionary):
#     # open image 

def keyword_fuzzing(input, type = None, mutations = None, output_file = None):
    global RUN_COUNT
    mutation_str = mutations
    if mutations is None:
        mutation_str = "random"
    # print("Fuzzing file:", input, "with type", type, "Number of keyword swaps:", mutation_str, "\n")
    if (type == FileType.pdf or type == FileType.elf or type == FileType.jpeg):
        file = open(input, 'rb')
    else:
        file = open(input, 'r')
    fuzzed_output = ""
    if type == FileType.json:
        data = json.load(file)
        dictionary = json_keyword_extract(data)
        # dictionary += ["%n"]
        fuzzed_output = json_mutate_input(data, dictionary)
    elif type == FileType.csv:
        dictionary, file_data = csv_keyword_extract(file)
        # dictionary += ["%n"]
        fuzzed_output = csv_mutate_input(file_data, dictionary)
    elif type == FileType.elf:
        # Need to a file to save in if we want a modified elf
        if (output_file == None):
            fuzzed_output = ""
        else:
            # Mutate elf header info such to craft bad ELF files
            file.close()
            elf = ELF.from_file(input)

            # get headers
            elf = elf.Elf
            elf.append_section('BAD SECTION', "???%n%n%n", 0xdeadbeaf)
            # args: section_id, addr, mem_size. GIVE invalid mem_size and addr
            elf.append_segment(0, 0xdeadbeaf, -100000)
            new_elf = os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
            os.write(new_elf, bytes(elf))
            os.close(new_elf)

    elif type == FileType.pdf:
        # Need to a file to save in if we want a modified pdf
        if (output_file == None):
            fuzzed_output = ""
        else:
            # read metadata extract out keywords 
            pdf = PdfFileReader(file)
            pdf_info = pdf.getDocumentInfo()
            pdf_writer = PdfFileWriter()
            dictionary = []
            if '/Keywords' in pdf_info:
                dictionary = pdf_info['/Keywords']
            # modify metadata
            if (RUN_COUNT % 4 == 0):
                pdf_info.title = "%n%n%n"
                pdf_info.author = dictionary[random.randint(0, len(dictionary)-1)]
                pdf_info.creator = dictionary[random.randint(0, len(dictionary)-1)]
            else:
                pdf_writer.addPage(pdf_info.getPage(0))
                pdf_writer.addMetadata({"secret": "%n%n%n%n%n"})
                pdf_writer.insertBlankPage(100, 100, 1);
                pdf_writer.insertBlankPage(100, 100, 2);
                pdf_writer.insertBlankPage(100, 100, 3);
                with open(output_file, "wb") as new_pdf:
                        pdf_writer.write(new_pdf)

    elif type == FileType.xml:
        data_str = file.read()
        # convert xml to json
        json_dict = xmlfile_to_json(data_str)
        # use json mutation plus custom dictionary
        dictionary = json_keyword_extract(json_dict)
        # dictionary += ["%n"]
        fuzzed_output_dict = json_mutate_input(json_dict, dictionary, dict=True) 
        # convert json back to xml
        fuzzed_output = json_dict_to_xml(fuzzed_output_dict)
        if (RUN_COUNT % 4 == 0):
            fuzzed_output = xml_remove_closing_tags(fuzzed_output)
            fuzzed_output += deeply_nested_xml_no_closing_brace()
        elif (RUN_COUNT % 4 == 1):
            # add weird xml prologue
            fuzzed_output = add_xml_prologue(fuzzed_output)
        elif (RUN_COUNT % 4 == 2):
            fuzzed_output = xml_format_str_insert(data_str)
    elif type == FileType.plaintext:
        dictionary, file_data = keyword_extract(file, " ")
        # add in special words into dictionary
        dictionary += ["longlonglongword", "%n","Admin", "admin", "ADMIN", "password", "sudo"]
        # replace words with same strategy as csv
        fuzzed_output = csv_mutate_input(file_data, dictionary)
        # print(fuzzed_output)
    elif type == FileType.jpeg:
        # Need to a file to save in if we want a modified jpeg
        if (output_file != None):
            fuzzed_output = ""
        else:
            # JPEGS don't really have keywords BUT we can 
            # modify metadata info if it exits 
            jpeg_img = Image(file)
            if (jpeg_img.has_exif):
                if (RUN_COUNT % 4 == 0):
                    jpeg_img.delete_all()
                else:
                    try:
                        for key in dir(jpeg_img):
                            jpeg_img.set(key, -1)
                    except:
                        print("Keyword extraction: JPEG metadata update failed")
                with open(output_file, "wb") as new_img:
                        new_img.write(jpeg_img.get_file())
    else:
        # print("Type not supported")
        for line in file:
            fuzzed_output += line
    file.close()
    RUN_COUNT =  RUN_COUNT + 1
    if (output_file != None and (type != FileType.elf  or type != FileType.pdf or type != FileType.jpeg)):
        output = open(output_file, "w")
        output.write(fuzzed_output)
        output.close()
    return fuzzed_output
