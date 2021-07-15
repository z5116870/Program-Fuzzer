import sys
import re
from subprocess import Popen, PIPE

#replaces all numbers in a file to a desired number
def replace_all(file, int):
    payload = ""
    with open(file, 'r') as f:
        for line in f.readlines():
            new_string = re.sub("[-]?\\d+", str(int), line)
            payload += new_string
    return payload

def file_replace_all(file):
    payload = replace_all(file, 0)
    payload += replace_all(file, -1)
    payload += replace_all(file, 99999)
    payload += replace_all(file, -99999)
    payload += replace_all(file, -1.5)
    payload += replace_all(file, 1.5)

    return payload.strip()


#replaces one number at a time with desired number
def replace_one(file, replace):
    with open(file, 'r') as f:
        wordlist = []
        nums = []
        for line in f.readlines():
            wordlist.append(line)
            nums += re.findall("[-]?\\d+", line)

    payload = ""
    for number in nums:
        for i in range(len(wordlist)):
            if number in wordlist[i]:
                temp = wordlist[i].replace(number,str(replace))
                for x in range(0, i):
                    if x == i:
                        break
                    payload += wordlist[x]
                
                payload += temp

                if (i+1) > len(wordlist):
                    break
                else:
                    for y in range(i+1, len(wordlist)):
                        payload += wordlist[y]
    return payload

def file_replace_one(file):
    payload = []
    payload.append(replace_one(file, 0))
    payload.append(replace_one(file, -1))
    payload.append(replace_one(file, 99999))
    payload.append(replace_one(file, -99999))
    payload.append(replace_one(file, 1.5))
    payload.append(replace_one(file, -1.5))

    return payload

if __name__ == "__main__":
    file = sys.argv[1]

    payload = file_replace_one(file)
    binary = "./" + file[:-4]

    for line in payload:
        proc = Popen([binary], shell=True, stdin = PIPE, stdout = PIPE, stderr = PIPE)
        output, error = proc.communicate(bytes(line,'utf-8'))
        if(proc.returncode != 0):
            print(line)
            print(proc.returncode)
            print(error)