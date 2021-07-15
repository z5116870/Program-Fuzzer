import random
from subprocess import Popen, PIPE
import os
import time
import sys

bytes_array = [1, 2, 4, 8, 16, 32, 64, 128]

def bit_flipper(data):

    length_of_data = len(data)
    index_to_flip = random.choice(range(0,length_of_data))
    mask = random.choice(bytes_array)
    data[index_to_flip] = data[index_to_flip] ^ mask

    return data

def byte_flipper(data, flips = 1):

    length_of_data = len(data)
    index_to_flip = random.choice(range(0,length_of_data))
    mask = random.choice(bytes_array)
    data[index_to_flip] = data[index_to_flip] ^ random.getrandbits(8)

    return data

def special_bytes_flipper(data):
    length_of_data = len(data)
    indexes = range(0, length_of_data)
    index_to_flip = random.choice(indexes)
    extreme_bytes = random.choice([[0xFF, 0xFF, 0xFF, 0xFF], [0x00, 0x00, 0x00, 0x00], [0x00, 0x00, 0x00, 0x80], [0xFF, 0xFF, 0xFF, 0x7F], [0x00, 0x00, 0x00, 0x40], [0x00, 0x00], 
                 [0xFF, 0xFF], [0xFF], [0x7F], [0x00]])

    offset = 0
    for i in range(len(extreme_bytes)):
        if (index_to_flip + i >= length_of_data):
            return data
        data[index_to_flip + i] = extreme_bytes[i]
        offset += 1
    return data

methods = [1,2,3]

def create_crash_file(data):
    f = open("bad.txt", "wb+")
    f.write(data)
    f.close()

def run(f):
    # while True:
    start_time = time.time()
    while time.time() - start_time < 180:
    # for i in range(5):
        try:
            data = bytearray(f)
            method = random.choice(methods)
            if(method == 0):
                flipped = bit_flipper(data)
            elif(method == 1):
                flipped = byte_flipper(data)
            else:
                flipped = special_bytes_flipper(data)

            # print(flipped)
            flipped_str = str(flipped,'utf-8')
            proc = Popen([sys.argv[2]], shell=True, stdin = PIPE, stdout = PIPE, stderr = PIPE)
            out,err = proc.communicate(bytes(flipped_str,'utf-8'))
            if(err):
                print("CRASH *****************************************************", err)
                print(method)
                create_crash_file(flipped)
                # print(out)
                break
        except:
            pass

if __name__ == "__main__":
    with open(sys.argv[1], 'rb') as file:
        f = file.read()
    run(f)