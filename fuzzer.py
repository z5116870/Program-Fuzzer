import sys
from Strategies.ints import file_replace_one
from Strategies.flipper import bit_flipper, byte_flipper, special_bytes_flipper
from Strategies.repeatedParts import repeatedParts
from Strategies.keyword_extraction import keyword_fuzzing
from Strategies.getFileType import FileType, getFileType
import time
from subprocess import Popen, PIPE
import signal

seen_errors = {}
def time_out_handler(signum, frame):
    print("Timing out, program ran for over 5 minutes")
    raise TimeoutError()

def create_crash_file(data, num):
    f = open("bad" + str(num) + ".txt", "wb+")
    if not isinstance(data, bytearray) and not isinstance(data, bytes):
        data = bytes(data, 'utf-8')
    f.write(data)
    f.close()

def runFuzzedInput(text, binary, num):
    proc = Popen([binary], shell=True, stdin = PIPE, stdout = PIPE, stderr = PIPE)
    if not isinstance(text, bytearray):
        text = bytes(text, 'utf-8')
    output, error = proc.communicate(text)
    if error and proc.returncode != 0:
        if not proc.returncode in seen_errors:
            print("Found bad input error:", error, "\nProcess exited with code:", proc.returncode)
            create_crash_file(text, num)
            seen_errors[proc.returncode] = error;
            return num + 1
    return num

if __name__ == "__main__":
    signal.signal(signal.SIGALARM, time_out_handler)
    signal.alarm(300)

    args = len(sys.argv)
    if (args < 3):
        print("Usage: ./fuzzer <binary> <input_file>")
    else:
        binary = sys.argv[1]
        filename = sys.argv[2]

        filetype = getFileType(filename)

        with open(filename) as file:
            f = file.read()

        numErrors = 0
        # for each strategy run each fuzzing strategy 5 times
        for i in range(0, 5):
            fuzzing_data = keyword_fuzzing(filename, filetype)
            numErrors = runFuzzedInput(fuzzing_data, binary, numErrors)

        for i in range(0, 5):
            fuzzing_data = bit_flipper(bytearray(f, 'utf-8'))
            numErrors = runFuzzedInput(fuzzing_data, binary, numErrors)

        for i in range(0, 5):
            fuzzing_data = byte_flipper(bytearray(f, 'utf-8'))
            numErrors = runFuzzedInput(fuzzing_data, binary, numErrors)
        
        for i in range(0, 5):
            fuzzing_data = special_bytes_flipper(bytearray(f, 'utf-8'))
            numErrors = runFuzzedInput(fuzzing_data, binary, numErrors)

        # Check for known ints
        payload = file_replace_one(filename)
        for line in payload:
            numErrors = runFuzzedInput(line, binary, numErrors)

        # Check for repeated part fuzzing 
        payloads = repeatedParts(filename, filetype)
        print(len(payloads))
        for payload in payloads:
            print(payload)
            numErrors = runFuzzedInput(payload, binary, numErrors)
        
        signal.alarm(0)



