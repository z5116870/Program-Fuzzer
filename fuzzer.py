import sys
from Strategies.ints import file_replace_one
from Strategies.flipper import bit_flipper, byte_flipper, special_bytes_flipper
from Strategies.repeatedParts import repeatedParts
from Strategies.arithmetic import arithmetic
from Strategies.keyword_extraction import keyword_fuzzing
from Strategies.getFileType import FileType, getFileType
import time
from subprocess import Popen, PIPE
import signal
import os
from enum import Enum
from test import infLoop
INF_LOOP = 0
inFile = 'input.txt'

class StrategyType(Enum):
    BITFLIP = 0
    BYTEFLIP = 1
    SPECIALBYTEFLIPS = 2
    KNOWNINTS = 3
    REPEATEDPARTS = 4
    KEYWORDEXTRACTION = 5
    ARITHMETIC = 6
    COVERAGEBASED = 7

seen_errors = {}
strategies_used = {}
payload_files = {}

def time_out_handler(signum, frame):
    print("Timing out, program ran for over 5 minutes")
    raise TimeoutError()

def create_crash_file(data, num):
    f = open("bad.txt", "wb+")
    if not isinstance(data, bytearray) and not isinstance(data, bytes):
        data = bytes(data, 'utf-8')
    f.write(data)
    f.close()

def runFuzzedInput(text, binary, num, all_errors, strat):
    # Coverage-based approach for hanging/infinite loops
    # Run trace process to check for hang/infinite loop
    trace = Popen(['strace ' + binary + '<' + inFile], shell=True, stdout = open(os.devnull, 'wb'), stderr = PIPE)
    isOK = infLoop(trace.stderr)
    if(isOK != 1):
        if(not isOK in seen_errors):
            error = 'Infinite Loop Detected (coverage)'
            print("Found bad input error:", error, "\nProcess exited with code:", isOK)
            create_crash_file(text, num)
            seen_errors[isOK] = error;
            strategies_used[isOK] = strat.name
            payload_files[isOK] = "bad" + str(num) + ".txt"
            return num + 1, all_errors + 1
        return num, all_errors
    # If no crash, run program
    proc = Popen([binary], shell=True, stdin = PIPE, stdout = PIPE, stderr = PIPE)
    if not isinstance(text, bytearray):
        text = bytes(text, 'utf-8')

    # Timeout approach for hanging/infinte loops
    try:
        _, error = proc.communicate(text, timeout=0.1)
        if error and proc.returncode != 0:
            all_errors += 1;
            if not proc.returncode in seen_errors:
                print("Found bad input error:", error, "\nProcess exited with code:", proc.returncode)
                create_crash_file(text, num)
                seen_errors[proc.returncode] = error;
                strategies_used[proc.returncode] = strat.name
                payload_files[proc.returncode] = "bad" + str(num) + ".txt"
                return num + 1, all_errors
        return num, all_errors
    except:
        if(not 1337 in seen_errors):
            error = 'Infinite Loop Detected (timeout)'
            print("Found bad input error:", error, "\nProcess exited with code:", isOK)
            create_crash_file(text, num)
            seen_errors[isOK] = error;
            strategies_used[isOK] = strat.name
            payload_files[isOK] = "bad" + str(num) + ".txt"
            return num + 1, all_errors
        return num, all_errors

def print_errors_stats(numErrors, all_errors, start_time):
    print("\n#### Fuzzing completed ####\n")
    print("Total runtime:", str(time.time() - start_time), "seconds")
    print("Total crashes found:", all_errors)
    print("Total unique crashes:", numErrors)
    print("Crashes found:")
    for key in seen_errors.keys():
        print("\tExit code:", key)
        print("\t\tStderr:", seen_errors[key])
        print("\t\tStrategy Used:", strategies_used[key])
        print("\t\tPayload in file:", payload_files[key])

if __name__ == "__main__":
    start_time = time.time()
    signal.signal(signal.SIGALRM, time_out_handler)
    signal.alarm(300)

    args = len(sys.argv)
    if (args < 3):
        print("Usage: ./fuzzer <binary> <input_file>")
    else:
        binary = sys.argv[1]
        filename = sys.argv[2]

        filetype = getFileType(filename)

        with open(filename, errors='ignore') as file:
            f = file.read()
        # inp = open(inFile, 'wb')
        numErrors = 0
        all_errors = 0
        # for each strategy run each fuzzing strategy 5 times
        for i in range(0, 5):
            fuzzing_data = keyword_fuzzing(filename, filetype, inFile)
            numErrors, all_errors = runFuzzedInput(fuzzing_data, binary, numErrors, all_errors, StrategyType.KEYWORDEXTRACTION)

        for i in range(0, 1000):
            fuzzing_data = bit_flipper(bytearray(f, 'utf-8'))
            inp = open(inFile, 'w+b')
            inp.write(fuzzing_data)
            numErrors, all_errors = runFuzzedInput(fuzzing_data, binary, numErrors, all_errors, StrategyType.BITFLIP)

        for i in range(0, 1000):
            fuzzing_data = byte_flipper(bytearray(f, 'utf-8'))
            inp = open(inFile, 'w+b')
            inp.write(fuzzing_data)
            numErrors, all_errors = runFuzzedInput(fuzzing_data, binary, numErrors, all_errors, StrategyType.BYTEFLIP)

        for i in range(0, 1000):
            fuzzing_data = special_bytes_flipper(bytearray(f, 'utf-8'))
            inp = open(inFile, 'w+b')
            inp.write(fuzzing_data)
            numErrors, all_errors = runFuzzedInput(fuzzing_data, binary, numErrors, all_errors, StrategyType.SPECIALBYTEFLIPS)

        # Check for known ints
        payload = file_replace_one(filename)
        for line in payload:
            inp = open(inFile, 'w')
            inp.write(line)
            numErrors, all_errors = runFuzzedInput(line, binary, numErrors, all_errors, StrategyType.KNOWNINTS)

        # Check for repeated part fuzzing
        payloads = repeatedParts(filename, filetype)
        for payload in payloads:
            inp = open(inFile, 'w')
            inp.write(line)
            numErrors, all_errors = runFuzzedInput(payload, binary, numErrors, all_errors, StrategyType.REPEATEDPARTS)

	# Check for arithmetic fuzzing
        payloads = arithmetic(filename, filetype)
        for payload in payloads:
            inp = open(inFile, 'w')
            inp.write(line)
            numErrors, all_errors = runFuzzedInput(payload, binary, numErrors, all_errors, StrategyType.ARITHMETIC)


        signal.alarm(0)

        print_errors_stats(numErrors, all_errors, start_time)
