import argparse
import base64
import os
import os.path
import random
import sys
import signal
import time
from f_list import breakpoint_addresses
from ptrace import debugger
from subprocess import Popen, PIPE
# from pwn import *
from Strategies.flipper import bit_flipper, byte_flipper, special_bytes_flipper
from Strategies.ints import file_replace_one
from Strategies.flipper import bit_flipper, byte_flipper, special_bytes_flipper
from Strategies.repeatedParts import repeatedParts
from Strategies.keyword_extraction import keyword_fuzzing
from Strategies.getFileType import FileType, getFileType
# from fuzz_with_coverage import fuzz



target_file = sys.argv[1]
input_file = sys.argv[2]
dummy_file = "mutated.txt"
crash_directory = "crashes/"

with open(input_file) as file:
  input_file_data = file.read()

crash_list = {}

fuzzstop = False

def key_interrupt(sig, frame):
  global fuzzstop
  print('Finishing fuzz job.')
  fuzzstop = True

class coverage_based_mutation:
    
    def __init__(self,org_input):
        self.input = org_input

        self.mutated_inputs = []
        self.cache          = []
        self.collection     = []
        self.current        = set()

    def __iter__(self):
        self.analyse_mutation()
        self.mutation_strategy()
        return self

    def __next__(self):
        if not self.mutated_inputs:

            self.analyse_mutation()
            self.mutation_strategy()
        # print(self.mutated_inputs)
        if(fuzzstop):
            raise StopIteration
        else:
            return self.mutated_inputs.pop()

    def analyse_mutation(self):
        print('------- Analysing mutation ------------------\t\t')
        for inp in self.input:
            self.cache.append((inp, []))
        # print(self.cache)
        # print('cache size: {:d} [core samples promoted]'.format(len(self.cache)))

        for data, current in self.collection:
            # print(current - self.current)
            if current - self.current:
                self.cache.append((data, current))

        print('cache size: {:d} [new breakpoints reached]'.format(len(self.cache)))

        if self.collection and len(self.cache) < 100:
          self.collection.sort(reverse = True, key = lambda x: len(x[1]))

          for _ in range(min(100-len(self.cache), len(self.collection))):
            # Exponential Distribution
            v = random.random() * random.random() * len(self.collection)

            self.cache.append(self.collection[int(v)])
            self.collection.pop(int(v))
        #   print("bACKFILL ",self.cache)
        #   print('cache size: {:d} [backfill from collection]'.format(len(self.cache)))
        print('----------- Finished analysis round ----------------\t\t')

        for _, item in self.collection:
            self.current |= item

        self.collection = []

    def mutation_strategy(self):
        while self.cache:
          item,_ = self.cache.pop()
          for _ in range(20):
            # print(item)
            self.mutated_inputs.append(coverage_based_mutation.mutate_inputs(item))

        # print(self.mutated_inputs)


    def update_collection(self, data, cvg = None):
        # print(cvg)
        # print(self.collection)
        self.collection.append((data, cvg))

    @staticmethod
    def mutate_inputs(item):

        inputt = item[:]
        # print(inputt)
        f = random.choice(range(0,6))
        if(f == 0):
          ss = bit_flipper(inputt)
          
        elif(f == 1):
          ss = byte_flipper(inputt)
        elif(f == 2):
          ss = special_bytes_flipper(inputt)
        elif(f == 3):
          ss = keyword_fuzzing(input_file, getFileType(input_file))
        elif(f == 4):
          payload = file_replace_one(input_file)
          if(payload):
            ss = payload[random.choice(range(0,len(payload)))]
        elif(f == 5):
          payload = repeatedParts(input_file, getFileType(input_file))
          if(payload):
            ss = payload[random.choice(range(0,len(payload)))]
          else:
            ss = bit_flipper(inputt)

        # print(ss)

        return ss

def save_crash_files():
    crash_directory = "crashes/"

    if not os.path.exists(crash_directory):
        os.mkdir(crash_directory)

    global crash_list

    for address, m_input in crash_list.items():
        file = 'crash_{}.txt'.format(hex(address))

        with open(os.path.join(crash_directory, file), 'wb+') as fh:
          fh.write(m_input)

dummy_file = "dummy.txt"

def fuzz(tracer, inputs, breakpoints, binary):
  # print("here")
    covered = set()

    try:
        os.mkfifo(dummy_file, mode=0o777)
    except FileExistsError:
        pass

    input_to_subprocess = os.open(dummy_file, os.O_RDONLY | os.O_NONBLOCK)
    connect_with_child = os.open(dummy_file, os.O_WRONLY)

    subproc = Popen([binary], stdout=open(os.devnull,'wb'), stdin= input_to_subprocess, stderr=PIPE, close_fds=True)

    os.close(input_to_subprocess)
    try:
      # print("written", inputs)
      os.write(connect_with_child, bytes(inputs,'utf-8'))
    except:
        return covered

    os.close(connect_with_child)
    os.unlink(dummy_file)

    pid = subproc.pid

    try:
        ptracer = tracer.addProcess(pid, False)
        if(breakpoints):
          for breakpoint in breakpoints:
            ptracer.createBreakpoint(int(breakpoint,16), size = 4)

        while True:
          ptracer.cont()
          current_event = tracer.waitProcessEvent()

          if current_event.signum == signal.SIGTRAP:
            instruction_pointer = ptracer.getInstrPointer()
            # print(hex(instruction_pointer))
            br = ptracer.findBreakpoint(instruction_pointer - 1).desinstall()
            ptracer.setInstrPointer(instruction_pointer - 1)
            covered.add(instruction_pointer - 1)

          elif current_event.signum == signal.SIGINT or isinstance(current_event, debugger.ProcessExit):
            ptracer.detach()
            break

          elif current_event.signum == signal.SIGSEGV:
            crash_address = ptracer.getInstrPointer() - 1
            print("SEGFAULT", hex(crash_address))
            crash_list[crash_address] = bytes(inputs, 'utf-8')
            ptracer.detach()
            break
          else:
            continue

        ptracer.detach()

        return covered

    except:
        return covered


def main():
    signal.signal(signal.SIGINT, key_interrupt)
    start_time = time.time()
    breakpoints = breakpoint_addresses(target_file)

  # corpus = get_corpus(input_file)
    ptracer = debugger.PtraceDebugger()

    initial_seed = os.urandom(24)
    
    random.seed(initial_seed)

    # global input_file_data

    mutations = coverage_based_mutation([input_file_data])
    # print(mutator)

    # # print("STEP 1")
    counter = 0
    
    for mutation in mutations:
        # break
        # print("SAMPLE ",mutation)
    # # save_file(sample)
        coverage = fuzz(ptracer, mutation, breakpoints, target_file)
        # print("TRACE", trace)
        mutations.update_collection(mutation, coverage)
        counter += 1

        print('#{:3d} Coverage {:.2f}%\r'.format(
            counter, (len(coverage)/len(breakpoints)) * 100), end='')

    # x = counter / (time.time()-start_time)
    # print('-> {:.0f} exec/sec'.format(x))
    print(f"Unique crashes: {len(crash_list)}")
    
    save_crash_files()

    ptracer.quit()
    

if __name__ == '__main__':
  sys.exit(main())