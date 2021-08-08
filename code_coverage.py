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
from Strategies.flipper import bit_flipper, byte_flipper, special_bytes_flipper
from Strategies.ints import file_replace_one
from Strategies.flipper import bit_flipper, byte_flipper, special_bytes_flipper
from Strategies.repeatedParts import repeatedParts
from Strategies.keyword_extraction import keyword_fuzzing
from Strategies.getFileType import FileType, getFileType
from Strategies.arithmetic import arithmetic
# from rp2 import repeatedParts

target_file = sys.argv[1]
input_file = sys.argv[2]
dummy_file = "mutated.txt"
crash_directory = "coverage_crashes/"

# with open(input_file) as file:
#   input_file_data = file.read()

global input_file_data

crash_list = {}

crash_addr = set()

fuzzstop = False

def key_interrupt(sig, frame):
  global fuzzstop
  print('Finishing fuzz job.')
  fuzzstop = True

class coverage_based_mutation:
    
    def __init__(self,org_input):
        self.input = org_input
        self.init_flag = True
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
        if(fuzzstop):
            raise StopIteration
        else:
            return self.mutated_inputs.pop()

    def analyse_mutation(self):
        print('------- Analysing mutation ------------------\t\t')
        if(self.init_flag):
            self.cache.append((self.input, []))
            self.init_flag = False

        set = 0
        for data, current in self.collection:
            if current - self.current:
                self.cache.append((data, current))
                set += 1

        print('New mutated inputs added to collection {:d} '.format(set))
        for _, item in self.collection:
          self.current.update(item)

        self.collection = []

    def mutation_strategy(self):
        while self.cache:
          item,_ = self.cache.pop()
          for _ in range(100):
            self.mutated_inputs.append(coverage_based_mutation.mutate_inputs(item))
            self.mutated_inputs.append(coverage_based_mutation.mutate_inputs())

    def update_collection(self, data, cvg = None):
        self.collection.append((data, cvg))

    @staticmethod
    def mutate_inputs(item = []):

        if(isinstance(item, bytearray)):
          item1 = item[:]
        else:
          item1 = bytearray(input_file_data, 'utf-8')
        
        f = random.choice(range(0,6))

        if(f == 0):
          ss = bit_flipper(item1)
          
        elif(f == 1):
          ss = byte_flipper(item1)
        elif(f == 2):
          ss = special_bytes_flipper(item1)
        elif(f == 3):
          ss = keyword_fuzzing(input_file, getFileType(input_file))
        elif(f == 4):
          payload = file_replace_one(input_file, getFileType(input_file))
          if(payload):
            ss = payload[random.choice(range(0,len(payload)))]
        elif(f == 5):
          # item2 = str(item)
          payload = repeatedParts(input_file, getFileType(input_file))
          if(payload):
            # print(payload)
            ss = payload[random.choice(range(0,len(payload)))]
          else:
            ss = bit_flipper(bytearray(input_file_data, 'utf-8'))
        elif(f == 6):
          payloads = arithmetic(filename, getFileType(input_file))
          if(payload):
            # print(payload)
            ss = payload[random.choice(range(0,len(payload)))]
        return ss

def create_crash_file(data):
    f = open("bad.txt", "wb+")
    if not isinstance(data, bytearray) and not isinstance(data, bytes):
        data = bytes(data, 'utf-8')
    f.write(data)
    f.close()

def save_crash_files():
    crash_directory = "coverage_crashes/"

    global crash_list
    print(f"Unique crashes: {len(crash_list)}")
    if not os.path.exists(crash_directory):
        os.mkdir(crash_directory)

    bFlag = True
    for address, m_input in crash_list.items():
        if(bFlag):
          create_crash_file(m_input)
          bFlag = False
        file = 'crash_{}.txt'.format(hex(address))
        with open(os.path.join(crash_directory, file), 'wb+') as fh:
          fh.write(m_input)


def fuzz(dbg, data, bpmap, binary):
  DFILE = dummy_file

  covered = set()
  try:
    os.mkfifo(DFILE, mode=0o777)
  except FileExistsError:
    pass
  input_subprocess = os.open(DFILE, os.O_RDONLY | os.O_NONBLOCK)

  comm = os.open(DFILE, os.O_WRONLY)
  process = Popen(
      [binary],
      # shell=False,
      stdout=open(os.devnull,'wb'),
      stdin=input_subprocess,
      stderr=PIPE,
      close_fds=True,
      preexec_fn = os.setsid
  )

  os.close(input_subprocess)
  try:
    os.write(comm, bytes(data,'utf-8'))
  except:
    os.close(comm)
    os.unlink(DFILE)
    return covered

  os.close(comm)
  os.unlink(DFILE)


  pid = process.pid

  try:
    traceProc = dbg.addProcess(pid, False)
    if bpmap:
      for offset in bpmap:
        traceProc.createBreakpoint(int(offset,16), size = 4)
    
    while True:
      traceProc.cont()
      traceProcEvent = dbg.waitProcessEvent()
      if traceProcEvent.signum == signal.SIGSEGV:
        # info = traceProc.backtrace()
        crash_pointer = traceProc.getInstrPointer() - 1
        if(crash_pointer not in crash_addr):
          print("SEGFAULT at: ", hex(crash_pointer))
          crash_addr.add(crash_pointer)
        crash_list[crash_pointer] = bytes(data,'utf-8')
        traceProc.detach()
        break

      elif traceProcEvent.signum == signal.SIGFPE:
        crash_pointer = traceProc.getInstrPointer() - 1
        if(crash_pointer not in crash_addr):
          print("SIGFPE at: ", hex(crash_pointer))
          crash_addr.add(crash_pointer)
        crash_list[crash_pointer] = bytes(data,'utf-8')
        traceProc.detach()
        break

      elif traceProcEvent.signum == signal.SIGTRAP:
        instrPtr = traceProc.getInstrPointer()
        brkPts = traceProc.findBreakpoint(instrPtr-1).desinstall()
        traceProc.setInstrPointer(instrPtr-1)
        covered.add(instrPtr - 1)
      elif traceProcEvent.signum == signal.SIGINT:
        traceProc.detach()
        break
      elif traceProcEvent.signum == signal.SIGABRT:
        traceProc.detach()
        break
      elif isinstance(traceProcEvent, debugger.ProcessExit):
        traceProc.detach()
        break
      else:
        print('Something went wrong -> {}'.format(traceProcEvent))
    
    traceProc.detach()
    return covered

  except:
    return covered


def coverage(binary, filename):
    signal.signal(signal.SIGINT, key_interrupt)

    start_time = time.time()

    global input_file_data

    with open(filename) as file:
      input_file_data = file.read()

    breakpoints = breakpoint_addresses(binary)
    ptracer = debugger.PtraceDebugger()

    mutations = coverage_based_mutation([input_file_data])
    counter = 0
    
    for mutation in mutations:
        coverage = fuzz(ptracer, mutation, breakpoints, binary)
        mutations.update_collection(mutation, coverage)
        counter += 1

        print('#{:3d} Coverage {:.2f}%\r'.format(
            counter, (len(coverage)/len(breakpoints)) * 100), end='')

        if(time.time() - start_time >= 180):
          break

    save_crash_files()

    ptracer.quit()
    

# if __name__ == '__main__':
#   sys.exit(main())
# def main():
#     signal.signal(signal.SIGINT, key_interrupt)
#     start_time = time.time()
#     breakpoints = breakpoint_addresses(target_file)

#     ptracer = debugger.PtraceDebugger()

#     mutations = coverage_based_mutation([input_file_data])
#     counter = 0
    
#     for mutation in mutations:
#         coverage = fuzz(ptracer, mutation, breakpoints)
#         mutations.update_collection(mutation, coverage)
#         counter += 1

#         print('#{:3d} Coverage {:.2f}%\r'.format(
#             counter, (len(coverage)/len(breakpoints)) * 100), end='')
    
#     save_crash_files()

#     ptracer.quit()
    

# if __name__ == '__main__':
#   sys.exit(main())