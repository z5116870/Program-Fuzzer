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
# from rp2 import repeatedParts

target_file = sys.argv[1]
input_file = sys.argv[2]
dummy_file = "mutated.txt"
crash_directory = "crashes/"

with open(input_file) as file:
  input_file_data = file.read()

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

        # print("COLLECTION ",self.collection)
        for data, current in self.collection:
            # print(current, self.current)
            # print("SET")
            # print(set(current), set(self.current))
            if current - self.current:
                self.cache.append((data, current))

        print('New mutated input added to collection {:d} '.format(len(self.cache)))

        # print("LEN", self.collection and len(self.cache))
        if self.collection and len(self.cache) < 100:
          self.collection.sort(reverse = True, key = lambda x: len(x[1]))

          for _ in range(min(100-len(self.cache), len(self.collection))):
            # Exponential Distribution
            v = random.random() * random.random() * len(self.collection)
            # print("C!",self.collection)
            self.cache.append(self.collection[int(v)])
            self.collection.pop(int(v))
            # print("C@",self.collection)
        #   print("bACKFILL ",self.cache)
        #   print('cache size: {:d} [backfill from collection]'.format(len(self.cache)))
        print('----------- Finished analysis round ----------------\t\t')

        for _, item in self.collection:
          # print(item)
          self.current |= item
        # print("CRR",self.current)

        self.collection = []

    def mutation_strategy(self):
        while self.cache:
          item,_ = self.cache.pop()
          for _ in range(30):
            # print(item)
            self.mutated_inputs.append(coverage_based_mutation.mutate_inputs(item))

        # print(self.mutated_inputs)


    def update_collection(self, data, cvg = None):
        # print(cvg)
        # print(self.collection)
        self.collection.append((data, cvg))

    @staticmethod
    def mutate_inputs(item):

        if(isinstance(item, bytearray)):
          item1 = item[:]
        else:
          item1 = bytearray(input_file_data, 'utf-8')
        # inputt = item[:]
        # print(inputt)
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
          payload = file_replace_one(input_file)
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

        # print(ss)

        return ss

def save_crash_files():
    crash_directory = "crashes/"

    global crash_list
    print(f"Unique crashes: {len(crash_list)}")

    if not os.path.exists(crash_directory):
        os.mkdir(crash_directory)

    # global crash_list

    unique_inputs = set()
    for address, m_input in crash_list.items():
        file = 'crash_{}.txt'.format(hex(address))
        with open(os.path.join(crash_directory, file), 'wb+') as fh:
          fh.write(m_input)




def get_base(vmmap):
  # print(vmmap)
  for m in vmmap:
    if 'x' in m.permissions and m.pathname.endswith(os.path.basename(target_file)):
      return m.start


def fuzz(dbg, data, bpmap):
  DFILE = dummy_file

  covered = set()
  try:
    os.mkfifo(DFILE, mode=0o777)
  except FileExistsError:
    pass
  input_subprocess = os.open(DFILE, os.O_RDONLY | os.O_NONBLOCK)

  comm = os.open(DFILE, os.O_WRONLY)
  # print('Pipe open (%d, %d)' % (stdin, tochild))

  # try:
  process = Popen(
      [target_file],
      # shell=False,
      stdout=open(os.devnull,'wb'),
      stdin=input_subprocess,
      stderr=PIPE,
      close_fds=True,
      preexec_fn = os.setsid
  )
  # except:
  #   os.killpg(os.getpgid(process.pid), signal.SIGTERM) 
  #   # process.wait()
  #   # process.terminate()
  #   # process.kill()
  #   
  #   os.close(comm)
  #   os.unlink(DFILE)

  #   return

  # print("DATA ",data)
  # print(data)
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
    # base = get_base(traceProc.readMappings())
    if bpmap:
      for offset in bpmap:
        traceProc.createBreakpoint(int(offset,16), size = 4)
    
    while True:
      traceProc.cont()
      traceProcEvent = dbg.waitProcessEvent()
      if traceProcEvent.signum == signal.SIGSEGV:
        # info = traceProc.backtrace()
        crash_pointer = traceProc.getInstrPointer() - 1 # getInstrPointer() always returns instruction + 1
        if(crash_pointer not in crash_addr):
          print("SEGFAULT at: ", hex(crash_pointer))
          crash_addr.add(crash_pointer)
        # bf = True
        # if crash_ip not in crashes:
        crash_list[crash_pointer] = bytes(data,'utf-8')
        traceProc.detach()
        break

      elif traceProcEvent.signum == signal.SIGFPE:
        crash_pointer = traceProc.getInstrPointer() - 1 # getInstrPointer() always returns instruction + 1
        if(crash_pointer not in crash_addr):
          print("SIGFPE at: ", hex(crash_pointer))
          crash_addr.add(crash_pointer)
        # bf = True
        # if crash_ip not in crashes:
        crash_list[crash_pointer] = bytes(data,'utf-8')
        traceProc.detach()
        break

      elif traceProcEvent.signum == signal.SIGTRAP:
        instrPtr = traceProc.getInstrPointer()
        brkPts = traceProc.findBreakpoint(instrPtr-1).desinstall()
        traceProc.setInstrPointer(instrPtr-1) # Rewind back to the correct code
        # print("SIGTRAP",hex(instrPtr), brkPts)
        covered.add(instrPtr - 1)
      elif traceProcEvent.signum == signal.SIGINT:
        print('Stoping execution')
        traceProc.detach()
        break
      elif traceProcEvent.signum == signal.SIGABRT:
        print('Stoping execution')
        traceProc.detach()
        break
      elif isinstance(traceProcEvent, debugger.ProcessExit):
        traceProc.detach()
        break
      else:
        # print(data)
        print('Something went wrong -> {}'.format(traceProcEvent))
    
    traceProc.detach()
    # process.kill()
    process.kill()
    return covered

  except:
    # traceProc.detach()
    # process.kill()
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
        # print(str(mutation))
        # mutation = bytes(mutation, 'utf-8')
        coverage = fuzz(ptracer, mutation, breakpoints)
        # print("TRACE", trace)
        # print(coverage)
        mutations.update_collection(mutation, coverage)
        counter += 1

        print('#{:3d} Coverage {:.2f}%\r'.format(
            counter, (len(coverage)/len(breakpoints)) * 100), end='')
    
    save_crash_files()

    ptracer.quit()
    

if __name__ == '__main__':
  sys.exit(main())