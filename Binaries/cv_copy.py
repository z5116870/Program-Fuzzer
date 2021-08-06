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

SIZE = [4, 8, 16, 32, 64]
FLIP_ARRAY = [1, 2, 4, 8, 16, 32, 64, 128]
MAGIC_VALS = [
  [0xFF],
  [0x7F],
  [0x00],
  [0xFF, 0xFF], # 0xFFFF
  [0x00, 0x00], # 0x0000
  [0xFF, 0xFF, 0xFF, 0xFF], # 0xFFFFFFFF
  [0x00, 0x00, 0x00, 0x00], # 0x00000000
  [0x00, 0x00, 0x00, 0x80], # 0x80000000
  [0x00, 0x00, 0x00, 0x40], # 0x40000000
  [0xFF, 0xFF, 0xFF, 0x7F], # 0x7FFFFFFF
]

# Global flag to stop the mutator
stop_flag = False

# List of unique crashes
crashes = {}

# list of traces
trace = {}

config = {
  # 'file': 'mutated.txt', # name of the target file
  'target': '',     # Location of program to execute
  'corpus': '',     # Initial corpus of files to mutate
  'crashes_dir': 'crashes/', # Where to save crashes
  'seed': None,       # Seed for PRNG
}


input_file = "json_test.txt"
target_file = "json1.txt"

# print(os.uname())
with open(input_file ,'rb') as file:
  file_data = file.read()


class Mutator:
  def __init__(self, core):
    # core set of samples
    self.core = core

    # Data format = > (array of bytearrays, coverage)
    self.trace = set() # Currently observed blocks
    self.corpus =   [] # Corpus of executed samples
    self.pool =     [] # Mutation pool
    self.samples =  [] # Mutated samples

  def __iter__(self):
    # Initiate mutation round
    self._fit_pool()
    self._mutate_pool()
    return self

  def __next__(self):
    if not self.samples:
      self._fit_pool()
      self._mutate_pool()

    global stop_flag
    if stop_flag:
      raise StopIteration
    else:
      return self.samples.pop()

  def _fit_pool(self):
    # fit function for our genetic algorithm
    # Always copy initial corpus
    print('### Fitting round\t\t')
    for sample in self.core:
      self.pool.append((sample, []))
    print('Pool size: {:d} [core samples promoted]'.format(len(self.pool)))

    # Select elements that uncovered new block
    for sample, trace in self.corpus:
      if trace - self.trace: 
        self.pool.append((sample, trace))

    print('Pool size: {:d} [new traces promoted]'.format(len(self.pool)))

    # Backfill to 100
    if self.corpus and len(self.pool) < 100:
      self.corpus.sort(reverse = True, key = lambda x: len(x[1]))

      for _ in range(min(100-len(self.pool), len(self.corpus))):
        # Exponential Distribution
        v = random.random() * random.random() * len(self.corpus)

        self.pool.append(self.corpus[int(v)])
        self.corpus.pop(int(v))
      
      print('Pool size: {:d} [backfill from corpus]'.format(len(self.pool)))
    print('### End of round\t\t')
    
    # Update trace info
    for _, t in self.corpus:
      self.trace |= t

    # Drop rest of the corpus
    self.corpus = []

  def _mutate_pool(self):
    # Create samples by mutating pool
    while self.pool:
      sample,_ = self.pool.pop()
      for _ in range(10):
        self.samples.append(Mutator.mutate_sample(sample))

  def update_corpus(self, data, trace = None):
    self.corpus.append((data, trace))

  @staticmethod
  def mutate_sample(sample):
    _sample = sample[:] # Copy sample

    # methods = [
    #   Mutator.bit_flip,
    #   Mutator.byte_flip,
    #   Mutator.magic_number,
    #   Mutator.add_block,
    #   Mutator.remove_block,
    # ]

    f = random.choice(range(0,6))
    # idx = random.choice(range(0, len(_sample)))
    if(f == 0):
      ss = bit_flipper(bytearray(file_data))
    elif(f == 1):
      ss = byte_flipper(bytearray(file_data))
    elif(f == 2):
      ss = special_bytes_flipper(bytearray(file_data))
    elif(f == 3):
      ss = keyword_fuzzing(input_file, 1)
    elif(f == 4):
      payload = file_replace_one(input_file)
      if(payload):
        ss = payload[random.choice(range(0,len(payload)-1))]
    elif(f == 5):
      payload = repeatedParts(input_file, 1)
      if(payload):
        ss = payload[random.choice(range(0,len(payload)-1))]
      else:
        ss = bit_flipper(bytearray(file_data))
    # elif(f == 1):
    #   ss = bit_flipper(bytearray(file_data))

    return ss

  # def bit_flip(index, _sample):
  #   # num = random.choice(SIZE)
  #   # for idx in random.choices(range(len(_sample)), k = num):
  #     # print(_sample)
  #   _sample = bit_flipper(bytearray(file_data))

  # @staticmethod
  # def byte_flip(index, _sample):
  #   # num = random.choice(SIZE)
  #   # for idx in random.choices(range(len(_sample)), k = num):
  #   _sample = bytearray(byte_flipper(bytearray(file_data)))

  # @staticmethod
  # def magic_number(index, _sample):
  #   pass
  #   # num = random.choice(SIZE)
  #   # for idx in random.choices(range(len(_sample)), k = num):
  #   #   _sample[idx] = bytearray(bit_flipper(bytearray(file_data)))
  #   _sample = bytearray(byte_flipper(bytearray(file_data)))

  # @staticmethod
  # def add_block(index, _sample):
  #   pass
  #   # num = random.choice(SIZE)
  #   # for idx in random.choices(range(len(_sample)), k = num):
  #   #   _sample[idx] = bytearray(bit_flipper(bytearray(file_data)))
  #   _sample = bytearray(byte_flipper(bytearray(file_data)))

  # @staticmethod
  # def remove_block(index, _sample):
  #   pass
  #   # num = random.choice(SIZE)
  #   # for idx in random.choices(range(len(_sample)), k = num):
  #   #   _sample[idx] = bytearray(bit_flipper(bytearray(file_data)))
  #   _sample = bytearray(byte_flipper(bytearray(file_data)))


def save_crashes():
  print('Saving crashes...')
  crash_dir = config['crashes_dir']
  
  if not os.path.exists(crash_dir):
    os.mkdir(crash_dir)

  for ip, data in crashes.items():
    filename = 'crash.{:x}.txt'.format(ip)
    with open(os.path.join(crash_dir, filename), 'wb+') as fh:
      fh.write(data)
  
  print('{} unique crashes.'.format(len(crashes)))

def get_base(vmmap):
  # print(vmmap)
  for m in vmmap:
    if 'x' in m.permissions and m.pathname.endswith(os.path.basename(config['target'])):
      return m.start



def execute_fuzz(dbg, data, bpmap):
  trace = set()
  # cmd = [config['target'], config['file']]
  # cmd = [config['file'],config['target']]
  # print(cmd)
  # # pid = debugger.child.createChild(cmd, no_stdout=True, env=None)
  # child_proc = Popen(["cat mutated.txt | Binaries/json1"], shell=True)
  # p = process("Binaries/json1")
  # print(p.pid)
  # process = Popen(["Binaries/json1"], stdout=PIPE, stderr= PIPE, stdin=PIPE)
  # print(process.pid)
  # pause()
  # out,err = proc.communicate(bytes(flipped_str,'utf-8'))
  # # child_proc = Popen(config['target'], shell=True, stdin = PIPE, stdout = PIPE, stderr = PIPE)
  # # out,err = child_proc.communicate(bytes(f))
  # pid = child_proc.pid
  # print(pid)
  # pid, status = os.waitpid(process.pid, 0)
  # print(pid, status)
  # Wait for child to complete.
  # p = process("cat Binaries/json1.txt | Binaries/json1", shell=True)
  FNAME = 'mutated.txt'
  try:
    os.mkfifo(FNAME, mode=0o777)
  except FileExistsError:
    pass

  # Open read end of pipe. Open this in non-blocking mode since otherwise it
  # may block until another process/threads opens the pipe for writing.
  stdin = os.open(FNAME, os.O_RDONLY | os.O_NONBLOCK)

  # Open the write end of pipe.
  tochild = os.open(FNAME, os.O_WRONLY)
  print('Pipe open (%d, %d)' % (stdin, tochild))

  process = Popen(
      ['Binaries/json1'],
      # shell=False,
      stdout=None,
      stdin=stdin,
      stderr=None,
      universal_newlines=True,
  )
  os.close(stdin)

  # print('child started: %s (%s)' % (str(process.pid), str(process.stdin)))
  # print('writing to child ...')
  try:
    os.write(tochild, bytearray(data))
  except:
   return trace
  # os.write(tochild, bytes('Line 2\n', 'utf-8'))
  # print('data written')
  os.close(tochild)
  os.unlink(FNAME)


  pid = process.pid
  # try:
  proc = dbg.addProcess(pid, False)
  # newid = os.fork()
  # if(newid == 0):
  #   process.communicate(file_data)
  # print(proc.getregs())
  # print(proc.readMappings())
  base = get_base(proc.readMappings())
  # print(bpmap)
  if bpmap:
    for offset in bpmap:
      # print("BP: ",offset)
      # proc.createBreakpoint(base + offset)
      proc.createBreakpoint(int(offset,16), size = 4)

  # print(proc.getregs())
  # print("BASE", pid, proc)

  # Insert breakpoints for tracing
  
  while True:
    proc.cont()
    # print("HERE")
    event = dbg.waitProcessEvent()
    # event = dbg.waitSignals()
    # print("EVENT ",event.signum, signal.SIGTRAP)
    # instr_ptr = proc.getInstrPointer()
    if event.signum == signal.SIGSEGV:
      info = proc.backtrace()
      print(info)
      # print(dir(info))
      # print(info,dir(info.frames.pop),dir(info.frames.append),dir(info.frames.index),info.frames.sort)
      # print(dir(info),info.inode, info.major_device, info.minor_device, info.offset, info.pathname, info.permissions, info.search, info.start)
      print(instr_ptr, proc.getInstrPointer())
      crash_ip = proc.getInstrPointer() - 1 # getInstrPointer() always returns instruction + 1
      print("SEGFAULT", crash_ip)
      if crash_ip not in crashes:
        crashes[crash_ip] = data
      proc.detach()
      break
    elif event.signum == signal.SIGTRAP:
      ip = proc.getInstrPointer()
      br = proc.findBreakpoint(ip-1).desinstall()
      proc.setInstrPointer(ip-1) # Rewind back to the correct code
      # print("SIGTRAP",hex(ip), br)
      trace.add(ip - base - 1)
    elif event.signum == signal.SIGINT:
      print('Stoping execution')
      proc.detach()
      break
    elif isinstance(event, debugger.ProcessExit):
      proc.detach()
      break
    else:
      print('Something went wrong -> {}'.format(event))
  
  process.wait()
  # Program terminated
  return trace
  # except:
  #   return trace

def save_file(data, path='mutated1.txt'):
  with open(path, 'wb+') as fh:
    fh.write(data)

def get_corpus(path):
  corpus = []

  if os.path.isfile(path):
    with open(path, 'rb') as fh:
      corpus.append(bytearray(fh.read()))
  elif os.path.isdir(path):
    for file in os.listdir(path):
      if os.path.isfile(file):
        with open(file, 'rb') as fh:
          corpus.append(bytearray(fh.read()))

  print("CORPUS", corpus)
  return corpus

def get_bpmap(path):
  bpmap = []

  if path and os.path.isfile(path):
    with open(path, "r") as fh:
      for line in fh.readlines():
        bpmap.extend(list(map(lambda x: int(x.strip(), 16), line.split())))
  else:
    print("No breakpoint map; trace won't be generated")

  return bpmap

def create_config(args):
  config['target'] = args.target
  config['corpus'] = args.corpus
  config['bpmap'] = args.bpmap

  if args.seed:
    config['seed'] = base64.b64decode(seed)

def finish(sig, frame):
  global stop_flag
  print('Finishing fuzz job.')
  stop_flag = True

def main():
  signal.signal(signal.SIGINT, finish)
  parser = argparse.ArgumentParser()
  parser.add_argument('-t', '--target', help = 'target program', 
      required=True)
  parser.add_argument('-b', '--bpmap', help = 'map of breakpoints for trace',
      required=False)
  parser.add_argument('-c', '--corpus', help = 'corpus of files',
      required=True)
  parser.add_argument('-s', '--seed', help = 'seed for PRNG', 
      required=False)
  create_config(parser.parse_args())

  # bp_map = get_bpmap(config['bpmap'])
  bp_map = breakpoint_addresses(config['target'])
  # print(bp_map)
  corpus = get_corpus(config['corpus'])
  dbg = debugger.PtraceDebugger()

  # Seed the PRNG
  if config['seed']:
    initial_seed = config['seed']
  else:
    initial_seed = os.urandom(24)
    
  random.seed(initial_seed)
  print('Starting new fuzzing run with seed {}'.format(
      base64.b64encode(initial_seed).decode('utf-8')))
  
  # Initialize mutator
  mutator = Mutator(corpus)
  print(mutator)

  print("STEP 1")
  counter = 0
  start_time = time.time()
  for sample in mutator:
    # break
    # print("SAMPLE ",sample)
    # save_file(sample)
    trace = execute_fuzz(dbg, sample, bp_map)
    # print("TRACE", trace)
    mutator.update_corpus(sample, trace)
    counter += 1
    print('#{:3d} Coverage {:.2f}%\r'.format(
        counter, (len(trace)/len(bp_map)) * 100), end='')

  x = counter / (time.time()-start_time)
  print('-> {:.0f} exec/sec'.format(x))
  
  #cleanup
  dbg.quit()
  save_crashes()

if __name__ == '__main__':
  sys.exit(main())



'''
  def execute_fuzz(dbg, data, bpmap):
  trace = set()
  # cmd = [config['target'], config['file']]
  # cmd = [config['file'],config['target']]
  # print(cmd)
  # # pid = debugger.child.createChild(cmd, no_stdout=True, env=None)
  # child_proc = Popen(["cat mutated.txt | Binaries/json1"], shell=True)
  # p = process("Binaries/json1")
  # print(p.pid)
  # process = Popen(["Binaries/json1"], stdout=PIPE, stderr= PIPE, stdin=PIPE)
  # print(process.pid)
  # pause()
  # out,err = proc.communicate(bytes(flipped_str,'utf-8'))
  # # child_proc = Popen(config['target'], shell=True, stdin = PIPE, stdout = PIPE, stderr = PIPE)
  # # out,err = child_proc.communicate(bytes(f))
  # pid = child_proc.pid
  # print(pid)
  # pid, status = os.waitpid(process.pid, 0)
  # print(pid, status)
  # Wait for child to complete.
  # p = process("cat Binaries/json1.txt | Binaries/json1", shell=True)
  FNAME = 'mutated.txt'
  # os.mkfifo(FNAME, mode=0o777)

  # Open read end of pipe. Open this in non-blocking mode since otherwise it
  # may block until another process/threads opens the pipe for writing.
  stdin = os.open(FNAME, os.O_RDONLY | os.O_NONBLOCK)

  # Open the write end of pipe.
  tochild = os.open(FNAME, os.O_WRONLY)
  print('Pipe open (%d, %d)' % (stdin, tochild))

  process = Popen(
      ['Binaries/json1'],
      # shell=False,
      stdout=None,
      stdin=stdin,
      stderr=None,
      universal_newlines=True,
  )
  os.close(stdin)

  print('child started: %s (%s)' % (str(process.pid), str(process.stdin)))
  print('writing to child ...')
  os.write(tochild, bytes(file_data))
  # os.write(tochild, bytes('Line 2\n', 'utf-8'))
  print('data written')
  os.close(tochild)
  os.unlink(FNAME)


  pid = process.pid
  proc = dbg.addProcess(pid, False)
  # newid = os.fork()
  # if(newid == 0):
  #   process.communicate(file_data)
  # print(proc.getregs())
  # print(proc.readMappings())
  base = get_base(proc.readMappings())
  # print(bpmap)
  if bpmap:
    for offset in bpmap:
      # print("BP: ",offset)
      # proc.createBreakpoint(base + offset)
      proc.createBreakpoint(int(offset,16), size = 4)

  # print(proc.getregs())
  # print("BASE", pid, proc)

  # Insert breakpoints for tracing
  
  while True:
    proc.cont()
    # print("HERE")
    event = dbg.waitProcessEvent()
    # event = dbg.waitSignals()
    # print("EVENT ",event.signum, signal.SIGTRAP)
    
    if event.signum == signal.SIGSEGV:
      crash_ip = proc.getInstrPointer() - base - 1 # getInstrPointer() always returns instruction + 1
      if crash_ip not in crashes:
        crashes[crash_ip] = data
      proc.detach()
      break
    elif event.signum == signal.SIGTRAP:
      ip = proc.getInstrPointer()
      br = proc.findBreakpoint(ip-1).desinstall()
      proc.setInstrPointer(ip-1) # Rewind back to the correct code
      # print(hex(ip), br)
      trace.add(ip - base - 1)
    elif event.signum == signal.SIGINT:
      print('Stoping execution')
      proc.detach()
      break
    elif isinstance(event, debugger.ProcessExit):
      proc.detach()
      break
    else:
      print('Something went wrong -> {}'.format(event))
  
  process.wait()
  # Program terminated
  return trace
  '''