#!/usr/bin/env python3

import argparse
import sys
# import binaryninja as bn
from pwn import *

address = "./Binaries/jpg1"


def extract_functions(address):
  p = process(address)
  elf = ELF(address)

  symbols_dict = elf.symbols
  # print(elf.SymbolType)
  filtered_functions = {}
  for key in symbols_dict.keys():
    if(key[:1] != "." and key[:1] != "_" and key[:4] != "got." and key[:4] != "plt." and ("GLIBC" not in key) and key != "deregister_tm_clones" and key != "register_tm_clones" and key !=""):
      filtered_functions[key] = symbols_dict[key]

  # print(filtered_functions)
  return filtered_functions

skip_func = ['__libc_csu_init', 
             '__libc_csu_fini', 
             '_fini',
             '__do_global_dtors_aux',
             '_start',
             '_init',
             'sub_1034']

# def main():
  # parser = argparse.ArgumentParser()
  # parser.add_argument('-b', '--binary', help = 'binary to analyze', 
  #     required=True)
  # args = parser.parse_args()

  # bv = bn.binaryview.BinaryViewType.get_view_of_file(args.binary)

  # # select appropriate segment
  # for s in bv.segments:
  #   if s.executable:
  #     base = s.start

def breakpoint_addresses(address):
  bp_list = []
  filtered_functions = extract_functions(address)
  for func in filtered_functions.keys():
    # filter out the list of functions
    # if func.symbol.type == bn.SymbolType.ImportedFunctionSymbol: continue
    # if func.name in skip_func: continue
    #output = "{}: ".format(func.name)
    output = ""
    # for bb in func:
    # print(f'{func} : {hex(filtered_functions[func])}')

    bp_list.append(hex(filtered_functions[func]))

      #break
    # print(output)
    # print(bp_list)

  return bp_list

# if __name__ == '__main__':
#   sys.exit(main())

