from subprocess import Popen, PIPE
import signal
from Strategies.getFileType import FileType, getFileType
import time
import os
import sys
import re
import random

RE_NONTERMINAL = re.compile(r'(<[^<> ]*>)')
START_SYMBOL = "<start>"
EXPR_GRAMMAR = {
    "<start>":
        ["<expr>"],

    "<expr>":
        ["<term>+<expr>", "<term>-<expr>", "<term>"],

    "<term>":
        ["<factor>*<term>", "<factor>/<term>", "<factor>"],

    "<factor>":
        ["<expr>",
         "<digit>"],

    "<digit>":
        ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
}
def nonterminals(expansion):
	if isinstance(expansion, tuple):
		expansion = expansion[0]
	return re.findall(RE_NONTERMINAL, expansion)

def simple_grammar_fuzzer(grammar, start_symbol=START_SYMBOL,
                          max_nonterminals=10, max_expansion_trials=300,
                          log=False):
    term = start_symbol
    expansion_trials = 0

    while len(nonterminals(term)) > 0:
        symbol_to_expand = random.choice(nonterminals(term))
        expansions = grammar[symbol_to_expand]
        expansion = random.choice(expansions)
        new_term = term.replace(symbol_to_expand, expansion, 1)

        if len(nonterminals(new_term)) < max_nonterminals:
            term = new_term
            if log:
                print("%-40s" % (symbol_to_expand + " -> " + expansion), term)
            expansion_trials = 0
        else:
            expansion_trials += 1
            if expansion_trials >= max_expansion_trials:
                raise ExpansionError("Cannot expand " + repr(term))

    return term

def is_nonterminal(s):
	return re.match(RE_NONTERMINAL, s)

def runFuzzedInput(text, binary):
	proc = Popen([binary], shell=True, stdin = PIPE, stdout = PIPE, stderr = PIPE)
	output, error = proc.communicate(bytes(text, 'utf-8'))
	return(proc.returncode)

def arithmetic(testInput, type):
	# Fuzz using the expression grammar
	if (type == FileType.pdf or type == FileType.elf or type == FileType.jpeg):
		return []
	else:
		payload = ''
		payloads = []
		with open(testInput) as f:
			text = f.read()
		print(text)
		
		assert nonterminals("<term> * <factor>") == ["<term>", "<factor>"]
		assert nonterminals("<digit><integer>") == ["<digit>", "<integer>"]
		assert nonterminals("1 < 3 > 2") == []
		assert nonterminals("1 <3> 2") == ["<3>"]
		assert nonterminals("1 + 2") == []
		assert nonterminals(("<1>", {'option': 'value'})) == ["<1>"]
		assert is_nonterminal("<abc>")
		assert is_nonterminal("<symbol-1>")
		assert not is_nonterminal("+")

		for i in range(10):
			expr = simple_grammar_fuzzer(grammar=EXPR_GRAMMAR, max_nonterminals=8)
			payloads.append(expr)

		return payloads

def run(binary, testInput):
	print("making fuzzed inputs...")
	inputtype = getFileType(testInput)
	payloads = arithmetic(testInput, inputtype)
	print("Done.")
	badpload = []
	codes = []
	crashes = 0
	# p = process(binary)
	print("running fuzzed inputs...: " + binary)
	for payload in payloads:
		retCode = runFuzzedInput(payload, binary)
		if(retCode != 0):
			crashes += 1
			badpload.append(payload)
			codes.append(retCode)
	printStats(crashes, badpload, codes)

def printStats(crashes, badpload, codes):
	print("---STATS---")
	print("CRASHES: ", crashes)
	print("CAUGHT PAYLOADS:")
	i = 0
	x = 0
	for pload in badpload:
		print(x,': ', pload)
		x += 1

	# print only unique codes
	u = []
	for i in codes:
		if i not in u:
			u.append(i)
	print("CAUGHT CODES: ", u)

#run(sys.argv[1], sys.argv[2])
