# COMP6447 Fuzzer Assignment

Usage: python3 fuzzer.py \<path to binary\> \<path to input\>



Fuzzer functionality - Support input files:

- JSON
- CSV



Fuzzer functionality - Fuzzing Strategies:

- Bit flips
- Byte flips
- Known ints
- Repeated Parts
- Keyword extraction



Harness Functionality:

- Detects type of crash
- Logs useful statistics
  - Logs total runtime
  - Number of crashes found
  - Total number of unique crashes 
  - Information on what kind of crash happened, location of bad payload and strategy used to induce the crash
- Timeouts at 5 minutes to ensure our fuzzer doesn't run forever if there is an infinite loop
  - Note: Can't detect differences between code coverage and slow programs yet.