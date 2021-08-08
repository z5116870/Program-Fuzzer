# COMP6447 Fuzzer Assignment

## Installation

Unix:

   ```
   ./install.sh
   ```



## Usage

### Direct through python3

```
python3 fuzzer.py <path to binary> <path to input>
```

with coverage mutations

```
python3 fuzzer.py <path to binary> <path to input> -c
```

### Using executable

```
./fuzzer <path to binary> <path to input>
```

With coverage mutations

```
./fuzzer <path to binary> <path to input> -c
```



Fuzzer functionality - Support input files:

- JSON
- CSV
- Plaintext
- XML
- PDF
- ELF
- JPEG



Fuzzer functionality - Fuzzing Strategies:

- Bit flips
- Byte flips
- Known ints
- Repeated Parts
- Keyword extraction
- Arithmetic 
- Coverage Based (via -c option)



Harness Functionality:

- Detects type of crash
- Detects hangs and infinite loops
- Logs useful statistics
  - Logs total runtime
  - Number of crashes found
  - Total number of unique crashes 
  - Information on what kind of crash happened, location of bad payload and strategy used to induce the crash
- Timeouts at 3 minutes to ensure our fuzzer doesn't run forever if there is an infinite loop
