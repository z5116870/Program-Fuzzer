# Mid Week Check in

## Fuzzer Functionality and Design

Our fuzzer is split into two parts, code for various strategies used to mutate the given input and code for the harness which applies our different strategies to get payloads to run against the target binaries. 

So far our fuzzer is able to detect the following input types: 

* Plaintext
* Json 
* Csv
* Xml
* Jpeg 

We have yet to implement code to identify elf and pdf files. 

We have also implemented the following strategies for each input type:


<table>
  <tr>
   <td>Input Types
   </td>
   <td>Bit flip
   </td>
   <td>Byte flips
   </td>
   <td>Known Ints
   </td>
   <td>Repeated Parts
   </td>
   <td>Keyword Extraction
   </td>
   <td>Arithmetic
   </td>
   <td>Coverage Based
   </td>
  </tr>
  <tr>
   <td>Plaintext
   </td>
   <td>yes
   </td>
   <td>yes
   </td>
   <td>yes
   </td>
   <td>yes
   </td>
   <td>no
   </td>
   <td>no
   </td>
   <td>no
   </td>
  </tr>
  <tr>
   <td>JSON
   </td>
   <td>yes
   </td>
   <td>yes
   </td>
   <td>yes
   </td>
   <td>yes
   </td>
   <td>yes
   </td>
   <td>no
   </td>
   <td>no
   </td>
  </tr>
  <tr>
   <td>XML
   </td>
   <td>no
   </td>
   <td>no
   </td>
   <td>no
   </td>
   <td>no
   </td>
   <td>no
   </td>
   <td>no
   </td>
   <td>no
   </td>
  </tr>
  <tr>
   <td>CSV
   </td>
   <td>yes
   </td>
   <td>yes
   </td>
   <td>yes
   </td>
   <td>yes
   </td>
   <td>yes
   </td>
   <td>no
   </td>
   <td>no
   </td>
  </tr>
  <tr>
   <td>JPEG
   </td>
   <td>no
   </td>
   <td>no
   </td>
   <td>no
   </td>
   <td>no
   </td>
   <td>no
   </td>
   <td>no
   </td>
   <td>no
   </td>
  </tr>
</table>



## Mutation Strategies

**Keyword Extraction: **

The fuzzer is able to extract words from the input and this strategy randomly selects a word inside of the input and replaces it with a keyword from the input. For json, all the keys are identified as keywords and this strategy swaps the keys in the json file around while leaving the values as is . For csv, all the words in the csv file are considered keywords and a random set of locations and words are selected and replaced with random words from the set of keywords extracted from the input file. The idea behind using this fuzzing strategy is that by swapping keywords around, the program may end up assuming that a certain type or word is being used without checking thus our fuzzer may be able to identify bugs in binaries that don’t distinguish between user input, command words and metadata information. This fuzzing strategy might also identify bugs when a binary assumes to be processing a certain type of input but gets something else instead which could result in memory errors. 

---

**Known Ints:**

The fuzzer is able to extract integers from the input and this strategy randomly selects an integer inside the input and replaces it with different integers in hopes of crashing the program or finding a vulnerability. The idea behind this fuzzing strategy is that by altering the numbers in the inputs, we can create a payload that is not rejected, however creates unexpected behaviour. We check for things such as programs accepting negative inputs, very large numbers that could cause integer overflows, decimals that could alter certain operation results, buffer overflows. For example, if the program is asking for a length of input, and it is supplied 99999 as the answer, it might be more than expected and the program might wind up with a buffer overflow.

---

**Bit Flips:**

The fuzzer can flip the bit or byte of the string. The flipping strategy takes input in the form of bytearray and manipulates a bit or byte randomly. There is also a special case, where bytes known as “Magic values” are used to replace the existing bytes. All three strategies are used randomly to manipulate the input and cause unexpected behaviour in the binary. The idea behind this strategy is that if the right bit is flipped at the right place, it can cause the binary to take in unexpected input and expose the vulnerability, if it exists.

---

**Repeated Parts:**

The fuzzer is able to repeat parts of the input, selecting every substring of the input, repeating it at every location in the input up to a number which can be specified according to time constraints. A value of 10 was selected, enough to generate segmentation faults in both the json1 and csv1 binaries. A payload is generated for each repeated string altered input and fed to the binary and those that generate errors are recorded. The idea here is that by repeating certain parts of the input, any vulnerabilities that assume size and data type will be exposed, such as repeating value to a length field or repeating a large enough string to an assumed variable to cause a buffer overflow.

 


## Harness Functionality

The harness currently takes the various payloads created by the above strategies and runs them against the provided binary. The harness is able to detect when the program exists incorrectly and logs the payload information that caused the crash in a separate file. The harness is also able to filter out duplicate crashes and produces statistics after all the fuzzing is completed. The harness is currently able to display the type of crash that happened, the location of the payload that caused the crash and the type of mutation strategy used to generate the payload.