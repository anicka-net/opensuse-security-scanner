# fillup Security Scan Report

**Files scanned**: 27
**Files with findings**: 5
**Total findings**: 11

## Findings

### [Medium] writeBaseFileHeader (SRC/parser.c)
**File**: SRC/parser.c
**Type**: Out‑of‑bounds read
**Model**: openai/gpt-oss-20b@http://localhost:8404 (stage: triage)
**Description**: The function calculates `endOfHeader` as the index of a newline character. It then accesses `baseFileHeader[endOfHeader + 1]` to test for a second newline. If the newline is the last character in the buffer (`endOfHeader == length-1`), this read accesses one byte past the end of the buffer, potentially leaking memory contents or causing a crash.
**Exploitation**: An attacker controlling the contents of `baseFileHeader` could craft a file where the header ends at the very last byte of the buffer. The out‑of‑bounds read would then expose adjacent memory, which could be used to glean sensitive data or trigger a fault that could be leveraged in a larger exploit chain.

### [Medium] writeOutput (SRC/parser.c)
**File**: SRC/parser.c
**Type**: Potential buffer overflow
**Model**: openai/gpt-oss-20b@http://localhost:8404 (stage: triage)
**Description**: `newBaseFileName` is declared as `char newBaseFileName[ cfg_MaxVariableLength ]`. The code calls `createNewBaseFileName(baseFileName, newBaseFileName)` without showing bounds checks. If `createNewBaseFileName` writes more than `cfg_MaxVariableLength` bytes, it will overflow the stack buffer, corrupting adjacent data and potentially allowing arbitrary code execution.
**Exploitation**: By supplying a specially crafted `BaseFile` name that causes `createNewBaseFileName` to write beyond the allocated array, an attacker could overwrite return addresses or other control data on the stack, leading to code execution.

### [Medium] writeOutput (SRC/parser.c)
**File**: SRC/parser.c
**Type**: Path traversal / arbitrary file write
**Model**: openai/gpt-oss-20b@http://localhost:8404 (stage: triage)
**Description**: The code obtains `baseFileName` and `outputFileName` via `queryStringParameter` and then opens them for writing with `openFileForWriting`. No validation or sanitization of the path components is performed. An attacker who can influence these parameters can specify absolute paths or use `../` sequences to write to arbitrary locations on the filesystem, potentially overwriting critical files.
**Exploitation**: An attacker could set `BaseFile` or `OutputFile` to a path like `/etc/passwd` or `../../../../etc/shadow`, causing the program to create or overwrite those files, leading to privilege escalation or denial of service.

### [Low] writeOutput (SRC/parser.c)
**File**: SRC/parser.c
**Type**: Out‑of‑bounds read
**Model**: openai/gpt-oss-20b@http://localhost:8404 (stage: triage)
**Description**: The function unconditionally accesses `baseFileBlock[0]` and calls `getVEvaluationClass` on it, even when `numberOfUsedBaseBlocks` is zero. If the array is empty, this results in a read of uninitialized memory, which could lead to undefined behavior or a crash.
**Exploitation**: While unlikely to be directly exploitable, an attacker could trigger a crash by ensuring no base blocks are parsed, potentially causing a denial of service.

### [High] main (getArguments.c)
**File**: SRC/getArguments.c
**Type**: Buffer Overflow
**Model**: openai/gpt-oss-20b@http://localhost:8404 (stage: triage)
**Description**: The function `setStringParameter` is called with `*localArgv` without any length checks. If `setStringParameter` copies the string into a fixed‑size buffer, an attacker can supply a very long argument (e.g., a filename of thousands of characters) to overflow that buffer, corrupting adjacent memory and potentially enabling arbitrary code execution or a crash.
**Exploitation**: An attacker runs the program with a maliciously long filename argument, causing `setStringParameter` to overflow its internal buffer and overwrite return addresses or other critical data on the stack or heap.

### [Medium] main (getArguments.c)
**File**: SRC/getArguments.c
**Type**: Path Traversal
**Model**: openai/gpt-oss-20b@http://localhost:8404 (stage: triage)
**Description**: The program accepts file names as command‑line arguments and stores them in the parameters `BaseFile`, `AdditionalFile`, and `OutputFile`. If these parameters are later used to open files without sanitizing the path, an attacker can supply a path such as `../../etc/passwd` to read or write files outside the intended directory.
**Exploitation**: By invoking the program with arguments like `../../etc/passwd`, the attacker can cause the program to open and potentially read or overwrite sensitive system files.

### [Medium] main (getArguments.c)
**File**: SRC/getArguments.c
**Type**: Out‑of‑Bounds Array Access
**Model**: openai/gpt-oss-20b@http://localhost:8404 (stage: triage)
**Description**: The code decrements `localArgc` by 2 after consuming two arguments but does not verify that `localArgc` remains non‑negative before accessing `*localArgv`. If an attacker supplies an odd number of arguments, `localArgc` may become negative, leading to dereferencing beyond the bounds of the `argv` array.
**Exploitation**: Supplying an odd number of arguments can cause the program to read memory beyond the `argv` array, potentially leading to a crash or leaking of memory contents.

### [High] addVLength (variableblock.c)
**File**: SRC/variableblock.c
**Type**: Integer overflow
**Model**: openai/gpt-oss-20b@http://localhost:8404 (stage: triage)
**Description**: The function adds `additionalLength` to `outputBuffer->lengthOfBlock` without any bounds checking. If `lengthOfBlock` and/or `additionalLength` are large enough, the addition can overflow the `long` type, producing a negative or otherwise incorrect length value. Subsequent code that uses this length for memory allocation or array indexing may then allocate too little memory or write beyond allocated bounds, leading to a buffer overflow or memory corruption.
**Exploitation**: An attacker who can influence the values of `lengthOfBlock` and `additionalLength` (e.g., via crafted input that populates the `VariableBlock_t` structure before this call) could force the length to wrap around. When the wrapped length is later used to allocate or index a buffer, the program could write past the end of the buffer, corrupting memory or allowing arbitrary code execution.

### [Medium] All setter/getter functions that dereference `outputBuffer` (e.g., setVClassifier, getVClassifier, setVEvaluationClass, getVEvaluationClass, setVAssociation, getVAssociation, setVBeginOfBlock, getVBeginOfBlock, setVOffsetOfVariableName, getVOffsetOfVariableName, setVOffsetOfDelimiter, getVOffsetOfDelimiter, setVNumberOfEmptyLines, incVNumberOfEmptyLines, setVNumberOfCommentLines, getVNumberOfCommentLines, incVNumberOfCommentLines, setVPred, getVPred, setVSucc, getVSucc) in variableblock.c
**File**: SRC/variableblock.c
**Type**: Null pointer dereference / potential denial‑of‑service
**Model**: openai/gpt-oss-20b@http://localhost:8404 (stage: triage)
**Description**: None of the functions check whether `outputBuffer` (or the output pointer in `getVBeginOfBlock`) is `NULL` before dereferencing it. If a caller passes a `NULL` pointer, the program will crash with a segmentation fault. This can be triggered by malformed input or by manipulating pointers in memory, leading to a denial‑of‑service or, if the crash occurs in privileged code, potentially a privilege escalation scenario.
**Exploitation**: An attacker can supply a `NULL` pointer to any of these functions (for example, by forging a network packet that causes the program to construct a `VariableBlock_t` with a `NULL` pointer field, or by corrupting memory to set `outputBuffer` to `NULL`). The resulting crash can be used to disrupt service or to trigger further vulnerabilities that rely on the program's termination or on privileged execution paths.

### [High] consumeCommentLines (SRC/consume.c)
**File**: SRC/consume.c
**Type**: Buffer over-read / Undefined behavior
**Model**: openai/gpt-oss-20b@http://localhost:8404 (stage: triage)
**Description**: The function calls compareStringsExactly(markerString, buffer) to test whether the current buffer position starts with the comment marker string.  The implementation of compareStringsExactly is not shown, but typical string comparison functions expect the second argument to be a null‑terminated string.  Since consumeCommentLines operates on a raw buffer that is only bounded by the supplied length, the buffer may not be null‑terminated.  If compareStringsExactly reads past the end of the buffer it will over‑read memory, potentially exposing sensitive data or corrupting the stack.
**Exploitation**: An attacker could supply a specially crafted input file that contains a comment marker string at the very end of the buffer.  When consumeCommentLines processes this buffer, compareStringsExactly will read beyond the buffer bounds, causing a memory disclosure or a crash that could be leveraged for a denial‑of‑service or, if the over‑read lands on executable code, a code‑execution vulnerability.

### [High] readFile (SRC/file.c)
**File**: SRC/file.c
**Type**: Integer overflow / Buffer overflow
**Model**: openai/gpt-oss-20b@http://localhost:8404 (stage: triage)
**Description**: The function obtains the file length into a signed `long` variable `fileLength`.  
If `getFileLength()` returns a negative value (e.g., due to an error or an overflow in the underlying implementation) or if the file size exceeds `LONG_MAX`, the subsequent call to `allocateBuffer(fileLength, …)` will interpret the negative or oversized value as an unsigned size, allocating an astronomically large buffer.  
`readFileToBuffer(filePointer, fileLength, &buffer)` then attempts to read `fileLength` bytes into that buffer. Because the buffer size is effectively huge (or zero if the allocation failed), the read operation can overflow the allocated memory or cause a denial‑of‑service by exhausting system memory.  
Additionally, `addToWatchdog(fileLength)` and `associateBuffer(fileSpecifier, fileLength, &buffer)` use the same signed value, potentially causing counter underflow or storing a negative length, which may lead to further undefined behavior in later code.
**Exploitation**: An attacker can supply a specially crafted file (or trigger an error that makes `getFileLength()` return a negative value) to cause `allocateBuffer` to allocate an enormous amount of memory or zero bytes. The subsequent `readFileToBuffer` will then attempt to read a huge amount of data into the buffer, leading to a buffer overflow or a memory exhaustion attack that can crash the process or corrupt adjacent memory, potentially allowing arbitrary code execution or privilege escalation.

## Files confirmed clean

- SRC/metadata.c
- SRC/parameters.c
- SRC/services.c
- SRC/variableblock.h
- SRC/services.h
- SRC/portab.h
- SRC/parameters.h
- SRC/dump.c
- SRC/validate.c
- SRC/metadata.h
- TEST/FCSR/SRC/CreateOutfile.c
- SRC/parser.h
- SRC/consume.h
- TEST/FCSR/SRC/CreateRemoved.c
- TEST/FCSR/SRC/CreateBasefile.c
- TEST/FCSR/SRC/CreateAddfile.c
- SRC/file.h
- SRC/fillup_cfg.h
- SRC/validate.h
- SRC/getArguments.h
- SRC/dump.h
- SRC/fillup_cfg.c