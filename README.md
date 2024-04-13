# AES Implementation in C

This repository contains a basic implementation of the Advanced Encryption Standard (AES) algorithm in C, along with a Python test script to verify the correctness of the implementation.

## Files:

1. **rijndael.h**: Header file containing function prototypes and necessary macros for AES encryption and decryption.
2. **rijndael.c**: Source file containing the implementation of AES encryption and decryption functions.
3. **main.c**: Example C program demonstrating the usage of the AES implementation.
4. **tests.py**: Python script for testing the AES implementation by comparing the output with a Python AES implementation.
5. **Makefile**: Makefile to automate the build process.

## Usage:

1. **Build Project**: 
   - Use the provided Makefile to compile the source files and generate the executable.
```bash
make -m Makefile
```exit

2. **Run Tests**:
- Run the Python test script `tests.py` to verify the correctness of the AES implementation by comparing its output with a Python AES implementation.
```bash
pytest tests.py -vv
```exit
