# Functional Encryption

## 1. Introduction

This is the course project for CMPT 789: `Applied Cryptography`. This project is to implement a special type of `functional encryption`: `inner product encryption`.

For an overview of `functional encryption` and my implementation of `DDH`, please refer to my [presentation](/demo/ProjectPresentation.pdf).

**Topics:** _Cryptography_, _Functional Encryption with Inner Products_

**Skills:** _C++_, _gmp library_

## 2. How to run the code

**Prerequisite:** Please make sure that you have installed the `gmp` library for large integer arithmetic. You can install the `gmp` library by running the following command:

`sudo apt-get install libgmp3-dev`

After that, open the terminal on Ubuntu system. Execute the command `g++ -o FE FE.cpp -lgmp` to compile the code and generate the executable file.

Then, run the command `./FE` to see the outcomes.

## 3. Demo

![FE Demo](/demo/FE.gif)
