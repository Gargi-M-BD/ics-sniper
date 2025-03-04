# File Name: extractPatterns.py
# Author: Gargi Mitra
# Command Syntax: python3 extractPatterns.py  -i <path to input file> -o <path to output file>
# prereq: sudo pip3 install pycryptodome, matplotlib, pandas

import io
import os
import sys
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import csv
from datetime import datetime
import statistics
from itertools import groupby


def read_sequence(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read().strip()
            number_list = [int(num.strip()) for num in content.split(',')]

        return number_list

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
        return None
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return None
######################################## Cycle Detection Algo Starts Here ###########################################
#####################################################################################################################

def find_indices(lst, element):
    indices = []
    for i in range(len(lst)):
        if lst[i] == element:
            indices.append(i)
    # print(len(lst))
    # print(indices)
    return indices

################################################################################
def detect_subsequences(seq, counters, subseqlist, ctrlist):
    # print("Starting to detect subsequences")
    # print(seq)

    elem = seq[-1]

    rep = 1
    found_subseq = False

    idx = len(seq)-1
    idx1=0 # Initialization
    # print(idx)

    elemidx = find_indices(seq[:-1],elem) # list of indices of all elements in seq that equal elem
    # print(elemidx)

    lastidx = 0

    for ctr in range(len(elemidx)-1,0,-1):

        idx1 = elemidx[ctr]
        idx_diff = idx - idx1
        subseq_len = sum([float(x) * float(y) for x, y in zip(counters[idx1+1:idx+1], [len(sublist) for sublist in seq[idx1+1:idx+1]])]) # possible subsequence length

        rem_seq_len = sum([float(x) * float(y) for x, y in zip(counters[0:idx1+1], [len(sublist) for sublist in seq[0:idx1+1]])]) # to check if even subsequence match checking is possible

        if rem_seq_len >= subseq_len and subseq_len > 1:
            if (seq[idx1-idx_diff+1:idx1+1]==seq[idx1+1:idx+1]) and (counters[idx1-idx_diff+1:idx1+1]==counters[idx1+1:idx+1]):
                subseq = seq[idx1+1:idx+1]
                rep = rep + 1
                subseqlist.insert(0,subseq)
                ctrlist.insert(0,rep)

                idx = idx1
                found_subseq = True
                # print("Found subseq")
                # print(subseq)
                break

    while found_subseq==True:
        idx1 = idx - len(subseq)
        if (seq[idx1-len(subseq)+1:idx1+1]==seq[idx1+1:idx+1]) and (counters[idx1-len(subseq)+1:idx1+1]==counters[idx1+1:idx+1]):
            ctrlist[0] = ctrlist[0] + 1
            lastidx = idx1-len(subseq)
            idx = idx1
        else:
            found_subseq = False


    seq = seq[0:lastidx+1]
    # print(seq)
    counters = counters[0:lastidx+1]

    if len(seq) >= 4:
        detect_subsequences(seq, counters,subseqlist,ctrlist)

    return subseqlist, ctrlist

################################################################################

def detect_cycle(lser,outputfilename):

    print("Starting Cycle Analysis...")

    subsequences, counts = detect_subsequences(lser, [1]*len(lser),[],[])
    print("Patterns for VPN traffic")
    for idx in range(0,len(counts)):
        print(subsequences[idx], counts[idx])
    with open(outputfilename,'w') as outfile:
        outfile.write('Subsequence, Number of repetitions\n')
        for idx in range(0,len(counts)):
            outfile.write(str(subsequences[idx])+', '+str(counts[idx])+'\n')
    return

##################################################################################################################################################
##################################################################################################################################################
# Arguments to be read from command line
args = [('o', 'o', 'o')]

# Checking if all variables are/will be set
for var, env, arg in args:
    if not '-'+arg in sys.argv:
        vars()[var] = os.getenv(env)
        if vars()[var] == None:
            print('Input/Output file not specified')

# Read parameters from command line call
if len(sys.argv) != 0:
    i = 0
    options = sys.argv[1:]
    # iterate through parameters
    while i < len(options):
        if options[i] == '-i':
                i = i + 1
                inputfilename = options[i]
        elif options[i] == '-o':
                i = i + 1
                outputfilename = options[i]
        else:
            print('Error: Unknown Argument! '+ options[i])
        i = i + 1

###################################################################################
print("Starting pre-processing stage")


# Considering only unidirectional messages. Each message gets a response too. Therefore, the original pattern length will be double that of tlslenseq

tlslen = read_sequence(inputfilename)

tlslenseq = [[num] for num in tlslen]

detect_cycle(tlslenseq,outputfilename)
