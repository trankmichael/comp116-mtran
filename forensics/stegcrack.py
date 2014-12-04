#!/usr/bin/python

# usage: ./stegcrack.py stegfile dictionary

import sys, os

def main():
	stegfile_name = sys.argv[1]
	dictionary = open(sys.argv[2])

	for word in dictionary:
		os.system("steghide extract -sf " + stegfile_name + " -p " + word.strip())

if __name__ == "__main__":
	main()