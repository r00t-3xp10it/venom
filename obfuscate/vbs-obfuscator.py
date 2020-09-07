#!/usr/bin/python
"""
Author: r00t-3xp10it [SSA RedTeam @2020]
Framework: Venom v1.0.17 - vbs-obfuscator.py
Description: Use this script to encrypt one
existing .vbs payload using random ancii chars

"""


## Dependencies 'import'
import random, sys, string, time


## Script colors
WHITE = '\033[1m\033[0m'
GREEN = '\033[1m\033[92m'
YELLOW = '\033[1m\033[93m'
RED = '\033[1m\033[91m'
BLUE = '\033[1m\033[94m'


## Script banner
banner = """
 +------------------------------------------------+
 |               * vbs-obfuscator *               |
 | Obfuscate .VBS files using random ANCII chars  |
 +------------------------------------------------+
	 """
print(BLUE + banner)


## Dependencies checks
# params: Script-name, input-file, output-file
if len(sys.argv) <> 3:
	print(RED + "[ERROR] Usage: " + YELLOW + "python vbs-obfuscator.py infile.vbs outfile.vbs" + WHITE)
	sys.exit()

	
print(YELLOW + "Obfuscating " + sys.argv[1] + " payload!")
print(BLUE + "--------------------------------")
time.sleep(3.5)

## Randomize each character
splitter = str(chr(42))
def randCapitalization(characters):
	capicharacter = ""
	for character in characters:
		lowup = random.randrange(0,2)
		if lowup == 0:
			capicharacter += character.upper()
		if lowup == 1:
			capicharacter +=  character.lower()
	return capicharacter


## Random function names
NUM_OF_CHARS = random.randrange(5, 60)
pld = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(NUM_OF_CHARS))
array = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(NUM_OF_CHARS))
temp = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(NUM_OF_CHARS))
x = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(NUM_OF_CHARS))

## Store in encBody the obfuscated content
def obfu(body):
	encBody = ""
	for i in range(0, len(body)):
		if encBody == "":
			encBody += expr(ord(body[i]))
		else:
			encBody += "*" + expr(ord(body[i]))
	return encBody

def expr(char):
	range = random.randrange(100, 10001)
	exp = random.randrange(0, 3)

	if exp == 0:
		print "Char " + str(char) + " -> " + str((range+char)) + "-" + str(range)
                time.sleep(0.05)
		return str((range+char)) + "-" + str(range)
	if exp == 1:
		print "Char " + str(char) + " -> " + str((char-range)) + "+" + str(range)
		return str((char-range)) + "+" + str(range)
	if exp == 2:
		print "Char " + str(char) + " -> " + str((char*range)) + "/" + str(range)
		return str((char*range)) + "/" + str(range)


## Write to destination file
clear_text_file = open(sys.argv[1], "r")
obfuscated_file = open(sys.argv[2], "w")
obfuscated_file.write(randCapitalization("Dim " + pld + ", " + array + ", " + temp) + "\n")
obfuscated_file.write(randCapitalization(pld + " = ") + chr(34) + obfu(clear_text_file.read()) + chr(34) + "\n")
obfuscated_file.write(randCapitalization(array + " = Split(" + pld + ", chr(eval(") + obfu(splitter) + ")))\n")
obfuscated_file.write(randCapitalization("for each " + x + " in " + array) + "\n")
obfuscated_file.write(randCapitalization(temp + " = " + temp + " & chr(eval(" + x) + "))\n")
obfuscated_file.write(randCapitalization("next") + "\n")
obfuscated_file.write(randCapitalization("execute(" + temp) + ")\n")

## Close file handles before exit
clear_text_file.close()
obfuscated_file.close()
print("--------------------------------" + YELLOW)
print("payload " + BLUE + sys.argv[1] + YELLOW + " successfully obfuscated!")
time.sleep(2.6)
