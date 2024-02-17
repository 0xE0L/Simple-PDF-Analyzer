#!/usr/bin/python3

# Requirements: "pip3 install jsbeautifier"

### Imports

import sys
import os.path
import string
import re
import zlib
import codecs
import jsbeautifier

### Definitions / settings

keywords_list = ["/JS ", "/JavaScript"] # to be scanned by find_pattern()
separ_line_len = 60 # number of '-' printed when outputting decoded data

### Functions

# Function that can be used to do the equivalent of a "strings" command
# Not really useful as for now, reserved for future use
# Usage: strings_wrapper(string FILENAME, int MINIMUM_STRING_LENGTH)
# Exemple: strings_wrapper(filename, 10)

def strings(filename, min=6):
    with open(filename, errors="ignore") as file:
        result = ""
        for c in file.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:
            yield result

def strings_wrapper(filename, min=6):
    for i in strings(filename, min):
        print(i)

# Function that can be used to find a keyword in the PDF file, as a command "grep -a 'keyword' file.pdf" would do
# Can be case-sentitive (3rd arg to True) or not (3arg to False). No case-sentitivity is default behavior.
# Usage: find_pattern(string FILENAME, string KEYWORD/PATTERN, bool caseSensitivity)

def find_pattern(filename, pattern, caseSensitivity=False):
    search_pattern = ""
    if not caseSensitivity:
        search_pattern = "(?i)"
    search_pattern += pattern

    regex = re.compile(search_pattern)
    line_counter = 0
    match_counter = 0
    with open(filename, errors="ignore") as file:
        for line in file:
            line_counter += 1
            for match in re.finditer(regex, line):
                match_counter += 1
                print("[+] Found keyword '"+pattern+"' line "+str(line_counter)+": ", "'"+line[:-1]+"'")

    if not match_counter:
        print("[-] No match found for keyword '"+pattern+"'...")

# Function used to unpack ALL "/FlateDecode" objects of a PDF file
# These objects are containing data (can be text, JavaScript code etc) that is compressed using classical Deflate algorithm, so it can be unpacked using zlib!
# Here's how works parsing: 1) find a "FlateDecode" object, 2) take all data contained between "stream" and "endstream" tags, 3) unpack this data with zlib, then 4) print the result

# In the meantime, it will try to extract text present in unpacked data and return it as a string. It will use regex to parse and extract characters
# For example, here's how text looks like in depacked data: "[(H)5(el)6(l)5(o wo)3(r)-3(l)5(d)]" --> we should obtain "Hello world"
# The method we'll use is quick'n'dirty and is NOT perfect NOR exhaustive. It's just meant to give you an insight of what text is in the document without having to open it...

# As for now it seems to only support latin characters, because unfortunately some accents and alphabets (like cyrillic, sinograms, kanji etc) are written in another format
# For example, for "Hello" you'll have something like this: [(H)5(el)6(l)5(o)]. But for "Привет" you'd have this: [<0249026A>3<0262>5<025C025F026C>] (notice 1 char = 2 bytes, like in Unicode for example)
# It doesn't seems to be classical Unicode nor UTF-XX encoding, I didn't find which one it is... I guess it's maybe specific to PDF format
# If someone knows, help would be appreciated! Waiting for an improvment/solution, sorry for all non-latin fellows!

# Usage: unpack_flatedecode_and_extract_text(string FILENAME, bool TEXT_ONLY)
# With 2nd arg "bool TEXT_ONLY" set to True, this function won't print output (= decoded data) but will only extract text
# Return value: string containing extracted text

def unpack_flatedecode_and_extract_text(filename, txtOnly=False):
    with open(filename, "rb") as file:
        pdf = file.read()

    # FlateDecode-parsing regexes
    flateDecode_headers = re.compile(rb'.*FlateDecode.*').findall(pdf) # regex used to find FlateDecode objects' headers
    flateDecode_data = re.compile(rb'.*?FlateDecode.*?stream([\s\S]*?)endstream', re.S) # regex used to find FlateDecode objects' data

    # Text-parsing regexes
    regex1 = re.compile(rb'\[(.*?)\]') # match everything between [] (step 1)
    regex2 = re.compile(rb'\((.*?)\)') # then match everything between () (step 2)
    
    # Decoding loop
    extracted_text = b''
    i = 0
    for data in flateDecode_data.findall(pdf):
        if not txtOnly: print("-"*separ_line_len)
        if not txtOnly: print("[*] Header "+str(i)+":", flateDecode_headers[i])
        if not txtOnly: print("-"*separ_line_len)
        i += 1
        
        data = data.strip(b'\r\n')
        #if not txtOnly: print("[+] Compressed data:", data) # can be used for debugging
        #if not txtOnly: print("-"*separ_line_len)

        try:
            dezipped = zlib.decompress(data)
            if not txtOnly: print("[+] Unpacked data:", dezipped)
            if not txtOnly: print("-"*separ_line_len, "\n")
        except:
            if not txtOnly: print("[-] Zlib couldn't unpack this one. :( Skipping...")
            if not txtOnly: print("-"*separ_line_len, "\n")
            continue

        # Text extraction
        for stage1 in regex1.findall(dezipped):
            # Pre-processing where we replace characters '(', ')' and '\' by some alias, in order to avoid issues in parsing / matching
            stage1 = stage1.replace(b'\\\\', b'BACK_SLSH')
            stage1 = stage1.replace(b'\\(', b'PAR_OPEN')
            stage1 = stage1.replace(b'\\)', b'PAR_CLOSE')
            
            for stage2 in regex2.findall(stage1):
                extracted_text += stage2

    # Post-processing in final text where we replace aliases by corresponding character (as parsing and matching are now finished we can do it without any issue)
    extracted_text = extracted_text.replace(b'BACK_SLSH', b'\\')
    extracted_text = extracted_text.replace(b'PAR_OPEN', b'(')
    extracted_text = extracted_text.replace(b'PAR_CLOSE', b')')
    return extracted_text

# Function used to unpack / extract ONLY JAVASCRIPT "/FlateDecode" objects of a PDF file
# Usage: spot_extract_javascript(string FILENAME, bool EXTRACT_TO_FILE)
# If the 2nd argument is set to True, extracted JavaScript will be displayed AND written to a file (default). If it's set to False, it will only be displayed.

def unpack_javascript(pdf, jsObjectID, extractToFile):
    # Step 2 - Find where the content of an object is located and unpack it
    # For example, for objectID '251' we'll have to find this line --> "251 0 obj" (= pattern is "$objectID 0 obj")
    # Then we'll just have to take what's between "stream/endstream" tags located just after, and we'll unpack it!
    # Precisely, here's how content should be parsed: "$objectID 0 obj stream >>> CONTENT <<< endstream endobj"
    flateDecode_data = re.compile(jsObjectID + rb' 0 obj[\s\S]*?stream([\s\S]*?)endstream[\s\S]*?obj')

    # Normally, one result only should be returned (so "flateDecode_data.findall(pdf)[0]" would have been sufficient), but just in case there's some problem with the regex it will let us see...
    for content in flateDecode_data.findall(pdf):
        content = content.strip(b'\r\n')
        print("-"*separ_line_len)
        
        try:
            dezipped = zlib.decompress(content)
        except:
            print("[-] Zlib couldn't unpack this JavaScript object. :( Skipping...\n")
            print("-"*separ_line_len, "\n")
            continue

        beautiful_code = jsbeautifier.beautify(dezipped.decode('utf-8'))

        # Write code to file (if option enabled)
        if extractToFile:
            filename = os.path.splitext(os.path.basename(sys.argv[1]))[0]
            filename += "_extracted" + jsObjectID.decode('utf-8') + ".js"
            with open(filename, "w") as file:
                file.write(beautiful_code)
        
        # Print the code
        print("[+] Unpacked code:", beautiful_code)
        print("-"*separ_line_len, "\n")

def spot_extract_javascript(filename, extractToFile=True):
    # Step 1 - Figure out what objects are JavaScript objects that can be unpacked, and save their number/ID
    # We do that by looking at their declaration. For example:
    #    <</S/JavaScript/JS 253 0 R>> --> unpackable JS, objectID "253"
    #    <</JavaScript 251 0 R/EmbeddedFiles 243 0 R>>  --> unpackable JS, objectID "251"
    with open(filename, "rb") as file:
        pdf = file.read()
    
    regex1 = re.compile(rb'\/JavaScript[\S\s]*?>>') # pre-match header of all potential JS objects
    regex2 = re.compile(rb'\/JavaScript.*?([1-9][0-9]*).*?>>') # extract object's ID from the header
    regex3 = re.compile(rb'(?<=[<])[0-9A-F]+(?=[>])') # extract inline hexstrings encoded like <HEXSTRING>

    noResultFound = True
    for jsObjectHeader in regex1.findall(pdf):
        
        jsObjectHeader = jsObjectHeader.replace(b'\r', b'').replace(b'\n', b'') # we temporarily remove '\r' and '\n' characters from the header before making the string comparison
        
        # only JS objects ending with "R>>" seems to be unpackable
        if jsObjectHeader[-3:] == b'R>>':
            noResultFound = False
            jsObjectID = regex2.findall(jsObjectHeader)[0]
            print("-"*separ_line_len)
            print("[+] Found JavaScript object number:", jsObjectID.decode('utf-8'))
            unpack_javascript(pdf, jsObjectID, extractToFile)

        # try find hex strings encoded
        hexStrings = regex3.findall(jsObjectHeader)
        if hexStrings:
            noResultFound = False
            for hexStr in hexStrings:
                print("[+] Decoded hex string:\n-----\n%s-----" % bytes.fromhex(hexStr.decode()).decode('utf-8'))

    if noResultFound:
        print("[-] Looks like this PDF doesn't contain JavaScript code!")

# Function used to decode characters like latin accents that may be present in the text
# For example, will replace "\351" by 'é' character ("\351" --> chr(0o351) --> 'é')

def text_postprocessing(text):
    ESCAPE_SEQUENCE_RE = re.compile(r'''
        ( \\U........      # 8-digit hex escapes
        | \\u....          # 4-digit hex escapes
        | \\x..            # 2-digit hex escapes
        | \\[0-7]{1,3}     # Octal escapes
        | \\N\{[^}]+\}     # Unicode characters by name
        | \\[\\'"abfnrtv]  # Single-character escapes
        )''', re.UNICODE | re.VERBOSE)

    def decode_match(match):
        return codecs.decode(match.group(0), 'unicode-escape', errors="ignore")
    
    return ESCAPE_SEQUENCE_RE.sub(decode_match, text)

# Function that verifies if a given file is indeed a PDF or not, by checking its magic bytes "%PDF"
# Particularity of PDF format is that those magic bytes aren't necessarily at the very beginning of the file, but can be kind of placed anywhere in its first 1024 bytes
# So this function will scan first 1024 bytes of a file looking for those bytes, if it finds them it's a PDF, if it doesn't it's not...
# Sources: https://exiftool.org/forum/index.php?topic=9086.msg46901#msg46901 AND https://stackoverflow.com/a/32179564

# Usage: isPDFdocument(string FILENAME)
# Return value: True if it's a PDF, False otherwise

def isPDFdocument(filename):
    with open(filename, 'rb') as file:
        pdf_begin = file.read(1024) # read only first 1024 bytes
    if b'%PDF' not in pdf_begin:
        return False
    return True

### Main

if __name__ == "__main__":
    # Verifying arguments
    
    if (len(sys.argv) < 2):
        print("Usage:", sys.argv[0].split('\\')[-1], "file-to-scan.pdf")
        exit(1)

    if not os.path.exists(sys.argv[1]):
        print("[!] Error: file doesn't exist")
        exit(1)

    if not isPDFdocument(sys.argv[1]):
        print("[!] Error: this file doesn't seem to be a PDF document")
        print("If you want to scan it anyway (at your own risk), you can remove this disclaimer by deleting the call to isPDFdocument()")
        exit(1)

    # Beginning real work
    print("##### Pattern matching #####\n")
    for keyword in keywords_list:
        find_pattern(sys.argv[1], keyword, False)
        print("")
    print("")

    #

    print("##### Unpack all data (decompress all FlateDecode objects) #####\n")
    extracted_text = unpack_flatedecode_and_extract_text(sys.argv[1], False)
    print("")

    print("##### Extracted text (from dezipped content) #####\n")
    if extracted_text != b'':
        decoded_text = extracted_text.decode("latin1")
        print("[+] Extracted text:", "'"+text_postprocessing(decoded_text)+"'\n")
    else:
        print("[-] This document doesn't contain compressed text\n")
    print("")

    #
    
    print("##### Find and unpack JavaScript code #####\n")
    spot_extract_javascript(sys.argv[1], True)
    print("")
