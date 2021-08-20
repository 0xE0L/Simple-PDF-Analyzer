# Simple-PDF-Analyzer
```
   _____ _                 __           ____  ____  ______    ___                __                     
  / ___/(_)___ ___  ____  / /__        / __ \/ __ \/ ____/   /   |  ____  ____ _/ /_  ______  ___  _____
  \__ \/ / __ `__ \/ __ \/ / _ \______/ /_/ / / / / /_______/ /| | / __ \/ __ `/ / / / /_  / / _ \/ ___/
 ___/ / / / / / / / /_/ / /  __/_____/ ____/ /_/ / __/_____/ ___ |/ / / / /_/ / / /_/ / / /_/  __/ /    
/____/_/_/ /_/ /_/ .___/_/\___/     /_/   /_____/_/       /_/  |_/_/ /_/\__,_/_/\__, / /___/\___/_/     
                /_/                                                            /____/                   
```

## What?

Simple-PDF-Analyzer (SPA) is a script aimed at inspecting PDF files to detect malicious or suspect ones.
It will notably extract and print JavaScript code contained in a PDF so that a analyzer can review it, because malicious PDF documents often relies on JS codes to perform their actions (like executing malicious JS code or exploiting vulnerabilities in PDF readers to install an implant).

The purpose of the script is to be simple, easy to use and to assist in the analysis of a PDF document.
It highlights/extracts interesting parts from a PDF file and show them to a reverse-engineer/forensic analyst that will review these parts manually.

Thus, it's made for cybersecurity insiders and does NOT have automatic analysis / verdict functionalities: if you're looking for this, you might wanna use an antivirus or VirusTotal (if your PDF document isn't confidential)! You also might wanna take a look to projects like [PeePDF](https://github.com/jesparza/peepdf).

## Supported functionalities

Supported functionalities at the moment:
- Unpack and extract all FlateDecode objects present in PDF.
- Specifically extract JavaScript codes embedded in PDF and output them beautifully, so you can review them manually. \
  The extracted code can also be written to .js files.
- Extract text present in the PDF file (latin text only, quick'n'dirty-like).

## Requirements

SPA relies on [jsbeautifier](https://pypi.org/project/jsbeautifier/) Python library to output the JavaScript code beautifully. \
So, requirements are:
```pip3 install jsbeautifier```

## Usage
```./spa.py file_to_analyze.pdf```

## How it works?

First of all, I'd like to thank SentinelOne for [their article](https://www.sentinelone.com/blog/malicious-pdfs-revealing-techniques-behind-attacks/) that explain very well how stuff works. The script they show was used as a starting point to make SPA.

PDF documents relies on Adobe PostScript (a page description language) to display their content. In a few words, it notably uses tags - as HTML language does - except it's a way more advanced/complex language. But let's focus only on interesting parts (for us), they won't be too complicated.

A PDF/PostScript code contains many entities called "objects", than can be anything (text, image, code etc). It's declared using tags similar to this: `42 0 obj`, where "42" is the object's ID. Every object has an unique ID.

In our case, we're particularly looking for "FlateDecode" objects, because JavaScript code is stored in this kind of objects. FlateDecode objects are storing their content in a compressed/packed way, using classical "Deflate" algorithm. So we will simply parse these objects and unpack their content using zlib!
Except from JavaScript code, FlateDecode objects will often contain the text of the PDF document.

Basically, to unpack JavaScript code, here's what needs to be done:
1) First, we have to identify which FlateDecode objects contain JavaScript code. They can be identified by looking for their declaration, that have a pattern similar to this:  `<</S/JavaScript/JS 253 0 R>>` --> in this case we know object "253" is unpackable JavaScript code.

2) Then, we have to find where is stored the compressed content associated to this object.
The content/compressed code is not necessarily located NEXT to the declaration, it can be located further away in the document! If we know object `253` is JavaScript code, we can locate its content by finding a pattern similar to this: `253 0 obj`.

3) Once you've located this pattern, the raw data we're looking for should be located just after, between object's tags named "stream" and "endstream".
4) So we just take this raw data, unpack it with zlib, beautify it, then print it. We've extracted our JavaScript code.

It's all about parsing and unpacking, it can be done manually by searching for these patterns in the document, however it quickly becomes tedious... That's why this script does it for you!

It's not explained here, but the script also use FlateDecode objects to extract the text of the document. If you want more details about it, read the code that is heavily commented so that you can quickly understand how it works.

## Improvements

Improvements that should/could be made in the future:
- Decode non-latin characters (cyrillic, sinograms, kanji etc).
- Allow the user to select custom options using arguments, instead of executing all options (might or might not be done as I want to keep it quick'n'simple).
