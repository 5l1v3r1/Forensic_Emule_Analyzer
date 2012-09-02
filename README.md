Forensic Emule Analyzer
=======================

Emule Analyzer parses unallocated clusters of EnCase Image Files (*.e01) mounted with Access Data`s FTK Imager for deleted known.met records.

Mount evidence in FTK Imager as

MountType: Physical & Logical 

Mount Method: File System / Read Only (IMPORTANT or FEA will not work!)

Drive Letter: This will be the volume for which EmuleAnalyzer will ask

EmuleAnalyzer searches and parses active know.met files recursively too. FEA analyzes the internal structure of files and so it works with corrupted files or partial files which crash most of the other known.met parser.

Results can be searched for keywords (eg. child porn codewords). Check the included keywords file for instructions how to make keyword files.

All results are written to TAB separated files.
FTK Imager 3.0 or newer required. It is free (as in beer) an can be found at http://accessdata.com/support/product-downloads

Regards to Access Data for making this great tool available for free!

Double-check the results!

Written in Python 3 using PyQT.