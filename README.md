phpchecker
==========

This is a simple shell script that checks for possibly malicious php files on a filesystem.

I made this script as an attempt to fetch anomalies on a webserver which I administer as an attempt to locate various webshells and whatnot.
It actually turned out to be quite useful and as such I thought I'd share it.



Chmod it to 700 (or something similar).

Usage: backdoorcheck.sh <options>

Options are:

-b			Enable checking for raw bytestreams to the browser.
-f <folder>	Only check folder instead of the whole file system.
-h			This cruft.
-l <list>	Enable additional checks from a list.
-o <file>	The output file
-s <file>	Enable statistics (will be generated in file).
