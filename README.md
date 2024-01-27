# SMBeeline
A tool for pillagin smb shares in bulk!

A python script to pillage networks of loose smb shares. The script takes an nmap xml scan file as input and tries to download all the loose info from open shares.
USAGE:
smbeeline.py [path/to/nmap/xml/scan/file] --list (this lists available directories and files).
smbeeline.py [path/to/nmap/xml/scan/file] --pillage (this downloads all the loose files, the files are saved in a folder called "loot" at the location you execute the script in).

Tested against multiple samba shares, windows 7 and windows 10 shares.

Tested on python 3.7.10, chances are it will not run with python 3.8 ->.

supports SMBv1 and SMBv2.

working on support for Python 3.8 ->, and SMBv3 support.

enjoy responsibly!
