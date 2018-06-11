Shocker
======================
A tool to find and exploit servers vulnerable to Shellshock

Ref: https://en.wikipedia.org/wiki/Shellshock_(software_bug)

Released as open source by NCC Group Plc - https://www.nccgroup.trust/

Developed By:
* Tom Watson, tom [dot] watson [at] nccgroup [dot] trust

https://github.com/nccgroup/shocker

Released under AGPL see LICENSE for more information

Help Text
-------------
usage: 
shocker.py 

-h, --help            show this help message and exit

--Host HOST, -H HOST
                      A target hostname or IP address

--file FILE, -f FILE  File containing a list of targets

--port PORT, -p PORT  The target port number (default=80)

--command COMMAND     Command to execute (default=/bin/uname -a)

--cgi CGI, -c CGI     Single CGI to check (e.g. /cgi-bin/test.cgi)

--proxy PROXY         *A BIT BROKEN RIGHT NOW* Proxy to be used in the form
                      'ip:port'

--ssl, -s             Use SSL (default=False)

--threads THREADS, -t THREADS
                      Maximum number of threads (default=10, max=100)

--verbose, -v         Be verbose in output

Usage Examples
-------------
`./shocker.py -H 127.0.0.1 --command "/bin/cat /etc/passwd" -c /cgi-bin/test.cgi`

Scans for http://127.0.0.1/cgi-bin/test.cgi and, if found, attempts to cat 
/etc/passwd

`./shocker.py -H www.example.com -p 8001 -s`

Scan www.example.com on port 8001 using SSL for all scripts in cgi_list and
attempts the default exploit for any found

`./shocker.py -f ./hostlist`

Scans all hosts listed in the file ./hostlist with the default options

Dependencies 
-------------
Python 2.7+

Change Log
-------------
Changes in version 1.1 (June 2018)

* Added some additinoal debugging  functionality and corrected help text

Changes in version 1.0 (March 2016)

* Some additional scripts contributed and updates to some comments, URLs and contact details 

Changes in version 0.72 (December 2014)

* Minor corrections to logic and typos

Changes in version 0.71 (December 2014)

* Added timeout to urllib2.urlopen requests using a global 'TIMEOUT'

Changes in version 0.7 (November 2014)

* Add interactive 'psuedo console' for further exploitation of a chosen vulnerable server
* Attemped to clean up output buffering issues by wrapping sys.stdout in a class which flushes on every call to write
* Added a progress indicator for use in time consuming tasks to reassure non vebose users

Changes in version 0.6 (October 2014)

* Preventing return codes other than 200 from being considered successes
* Added ability to specify multiple targets in a file
* Moved the 'cgi_list' list of scripts to attempt to exploit to a file
* Fixed some output formatting issues
* Fixed valid hostname/IP regex to allow single word hostnames

Changes in version 0.5 (October 2014)

* Added ability to specify a single script to target rather than using cgi_list
* Introduced a timeout on socket operations for host_check
* Added some usage examples in the script header
* Added an epilogue to the help text indicating presence of examples

Changes in version 0.4 (October 2014)

* Introduced a thread count limit defaulting to 10
* Removed colour support until I can figure out how to make it work in Windows and *nix equally well
* Spelling corrections
* More comprehensive cgi_list
* Removes success_flag from output

Pre 0.4 (October 2014)

* No idea

TODO
-------------
* Identify and respond correctly to HTTP/200 response - false positives - Low priority/hassle
* Implement curses for *nix systems - For the whole application or only psuedo terminal? - Low priority/prettiness
* Thread the initial host check now that multiple targets are supported (and could be make this bit time consuming)
* Change verbose to integer value - quiet, normal, verbose, debug?
* Add option to skip initial host checks for the sake of speed?
* Add a summary of results before exiting
* Save results to a file? Format?
* Eventually the idea is to include multiple possible vectors but currently only one is checked.
* Add Windows and *nix colour support - Low priority/prettiness
* Add a timeout in interactive mode for commands which don't return, e.g. /bin/cat /dev/zero
* Prettify - Low priority/pretinness (obviously)
* Add support for scanning and explointing SSH and SMTP? https://isc.sans.edu/diary/Shellshock+via+SMTP/18879
* Add SOCKS proxy support, potentially using https://github.com/rpicard/socksonsocks/ from Rober Picard
* Other stuff. Probably.

Thanks to...
-------------
Anthony Caulfield @ NCC for time and effort reviewing early versions

Brendan Coles @ NCC for his support and contributions
