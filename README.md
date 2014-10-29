Shocker
======================
A tool to find and exploit servers vulnerable to Shellshock

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed By:
* Tom Watson, tom [dot] watson [at] nccgroup [dot] com

https://github.com/nccgroup/shocker

Released under AGPL see LICENSE for more information

Help Text
-------------
usage: 
shocker.py 

-h, --help            show this help message and exit

--Hostname HOSTNAME, -H HOSTNAME
                      A target host

--file FILE, -f FILE  File containing a list of targets

--port PORT, -p PORT  The target port number (default=80)

--exploit EXPLOIT, -e EXPLOIT
                      Command to execute (default=/bin/uname -a)

--cgi CGI, -c CGI     Single CGI to check (e.g. /cgi-bin/test.cgi)

--proxy PROXY         *A BIT BROKEN RIGHT NOW* Proxy to be used in the form
                      'ip:port'

--ssl, -s             Use SSL (default=False)

--threads THREADS, -t THREADS
                      Maximum number of threads (default=10, max=100)

--verbose, -v         Be verbose in output

Usage Examples
-------------
`./shocker.py -H 127.0.0.1 -e "/bin/cat /etc/passwd" -c /cgi-bin/test.cgi`

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
* Thread the initial host check now that multiple targets are supported (and could be make this bit time consuming)
* Add option to skip initial host checks for the sake of speed?
* Add some slightly more useful exploitation options. (Shells?)
* Add a summary of results before exiting
* Save results to a file? Format?
* Eventually the idea is to include multiple possible vectors but currently only one is checked.
* Implement some form of progress indicator for slow tasks
* Fix problem with proxy returning 200 for unavailable URLs/false positives
* Add Windows and *nix colour support
* Prettify
* Add support for scanning and explointing SSH and SMTP? https://isc.sans.edu/diary/Shellshock+via+SMTP/18879
* Other stuff. Probably.

Thanks to...
-------------
Anthony Caulfield @ NCC for time and effort reviewing early versions
