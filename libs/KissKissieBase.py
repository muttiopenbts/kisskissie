"""
Simple tcp client that reads a template file, replaces contained tags and sends the contents to a destination server.
Results are sent to a message queue.
"""
from Queue import Queue
import sys
import uuid
import string
import re
import threading

class KissKissieBase(object):
    def __init__(self, queue=None, debug=False):
        self._queue = queue
        self._queue_message = {
            'scan_id':None, 
            'status':None, 
            'victim_host':None, 
            'data':None, 
            'type':None, 
            'sender':type(self).__name__, 
            'recipient': None, 
            'exfiltrate_filename':None, 
            'count': 1,
        }
        self.debug=debug
        self.lock = threading.Lock()
        self.timeout = 10
        
    def generateScanID(self):
        id = self.__generateScanID__()
        self._queue_message['scan_id'] =  id
        return id
        
    def __generateScanID__(self):
        id = str(uuid.uuid4())
        return id

    def run(self):
        self.generateScanID()

    def sendMessageToQueue(self, queue_message={'scan_id':None, 'exfiltrate_filename':None,'data':None,'victim_host':None  }):
        if queue_message['scan_id'] is None:
            self._queue.put(self._queue_message)
        else:
            self._queue.put(queue_message)
        
    def receiveMessageFromQueue(self):
        message = self._queue.get()

    def getScanIdFromText(self, url):
        if not url == '' or not url == None:
            str = url
            match = re.search('.*scan_id=(.+?)/', str)
            if match:
                return match.group(1)

    def getExfiltrateFromData(self, payload='GET /scan_id=ramdom_id/exfiltrate_start=some data \nexfiltrate_end'):
        '''
        Will try to extract exfil data from string using start and end markers.
        Sometimes the socket connection may timeout and the end marker may be missing so just return as much data available.
        '''
        str = payload
        try:
            match = re.search('.*exfiltrate_start=(.*)exfiltrate_end', str, re.DOTALL)
            if match:
                return match.group(1)
        except:
            pass
        try:
            match = re.search('.*exfiltrate_start=(.*)', str, re.DOTALL)
            if match:
                return match.group(1) + "\n===========SESSION CUT SHORT==========="
        except:
            pass

    def getScanIdFromUrl(self, url_query):
        return self.__getScanIdFromUrl(url_query)
        
    def __getScanIdFromUrl(self, url_query):
        '''
        Retrieve scan_id from query string sent to server. '''
        from urlparse import parse_qs
        try:
            r = parse_qs(url_query, keep_blank_values=True)
            scan_id = r['scan_id'][0]
        except:
            scan_id = "None"
        return scan_id
        
    def getTemplate(self, template_name, template_tags):
        '''Open a template file that contains tag placements and replace 
        tags with user specified words.
        '''    
        try:
                file = open(template_name, 'r')
                t = string.Template(file.read())
                self._file = t.safe_substitute(template_tags)
                return self._file
        except:
            pass
        try:
                file = open(template_name.encode('string-escape'), 'r')
                t = string.Template(file.read())
                self._file = t.safe_substitute(template_tags)
                return self._file
        except:
            raise
