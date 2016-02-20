"""
Simple tcp client that reads a template file, replaces contained tags and sends the contents to a destination server.
Results are sent to a message queue.
"""
from Queue import Queue
import sys
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
        tags with user specified words.'''
        with open(template_name) as f:
            t = string.Template(f.read())
            out = t.safe_substitute(template_tags)

            if template_name.endswith('.http'):
                split = out.split('\r\n', 1)
                if len(split) != 2:
                    split = out.split('\n\n', 1)

                headers = {}
                unsplit_headers = split[0].splitlines()
                for h in unsplit_headers:
                    h = h.split(':')
                    headers[h[0].strip()] = h[1].strip()

                return headers, split[1]
            else:
                return {}, out
