from BaseHTTPServer import BaseHTTPRequestHandler
import urlparse
from BaseHTTPServer import HTTPServer
import string
from Queue import Queue
from KissKissieBase import KissKissieBase

class DtdServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        parsed_path = urlparse.urlparse(self.path)
        self.server._queue_message['scan_id'] = self.server.getScanIdFromUrl(parsed_path.query)
        self._template_name = self.server.template_name
        self._file = self.server.getTemplate(self._template_name)
        self.wfile.write(self._file)
        self.server.sendMessageToQueue()

    def log_message(self, format, *args):
        if self.server.debug:
            BaseHTTPRequestHandler.log_message(self, format, *args)
        return
    
    def __example_do_GET(self):
        if self.server.debug:
            parsed_path = urlparse.urlparse(self.path)
            message_parts = [
                    'CLIENT VALUES:',
                    'client_address=%s (%s)' % (self.client_address,
                                                self.address_string()),
                    'command=%s' % self.command,
                    'path=%s' % self.path,
                    'real path=%s' % parsed_path.path,
                    'query=%s' % parsed_path.query,
                    'request_version=%s' % self.request_version,
                    '',
                    'SERVER VALUES:',
                    'server_version=%s' % self.server_version,
                    'sys_version=%s' % self.sys_version,
                    'protocol_version=%s' % self.protocol_version,
                    '',
                    'HEADERS RECEIVED:',
                    ]
            for name, value in sorted(self.headers.items()):
                message_parts.append('%s=%s' % (name, value.rstrip()))
            message_parts.append('')
            message = '\r\n'.join(message_parts)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(message)

class DtdServer(HTTPServer, KissKissieBase):
    def __init__(self, queue, collector_url, port=80, host='', template_name='', debug=False):
        KissKissieBase.__init__(self, queue, debug)
        HTTPServer.__init__(self, (host, port), DtdServerHandler)
        self._port = port
        self._collector_url = collector_url
        self._host = host
        self._template_name = template_name

    def run(self):
        self.template_name = self._template_name
        self.queue = self._queue
        if self.debug:
            print 'Starting server DTD server %s:%s, use <Ctrl-C> to stop' %(self._host, self._port)
        super(DtdServer, self).serve_forever()
    
    def getTemplate(self, template_name):
        template_tags = {
                'collector_url': self._collector_url,
                }
        t = KissKissieBase.getTemplate(self, template_name, template_tags)
        return t.replace('$scan_id', self._queue_message['scan_id'])
        
