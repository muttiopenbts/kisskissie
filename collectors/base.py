import asynchat
import asyncore
import socket
import threading


class BaseHandler(asynchat.async_chat):
    def __init__(self, server, conn, addr):
        asynchat.async_chat.__init__(self, conn)
        self.server = server
        self.conn = conn
        self.addr = addr
        self.ibuffer = []
        self.scan_id = None
        self.file_id = None

    def collect_incoming_data(self, data):
        self.ibuffer.append(data)

    def handle_close(self):
        asynchat.async_chat.handle_close(self)

        if self.scan_id is not None and self.server.queue is not None:
            self.server.queue.put({
                'scan_id': self.scan_id,
                'file_id': self.file_id,
                'source_ip': self.addr[0],
                'source_port': self.addr[1],
            })


class BaseServer(asyncore.dispatcher):
    def __init__(self, server_address, handler, output_dir, queue=None):
        asyncore.dispatcher.__init__(self)
        self.handler = handler
        self.output_dir = output_dir
        self.queue = queue

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(server_address)
        self.listen(5)

    def handle_accept(self):
        try:
            conn, addr = self.accept()
        except socket.error:
            return
        except TypeError:
            return

        self.handler(self, conn, addr)


class BaseCollector(threading.Thread):
    def __init__(self, addr, output_dir, queue):
        super(BaseCollector, self).__init__()
        self.addr = addr
        self.output_dir = output_dir
        self.queue = queue
