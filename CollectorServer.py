from socket import *
import thread
from Queue import Queue
from KissKissieBase import KissKissieBase

class CollectorServer(KissKissieBase):
    """
    """

    def __init__(self, queue, timeout=10, port=80, host='', debug=False):
        super(CollectorServer, self).__init__(queue, debug)
        self._port = port
        self._buffer_size = 4096
        self._host = host
        self._log_file = 'log.txt'
        if queue:
            self._queue = queue
    
    def response(self, key):
        return 'Server response: ' + key

    def handler(self,clientsock,addr):
        clientsock.settimeout(self.timeout)
        print("Collector handler...")
        try:
            data = ''
            while True:
                received_data = None
                received_data = clientsock.recv(self._buffer_size)
                if not received_data: break
                data += received_data
            if self.debug:
                print "Collector received %s"%data
            print("Collector received %s"%data)
        except Exception as e:
            if self.debug:
                print e
        finally:
            clientsock.close()
            self.processCollectedData(data,clientsock,addr)

    def processCollectedData(self, data, clientsock, addr):
        queue_message = {}
        with self.lock:
            queue_message['scan_id'] = self.getScanIdFromText(data)
            queue_message['data'] = self.getExfiltrateFromData(data)
            queue_message['victim_host'] = addr[0]
            queue_message['sender'] = self._queue_message['sender']
            print "Process collected data"
            self._queue.put(queue_message)

    def logit(self):
        try:
            output_file = open(self._log_file, "a", 0)
            output_file.write(data)
            output_file.close()
        except e:
            print e

    def run(self):
        ADDR = (self._host, self._port)
        serversock = socket(AF_INET, SOCK_STREAM)
        serversock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        serversock.bind(ADDR)
        serversock.listen(0)
        
        if self.debug:
            print 'Starting Collector Server, listening on port: %s\n' % self._port
        while True:
            if self.debug:
                print 'waiting for connection to Collector...'
            clientsock, addr = serversock.accept()
            if self.debug:
                print 'Collector...connected from: ', addr 
            thread.start_new_thread(self.handler, (clientsock, addr))

    def stop(self):
        socket.socket(socket.AF_INET, 
                      socket.SOCK_STREAM).connect( ('127.0.0.1', self._port))
        self.socket.close()
