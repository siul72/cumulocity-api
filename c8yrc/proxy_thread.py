import logging
import threading
from c8yrc.tcp_socket import TCPServer
logging = logging.getLogger(__name__)


class ProxyThread (threading.Thread):

    def __init__(self, proxy_handler: TCPServer):
        threading.Thread.__init__(self)
        self.tcp_server = proxy_handler

    def run(self):
        try:
            self.tcp_server.start()
        except Exception as ex:
            logging.error(f'Error on TCP-Server {ex}')
        finally:
            self.tcp_server.stop()
            logging.info('exit from proxy thread')

    def stop(self):
        self.tcp_server.stop()
