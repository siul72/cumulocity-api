import logging
import threading

import certifi
import websocket
import ssl
logging = logging.getLogger(__name__)


class WebsocketClient(threading.Thread):

    def __init__(self, host, tenant, config_id, device_id, session, token, ignore_ssl_validate=False, reconnects=5):
        self.host = host
        self.tenant = tenant
        self.config_id = config_id
        self.device_id = device_id
        self.web_socket = None
        self.tcp_server = None
        self._ws_open_event = None
        self._ws_open = False
        self._ws_timeout = 10
        self.wst = None
        self.session = session
        self.trigger_reconnect = True
        self.reconnect_counter = 0
        self.ignore_ssl_validate = ignore_ssl_validate
        self.max_reconnects = reconnects
        self.token = token

    def connect(self):

        self._ws_open_event = threading.Event()
        if self.host.startswith('https'):
            self.host = self.host.replace('https', 'wss')
        elif self.host.startswith('http'):
            self.host = self.host.replace('http', 'wss')
        elif not self.host.startswith('wss://'):
            self.host = f'wss://{self.host}'
        url = f'{self.host}/service/remoteaccess/client/{self.device_id}/configurations/{self.config_id}'
        logging.info(f'Connecting to WebSocket with URL {url} ...')
        headers = {'Content-Type': 'application/json', 'X-XSRF-TOKEN': self.session.cookies.get_dict()['XSRF-TOKEN']}
        cookies = self.session.cookies.get_dict()
        cookie_string = "; ".join([str(x) + "=" + str(y) for x, y in cookies.items()])
        self.web_socket = websocket.WebSocketApp(url, header=headers, cookie=cookie_string)
        self.web_socket.on_message = lambda ws, msg: self._on_ws_message(ws, msg)
        self.web_socket.on_error = lambda ws, error: self._on_ws_error(ws, error)
        self.web_socket.on_close = lambda ws, msg, msg2: self._on_ws_close(ws, msg, msg2)
        self.web_socket.on_open = lambda ws: self._on_ws_open(ws)
        web_socket_kwargs = {'ping_interval': 10, 'ping_timeout': 7}
        if self.ignore_ssl_validate:
            web_socket_kwargs['sslopt'] = {'cert_reqs': ssl.CERT_NONE}
        else:
            web_socket_kwargs["sslopt"] = {"ca_certs": certifi.where()}

        self.wst = threading.Thread(target=self.web_socket.run_forever, kwargs=web_socket_kwargs)
        self.wst.daemon = True
        self.wst.name = f'WSTunnelThread-{self.config_id}'
        self.wst.start()
        return self.wst

    def reconnect(self):
        self.reconnect_counter += 1
        logging.info(f'Reconnecting to WebSocket...')
        if self.web_socket:
            self.web_socket.keep_running = False
            self.web_socket.close()
        self.web_socket = None
        self.connect()

    def stop(self):
        # Closing WebSocket
        # self.tcp_server.stop()
        logging.debug(f'Stopping WebSocket Connection...')
        self.trigger_reconnect = False
        self.tcp_server.stop_connection()
        if self.web_socket:
            self.web_socket.keep_running = False
            self.web_socket.close()
        self.web_socket = None

    def is_ws_available(self):
        if self._ws_open:
            return True
        self._ws_open_event.wait(timeout=self._ws_timeout)
        return self._ws_open

    def _on_ws_message(self, _ws, message):
        try:
            logging.debug(f'WebSocket Message received: {message}')
            if self.tcp_server.is_tcp_socket_connected():
                if self.tcp_server.connection is not None:
                    logging.debug(f'Sending to TCP Socket: {message}')
                    self.tcp_server.connection.send(message)
        except Exception as ex:
            logging.error(f'Error on handling WebSocket Message {message}: {ex}')
            self.stop()

    def _on_ws_error(self, _ws, error):
        logging.debug(f'Type of WS Error {type(error)}')
        if hasattr(error, 'status_code'):
            logging.error(f'WebSocket Error received: {error} with status {error.status_code}')

        if isinstance(error, websocket.WebSocketTimeoutException):
            logging.info(f'Device {self.device_id} seems to be offline. No connection possible.')
        else:
            logging.error(f'WebSocket Error received: {error}')

        self.ws_handshake_error = True
        self._ws_open = False
        self._ws_open_event.set()
        self.stop()

    def _on_ws_close(self, _ws, close_status, close_reason):
        logging.info(f'WebSocket Connection closed. Status: {close_status}, Reason: {close_reason}')
        self._ws_open = False
        self._ws_open_event.set()
        if self.tcp_server.is_tcp_socket_available():
            self.tcp_server.connection.send(b'FIN')
            self.tcp_server.stop_connection()

        if self.trigger_reconnect and self.reconnect_counter < self.max_reconnects:
            logging.info(f'Reconnect with counter {self.reconnect_counter}')
            self.reconnect()
        #else:
        #    os.kill(os.getpid(), signal.SIGUSR1)

    def _on_ws_open(self, _ws):
        logging.info(f'WebSocket Connection opened!')
        self._ws_open = True
        self._ws_open_event.set()
