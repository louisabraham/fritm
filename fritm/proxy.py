"""
This file implements a MITM (https://en.wikipedia.org/wiki/Man-in-the-middle_attack)
by simulating an HTTP CONNECT tunnel (https://en.wikipedia.org/wiki/HTTP_tunnel)

inspired by https://github.com/inaz2/proxy2/blob/master/proxy2.py
"""

from socketserver import ThreadingMixIn
from http.server import HTTPServer, BaseHTTPRequestHandler
import socket
from threading import Thread, Lock


class ConnectionWrapper:
    """
    Class that wraps a socket and acquires a lock.
    
    When the `.close()` method is called (to close the socket),
    it relases the lock.
    """

    def __init__(self, sock):
        self.socket = sock
        self.lock = Lock()
        self.lock.acquire()

    def wait_until_release(self, blocking=True, timeout=-1):
        self.lock.acquire(blocking, timeout)

    def close(self):
        self.lock.release()

    def __getattr__(self, attr):
        return getattr(self.socket, attr)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Subclass of HTTPServer that inherits from 
    ThreadingMixIn to handle multiple requests at once
    """

    pass


def make_proxy_request_handler(callback):
    """Returns a class inheriting from BaseHTTPRequestHandler
    """

    class ProxyRequestHandler(BaseHTTPRequestHandler):
        def do_CONNECT(self):
            """This method is called when the client tries
            to open a socket through our HTTP tunnel
            """
            # address of the requested socket
            address = self.path.split(":", 1)
            address[1] = int(address[1])
            try:
                soServer = socket.create_connection(address, timeout=self.timeout)
            except Exception as e:
                self.send_error(502)
                return
            self.send_response(200, "Connection Established")
            self.end_headers()

            soClient = ConnectionWrapper(self.connection)

            # The callback function is launched.
            # soClient behaves exactly like a socket
            # but instead of being closed, its .close()
            # method will release the lock.
            callback(soClient, soServer)

            # This waits until the lock is released.
            # The underlying socket will be closed by
            # the TCPServer at the end of do_CONNECT
            soClient.wait_until_release()

            # VERY IMPORTANT to avoid an infinite loop
            self.close_connection = True

    return ProxyRequestHandler


def start_proxy_server(callback, port=8080):
    """Opens an http tunnel
    When a CONNECT request is made, it opens the socket
    to the real address and calls
    `callback(soClient, soServer)`

    Returns an http server that can be closed with
    `httpd.server_close()`
    """
    httpd = ThreadingHTTPServer(
        ("localhost", port), make_proxy_request_handler(callback)
    )
    Thread(target=httpd.serve_forever).start()
    return httpd
