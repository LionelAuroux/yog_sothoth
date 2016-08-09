#!/usr/bin/env python3

import socket
import threading
import socketserver
import selectors
import re

class Header:
    pass

class TunnelData:
    def __init__(self, insock, outsock):
        self.insock = insock
        self.outsock = outsock

    def dotunnel(self, sel):
        infd = self.insock.fileno()
        outfd = self.outsock.fileno()
        data = self.insock.recv(1024)
        if len(data) > 0:
            print("%d > %d" % (infd, outfd))
            #print("%s" % repr(data))
            try:
                # have we closed this destination
                print("OUTSOCK %s" % repr(self.outsock))
                sel.get_key(self.outsock)
                self.outsock.sendall(data)
            except KeyError:
                pass
        else:
            print("closing %d" % infd)
            sel.unregister(self.insock)
            sel.unregister(self.outsock)
            self.insock.close()
            self.outsock.close()

class ProxyHandler(socketserver.BaseRequestHandler):

    szpack = 1024
    
    def __init__(self, *args):
        self.meth_proto = {'HEAD': self._fwd, 'GET': self._fwd, 'POST': self._fwd, 'CONNECT': self._fwdssl}
        self.client = None
        socketserver.BaseRequestHandler.__init__(self, *args)

    def _gethead(self):
        msg = Header()
        lscmd = self.data.split(b'\r\n')
        first = lscmd[0].split(b' ')
        msg.headers = dict()
        endidx = lscmd.index(b'')
        for h in lscmd[1:endidx]:
            kv = h.split(b": ")
            msg.headers[kv[0].decode('ascii')] = kv[1].decode('ascii')
        msg.cmd = first[0].decode('ascii')
        msg.url = first[1].decode('ascii')
        m = re.match(r'(?:(?P<proto>https?)://)?(?P<host>[^:/]+)(?::(?P<port>\d+))?(?P<req>/.*)?', msg.url)
        if m is None:
            raise RuntimeError("Bad RE to parse URL")
        msg.proto = 'http'
        if m.group('proto') is not None:
            msg.proto = m.group('proto')
        msg.hostname = m.group('host')
        msg.port = 80
        if m.group('port') is not None:
            msg.port = int(m.group('port'))
        if msg.port == 443 and msg.proto is None:
            msg.proto = 'https'
        msg.req = m.group('req')
        h = vars(msg)
        print(repr(h))
        return msg

    def _getdata(self, readsock):
        data = readsock.recv(ProxyHandler.szpack)
        sz = len(data)
        print("R %d" % sz, end=None)
        if sz != 0:
            while sz == ProxyHandler.szpack:
                d = readsock.recv(ProxyHandler.szpack)
                data += d
                sz = len(d)
                print("R %d" % sz, end=None)
        return data

    def _clientconn(self):
        if self.client is None:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.head.hostname, self.head.port))
        return self.client

    def _fwd(self):
        cs = self._clientconn()
        cs.sendall(self.data)
        self.response = self._getdata(cs)
        #print("--- begin ---")
        #print(repr(self.response))
        #print("--- end ---")
        self.request.sendall(self.response)

    def _fwdssl(self):
        data = b"HTTP/1.1 200 Connection established\r\n\r\n"
        #print("SDATA : %s" % repr(data))
        cs = self._clientconn()
        self.request.sendall(data)
        sel = selectors.DefaultSelector()
        tun_cs2brows = TunnelData(cs, self.request)
        tun_brows2cs = TunnelData(self.request, cs)
        sel.register(cs, selectors.EVENT_READ, tun_cs2brows.dotunnel)
        sel.register(self.request, selectors.EVENT_READ, tun_brows2cs.dotunnel)
        while True:
            events = sel.select()
            for key, mask in events:
                cb = key.data
                cb(sel)
            if len(sel.get_map()) == 0:
                print("End TUNNEL")
                break

    def handle(self):
        cur_th = threading.current_thread()
        print("Th %s" % cur_th.name)
        self.data = self._getdata(self.request)
        if len(self.data) > 0:
            # identify proto
            self.head = self._gethead()
            if self.head.cmd not in self.meth_proto:
                raise ValueError("Not supported method: %s" % self.head.cmd)
            self.meth_proto[self.head.cmd]()

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, *args):
        self.allow_reuse_address = True
        socketserver.TCPServer.__init__(self, *args)
        socketserver.ThreadingMixIn.__init__(self)

if __name__ == "__main__":
    HOST, PORT = "localhost", 8080
    server = ThreadedTCPServer((HOST, PORT), ProxyHandler)
    ip, port = server.server_address
    server_th = threading.Thread(target=server.serve_forever)
    # Exit
    server_th.daemon = True
    server_th.start()
    try:
        server_th.join()
    except KeyboardInterrupt:
        print("Stop")
        server.shutdown()
        server.server_close()
