#!/usr/bin/python2

import os
import sys
import string
import socket
import struct
from time import sleep

data = string.digits + string.lowercase + string.uppercase

def server(port, filename):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    s.bind(('0.0.0.0', int(port)))
    s.listen(3)
    
    cs, addr = s.accept()
    print addr
    
    file_size = os.path.getsize(filename)
    send_size = 0

    with open(filename, 'rb') as f:
        while True:
            data = f.read(1024)
            if data:
                send_size += sys.getsizeof(data)
                print '%f%%' % (float(send_size) / file_size)
                cs.send(data)
            else:
                break
            sleep(0.05)
    
    s.close()


def client(ip, port, filename):
    s = socket.socket()
    s.connect((ip, int(port)))
    
    with open(filename, 'wb') as f:
        while True:
            data = s.recv(1024)
            if data:
                f.write(data)
            else:
                break
    
    s.close()

if __name__ == '__main__':
    if sys.argv[1] == 'server':
        server(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == 'client':
        client(sys.argv[2], sys.argv[3], sys.argv[4])
