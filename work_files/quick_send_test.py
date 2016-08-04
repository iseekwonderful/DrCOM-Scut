import socket
import time
import random
from threading import Thread


class Receiver(Thread):
    def __init__(self, sock):
        Thread.__init__(self)
        self.sock = sock

    def run(self):
        while True:
            content, addr = sock.recvfrom(2048)
            print("{}: {}".format(content.encode('Hex'), addr))


if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('125.216.238.86', 61440))
    source = "ff 96 45 25 cc 3f 20 be 10 e4 83 5b e5 f5 d7 92 c3 00 00 00 44 72 63 6f ca 26 d2 83 d3 d2 7d d8 ee 56 01 6a 00 00"
    source = source.replace(" ", '')
    source_1 = source[:-8] + "aabb" + source[-4:]
    source_2 = source[:-4] + "aabb"
    source_3 = source[:-20] + "aabb" + source[-16:]
    source_1 = source_1.replace(" ", '')
    source_2 = source_2.replace(" ", '')
    source_3 = source_3.replace(" ", '')
    data = source.decode("hex")
    data_1 = source_1.decode("hex")
    data_2 = source_2.decode("hex")
    data_3 = source_3.decode("hex")
    r = Receiver(sock)
    r.start()
    print("send origin")
    sock.sendto(data, ("202.38.210.131", 61440))
    time.sleep(5)
    print("send M1")
    sock.sendto(data_1, ("202.38.210.131", 61440))
    time.sleep(5)
    print("send M2")
    sock.sendto(data_2, ("202.38.210.131", 61440))
    time.sleep(5)
    print("send M3")
    sock.sendto(data_3, ("202.38.210.131", 61440))
    time.sleep(5)
    print("resend source")
    sock.sendto(data, ("202.38.210.131", 61440))
    time.sleep(10)