from struct import pack, unpack
from fcntl import ioctl
import socket
from hashlib import md5
from select import select
import time
import sys


class Utils:
    @staticmethod
    def get_ip_index(sock, iface):
        SIOCGFINDEX = 0x8933
        if_name, index = unpack("16sI", ioctl(
            sock, SIOCGFINDEX, pack("16sI", iface, 0)
        ))
        return index

    @staticmethod
    def get_hw_addr(sock, iface):
        SIOCGIFHWADDR = 0x8927
        if_name, _, hw_addr = unpack("16sH6s", ioctl(
            sock, SIOCGIFHWADDR, pack("16sH6s", iface, 0, '')
        ))
        return hw_addr


class DrComSupplicant:
    def __init__(self, iface, username, password):
        self.ETH_P_PAE = 0x888E
        self.iface = iface
        self.state = 0
        self.username = username
        self.password = password
        self.server_hw_addr = None
        self.sock = socket.socket(17, socket.SOCK_RAW, socket.htons(self.ETH_P_PAE))
        self.sock.bind((iface, 0))
        self.if_index = Utils.get_ip_index(self.sock, self.iface)
        self.hw_addr = Utils.get_hw_addr(self.sock, self.iface)
        self.pae_group_addr = b"\x01\x80\xc2\x00\x00\x03"
        self.last_start = None

    def make_ether_header(self, near=False):
        if near:
            return pack('>6s6sH', self.pae_group_addr, self.hw_addr, self.ETH_P_PAE)
        else:
            return pack('>6s6sH', self.server_hw_addr, self.hw_addr, self.ETH_P_PAE)

    def make_8021x_header(self, x_type, length=0):
        return pack('BBH', 1, x_type, length)

    def make_eap_pkt(self, eap_code, eap_id, eap_data):
        return pack('>BBH%ds' % len(eap_data), eap_code, eap_id, len(eap_data) + 4, eap_data)

    def send_start(self):
        X_TYPE_START = 1
        pkt = self.make_ether_header(near=True) + self.make_8021x_header(X_TYPE_START, 0) + b'\x00' * 78
        self.sock.send(pkt)
        print("Send Start Packet")
        self.last_start = time.time()
        self.state = 0

    def send_logoff(self):
        X_TYPE_START = 2
        if self.server_hw_addr is None:
            pkt = self.make_ether_header(near=True) + self.make_8021x_header(X_TYPE_START, 0)
        else:
            pkt = self.make_ether_header() + self.make_8021x_header(X_TYPE_START, 0)
        self.sock.send(pkt)
        print("Disconnect from Server")
        self.state = 0


    def handle(self):
        # EAP Type and code define
        X_TYPE_EAP_PACKET = 0

        EAP_CODE_REQUEST = 1
        EAP_CODE_RESPONSE = 2
        EAP_CODE_SUCCESS = 3
        EAP_CODE_FAILURE = 4

        EAP_TYPE_IDENTITY = 1
        EAP_TYPE_MD5CHALLENGE = 4

        data = self.sock.recv(65535)
        # print("Received packet length: {}".format(len(data)))

        # Ethernet check
        ether_dst, ether_src, ether_type = unpack('>6s6sH', data[:14])
        # print ether_dst.encode("hex"), self.pae_group_addr.encode("hex")
        if (ether_dst != self.hw_addr and self.state != 10) or ether_type != self.ETH_P_PAE:
            print("Ethernet check failed : dst:{} type: {}".format(
                ether_dst.encode('hex'), ether_type))
            return

        if self.server_hw_addr is None:
            self.server_hw_addr = ether_src
            #print("Server mac address is {}".format(self.server_hw_addr.encode("hex")))

        # 802.1X check
        a_8021x_ver, a_8021x_type, a_8021x_length = unpack('>BBH', data[14:18])
        if a_8021x_ver != 1 and a_8021x_type != 0:
            print('802.1X check failed: ver={} type={}'.format(
                a_8021x_ver, a_8021x_type))
            return

        # EAP length check
        eap_code, eap_id, eap_length = unpack('>BBH', data[18:22])
        # print("code: {}, id: {}, length: {} state: {}".format(eap_code, eap_id, eap_length, self.state))
        if eap_length > len(data) - 18 or eap_length != a_8021x_length:
            print('EAP length check failed: len={} len(802.1X)={}'.format(
                eap_length, a_8021x_length))
            return

        if self.state == 0:
            if eap_code == EAP_CODE_REQUEST and eap_length >= 5:
                eap_type = unpack('B', data[22:23])[0]
                if eap_type == EAP_TYPE_IDENTITY:
                    print("Server->Client: Identify")
                    eap_pkt = self.make_eap_pkt(
                        EAP_CODE_RESPONSE, eap_id,
                        pack('B%ds' % len(self.username), EAP_TYPE_IDENTITY, self.username))
                    pkt = self.make_ether_header() + self.make_8021x_header(
                        X_TYPE_EAP_PACKET, len(eap_pkt))
                    pkt += eap_pkt
                    self.sock.send(pkt)

                    print("Client->Server: ID Response")

                    self.state = 1
            else:
                print("EAP check failed")
        if self.state <= 1:
            if eap_code == EAP_CODE_REQUEST and eap_length >= 5:
                eap_type = unpack('B', data[22:23])[0]
                if eap_type == EAP_TYPE_MD5CHALLENGE:
                    print("Server->client: MD5 Challenge")
                    eap_value_size = unpack('B', data[23: 24])[0]
                    if eap_value_size != eap_length - 10:
                        print('State 1 wrong MD5 challenge eap-Len: {}, value_len: {}'.format(
                            eap_length, eap_value_size))
                        return
                    challenge = data[24: 24 + eap_value_size]
                    response = md5(chr(eap_id) + self.password + challenge).digest()
                    pkt = self.make_ether_header()
                    extra = self.password + '\x00Da*\x00}\xd8\xeeV'
                    eap_pkt = self.make_eap_pkt(EAP_CODE_RESPONSE, eap_id, pack(
                        'BB16s{}s'.format(len(extra)), EAP_TYPE_MD5CHALLENGE, 16, response, extra
                    ))
                    pkt += self.make_8021x_header(X_TYPE_EAP_PACKET, len(eap_pkt))
                    pkt += eap_pkt
                    self.sock.send(pkt)

                    print("Client->Server: Md5 Challenge Response")
                    self.state = 2
                    return
            elif eap_code == EAP_CODE_FAILURE and eap_length == 4:
                print("Wrong identity")
                return
            else:
                print("EAP Identity Check failed")
                return
        elif self.state == 2:
            if eap_code == EAP_CODE_SUCCESS and eap_length == 4:
                print("Success!")
                self.state = 10
            else:
                print("Failed!")
                exit(1)
        elif self.state == 10:
            if eap_code == EAP_CODE_REQUEST and eap_length >= 5:
                eap_type = unpack('B', data[22:23])[0]
                if eap_type == EAP_TYPE_IDENTITY:
                    print("Server->Client: Identify")
                    eap_pkt = self.make_eap_pkt(
                        EAP_CODE_RESPONSE, eap_id,
                        pack('B%ds' % len(self.username), EAP_TYPE_IDENTITY, self.username))
                    pkt = self.make_ether_header() + self.make_8021x_header(
                        X_TYPE_EAP_PACKET, len(eap_pkt))
                    pkt += eap_pkt
                    self.sock.send(pkt)

                    print("Client->Server: ID Response")
            elif eap_code == EAP_CODE_FAILURE:
                self.state = 0
                self.send_start()
            else:
                raise Exception("Unknown packet")

    def run(self):
        for x in range(1):
            self.send_logoff()
            time.sleep(2)
        self.send_start()

        while True:
            r, w, x = select([self.sock], [], [self.sock])
            if x:
                raise Exception("socket Exception")
            self.handle()
            if time.time() - self.last_start and self.state == 0:
                self.send_start()


if __name__ == '__main__':
    if '-h' in sys.argv:
        print("A scut drom supplicant\nusage: python openwrt.py -u username -p password -i iface")
        exit(1)
    else:
        if '-u' not in sys.argv:
            print("Please input a username")
            exit(1)
        if '-i' not in sys.argv:
            print("Please input a interface")
            exit(1)
        if '-p' not in sys.argv:
            print("Please input a password")
            exit(1)
        try:
            username = sys.argv[sys.argv.index('-u') + 1]
            password = sys.argv[sys.argv.index('-p') + 1]
            iface = sys.argv[sys.argv.index('-i') + 1]
        except:
            print("usage: python openwrt.py -u username -p password -i iface\n"
                  "please put parameter after the option like: -u 200011112222")
            exit(1)
    dr = DrComSupplicant(iface, username, password)
    # dr = DrComSupplicant('eth0.2', '201520133579', '201520133579')
    try:
        dr.run()
    except KeyboardInterrupt:
        print("use ended disconnect")
        for x in range(1):
            dr.send_logoff()
