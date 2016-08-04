# -*- coding: utf-8 -*-

from threading import Thread
import socket
import time
import random
import binascii
from select import select
import struct

DRCOM_RESPONSE_FOR_ALIVE = '\x02'
DRCOM_RESPONSE_INFO = '\x04'
DRCOM_MISC_TYPE_2 = '\x02'
DRCOM_MISC_TYPE_4 = '\x04'


class UDPConnectionManager(Thread):
    def __init__(self, udp_delegate):
        Thread.__init__(self)
        self.udp_delegate = udp_delegate
        self.challenge_res = 0

    def wait_to_misc_loop(self):
        time.sleep(2)
        while self.udp_delegate.state == 2:
            if self.challenge_res < 3:
                print("[!!UDP]: Resend CRC Response")
                self.udp_delegate.send_udp_computerinfo(self.udp_delegate.current_crc_load)
                self.challenge_res += 1
                time.sleep(2)
            else:
                print("[!!UDP]: Try send Keep-Alive")
                self.udp_delegate.update_udp_misc1()
                self.udp_delegate.send_udp_misc1()
                return

    def run(self):
        self.wait_to_misc_loop()


class UDPKeepAlive(Thread):
    def __init__(self, username, password, md5_load, ip, mac):
        Thread.__init__(self)
        # A UDP Socket
        self.username = username
        self.password = password
        self.md5_load = md5_load
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # School's Auth Server
        self.DST_ADDRESS = ("202.38.210.131", 61440)
        self.DST_IP = self.DST_ADDRESS[0]
        self.DST_IP_HEX = socket.inet_aton(self.DST_IP)
        self.DST_PORT = self.DST_ADDRESS[1]
        # My network config
        self.MY_IP = ip
        self.MY_IP_HEX = socket.inet_aton(self.MY_IP)
        self.MY_MAC = mac
        self.MY_MAC_HEX = binascii.a2b_hex(self.MY_MAC.replace(':', ''))  # 转成十六进制的形式
        self.udp_sock.bind((self.MY_IP, self.DST_PORT))
        self.MY_PC_NAME = "PC-" + self.username
        # state
        self.is_init_done = False
        self.should_listen = True
        # attributes
        self.drcom_pkt_id = 0
        self.p_udp_misc1 = ""
        self.p_udp_misc3 = ""
        self.misc_random_4bytes = ''  # misc type 1和type 3都要用到
        self.crc_8byte_for_244byte_info = ''  # 244byte和12s alive都要用到
        self.state = 0
        self.current_crc_load = ''
        # manager
        self.udp_manager = UDPConnectionManager(self)
        self.udp_manager.daemon = True
        # print("UDP init: username: {}\npassword: {}\ndst_address: {}\ndst_port: {}\nself_ip: {}\nself_mac:{}\n".format(
        #     self.username, self.password, self.DST_IP, self.DST_PORT, self.MY_IP, self.MY_MAC
        # ))
        self.keep_alive_info2 = None

    def run(self):
        print("[UDP]: Start to udp keep-alive")
        self.send_udp_start()
        self.listen()

    def listen(self):
        try:
            while self.should_listen:
                r, w, x = select([self.udp_sock], [], [self.udp_sock])
                if x:
                    raise Exception("socket Exception")
                self.handle()
        except KeyboardInterrupt:
            print("End udp thread")
            exit()

    def restart(self):
        self.udp_manager = UDPConnectionManager(self)
        self.state = 0
        self.should_listen = True
        self.send_udp_start()
        self.listen()

    def send_udp(self, data, dst_addr):
        self.udp_sock.sendto(data, dst_addr)

    def crc_misc_type_3(self, data):
        """
            计算data的crc，其中data是 '\xab\xcd' 的形式
            reference: https://github.com/drcoms/drcom-generic/blob/master/analyses/d_keep_alive2.md
        """
        temp = 0
        for i in range(len(data))[::2]:
            temp ^= struct.unpack('H', data[i:i + 2])[0]
        result = struct.pack('I', temp * 711)
        return result

    def _crc_drcom(self, data):  # 由crc_drcom_info_hostname()调用
        result = 0
        for i in range(0, len(data), 4):
            ee = data[i:i + 4]
            result ^= struct.unpack('<I', ee)[0]
            result &= 0xFFFFFFFF
        return result

    def crc_drcom_info_hostname(self, data):  # 外部调用的是这个函数
        crc = (self._crc_drcom(data) * 19680126) & 0xFFFFFFFF
        return struct.pack('<I', crc)  # 大小端反过来

    def send_udp_start(self):  # 或者叫request for alive
        self.send_udp('\x07\x00\x08\x00\x01\x00\x00\x00', self.DST_ADDRESS)
        print '[UDP]: DrCOM Client: Send request alive.'

    def send_udp_computerinfo(self, load):
        self.send_udp(load, self.DST_ADDRESS)
        print '[UDP]: DrCOM Client: Send information.'

    def send_udp_misc1(self):
        self.send_udp(self.p_udp_misc1, self.DST_ADDRESS)
        print '[UDP]: DrCOM Client: Send misc type 1'

    def send_udp_misc3(self):
        self.send_udp(self.p_udp_misc3, self.DST_ADDRESS)
        print '[UDP]: DrCOM Client: Send misc type 3'

    # '\x2e\x63' -> '\x1c\x84'
    # '\x41\x68\x00\x00' -> '\x01\xd2\x99\x18'
    def send_udp_38byte_alive(self):
        # print("sented md5 is {}".format(self.md5_load[5:17].encode("hex")))
        try:
            load = '\xff' + self.crc_8byte_for_244byte_info + self.md5_load[5:17] + 3 * '\x00'\
                + self.keep_alive_info2 + '\x00\x00'
        except:
            print("[Critical]: Server Reject Due to auth left in server, retry in few minutes")
            exit(1)

        self.send_udp(load, self.DST_ADDRESS)
        print '[UDP]: DrCOM Client: Send alive per 12s'

    def request_unknown_content(self):
        self.misc_random_4bytes = chr(random.randint(0, 255)) + chr(random.randint(0, 255)) + \
                             chr(random.randint(0, 255)) + chr(random.randint(0, 255))  # 更新4字节的随机值 在2次对话中不变
        self.p_udp_misc1 = '\x07' + chr(self.drcom_pkt_id) + '\x28\x00\x0b\x01\x0f\x27' + self.misc_random_4bytes + 28 * '\x00'
        self.drcom_pkt_id += 1  # 对话id加1  发送包前先加保证比收到misc 2早

    # middle bytes from '\x28\x00\x0b\x01\x0f\x27' to '\x28\x00\x0b\x01\xdc\x02'
    def update_udp_misc1(self, current_random_bytes=False):
        self.misc_random_4bytes = chr(random.randint(0, 255)) + chr(random.randint(0, 255)) + \
                             chr(random.randint(0, 255)) + chr(random.randint(0, 255))  # 更新4字节的随机值 在2次对话中不变
        self.p_udp_misc1 = '\x07' + chr(self.drcom_pkt_id) + '\x28\x00\x0b\x01\xdc\x02' + self.misc_random_4bytes + 28 * '\x00'
        self.drcom_pkt_id += 1  # 对话id加1  发送包前先加保证比收到misc 2早

    def update_udp_misc3(self, former):
        temp = '\x07' + chr(self.drcom_pkt_id) + '\x28\x00\x0b\x03\xdc\x02' + \
               self.misc_random_4bytes + 12 * '\x00' + 4 * '\x00' + self.MY_IP_HEX + 8 * '\x00'  # 4个\x00是因为到时算出4字节crc要填回这个位置
        crc = self.crc_misc_type_3(temp)
        self.p_udp_misc3 = '\x07' + chr(self.drcom_pkt_id) + '\x28\x00\x0b\x03\xdc\x02' + \
                           self.misc_random_4bytes + 4 * '\x00' + former + 4 * '\x00' + crc + self.MY_IP_HEX + 8 * '\x00'
        self.drcom_pkt_id += 1  # 对话id加1  先加保证比收到misc 4早

    def alive_per_12s(self):
        time.sleep(9)  # misc 4 后延迟9秒
        self.send_udp_38byte_alive()
        time.sleep(3)  # 再延时3秒
        self.update_udp_misc1()  # 发起新一轮的1234对话
        self.send_udp_misc1()

    def handle(self):
        data, addr = self.udp_sock.recvfrom(2048)
        # print("receive {} from {} len: {}".format(data.encode("hex"), addr, len(data)))
        if addr != self.DST_ADDRESS:
            return
        if addr[1] == self.DST_PORT and data[4] == DRCOM_RESPONSE_FOR_ALIVE:
            # This is the server's challenge
            print("[UDP]: DrCOM: Response for alive!")
            #print("Args: {}, {}, {}, {}".format(self.MY_IP_HEX, self.MY_MAC_HEX, self.username, self.MY_PC_NAME))
            challenge_seed = data[8:12]
            # 915e3d0281c3a0bdec36d7f9c15e7a16b59c12b8 to 9435ae04da51e672cdba11bdd90e5d00638fb25b
            # '\xc7\x2f\x31\x01\x7e\x00\x00\x00' to '\xd0\xe5\xa4\x3a\x00\x00\x00\x00'
            # '\xca\x26\xc1\x21' to '\x00\x00\x00\x00'
            # udp_244byte_info = '\x07\x01\xf4\x00\x03\x0c' + self.MY_MAC_HEX + self.MY_IP_HEX + '\x02\x22\x00\x2a' + \
            #                     challenge_seed + '\xc7\x2f\x31\x01\x7e\x00\x00\x00' + self.username + \
            #                     self.MY_PC_NAME + (32 - len(self.MY_PC_NAME)) * '\x00' + \
            #                     '\x00\x00\x00\x00' + 36 * '\x00' + 'DrCOM\x00\xcf\x07\x2a\x00' + 54 * '\x00' + \
            #                     '9435ae04da51e672cdba11bdd90e5d00638fb25b' + 24 * '\x00'
            udp_244byte_info = '\x07\x01\xf4\x00\x03\x0c' + self.MY_MAC_HEX + self.MY_IP_HEX + '\x02\x22\x00\x2a' + \
                               challenge_seed + '\xc7\x2f\x31\x01\x7e\x00\x00\x00' + self.username + \
                               self.MY_PC_NAME + (32 - len(self.MY_PC_NAME)) * '\x00' + \
                               '\x00\x00\x00\x00' + 35 * '\x00' + '\x02DrCOM\x00\xcf\x07\x2a\x00' + "\x31\x35\x2e\x36\x2e\x30" + \
                               48 * '\x00' + '9435ae04da51e672cdba11bdd90e5d00638fb25b' + 24 * '\x00'

            self.crc_8byte_for_244byte_info = self.crc_drcom_info_hostname(udp_244byte_info)  # 马上计算crc 之后回填
            load = '\x07\x01\xf4\x00\x03\x0c' + self.MY_MAC_HEX + self.MY_IP_HEX + '\x02\x22\x00\x2a' + \
                    challenge_seed + self.crc_8byte_for_244byte_info + 4 * '\x00' + self.username + \
                    self.MY_PC_NAME + (32 - len(self.MY_PC_NAME)) * '\x00' + \
                   '\x00\x00\x00\x00' + 35 * '\x00' + '\x02DrCOM\x00\xcf\x07\x2a\x00' + \
                   "\x31\x35\x2e\x36\x2e\x30" + 48 * '\x00' + '9435ae04da51e672cdba11bdd90e5d00638fb25b' +\
                   24 * '\x00'  # 这里保证是244 byte
            self.current_crc_load = load
            self.send_udp_computerinfo(load)
            self.state = 2
            self.udp_manager.start()

        elif addr[1] == self.DST_PORT and (data[4] == DRCOM_RESPONSE_INFO or data[5] == '\x06'):
            print("[UDP]: DrCOM Server: Response Info, send misc")
            time.sleep(random.uniform(1, 1.2))
            # so here we need keep_alive_2
            info_2 = [0 for _ in range(16)]
            info_1 = data[16:]
            for x in range(16):
                info_2[x] = ((ord(info_1[x]) << (x & 7)) + (ord(info_1[x]) >> (8 - (x & 7)))) % 256
            keep_alive2 = "".join(["{:02X}".format(x) for x in info_2])
            self.keep_alive_info2 = keep_alive2.decode("hex")
            # print("[Important]: Keep-Alive info 2: {}".format(self.keep_alive_info2.encode("hex")))
            # if self.is_init_done:
            #     if data[5] == '\x06':
            #         self.update_udp_misc1(current_random_bytes=True)
            #     else:
            #         self.update_udp_misc1()
            # else:
            #     self.request_unknown_content()
            self.update_udp_misc1()
            self.send_udp_misc1()
            self.is_init_done = True
            self.state = 4

        elif addr[1] == self.DST_PORT and data[5] == DRCOM_MISC_TYPE_2:
            print("[UDP]: DrCOM Server: MISC 2 data: {}".format(data[16: 20].encode("hex")))
            self.update_udp_misc3(data[16: 20])
            self.send_udp_misc3()

        elif addr[1] == self.DST_PORT and data[5] == DRCOM_MISC_TYPE_4:
            print("[UDP]: DrCOM Server: MISC 4")
            self.drcom_pkt_id = 0
            self.alive_per_12s()


if __name__ == '__main__':
    udp = UDPKeepAlive("eth0.2", "201520133579", "201520133579")
    udp.start()