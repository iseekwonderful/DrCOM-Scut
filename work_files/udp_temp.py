#!/usr/bin/python
# -*- coding: utf-8 -*-
# By 7forz    https://github.com/7forz

from scapy.all import *
from hashlib import md5
import argparse
import time
import binascii
import socket
import random
import threading

__version__ = '0.2.0'

# 从用户输入获取username password iface
parser = argparse.ArgumentParser(description='802.1x Auth Tool for SCUT DrCOM Protocol')
parser.add_argument('--username', default='', help='the username, cannot be blank')
parser.add_argument('--password', default='', help='if no password is given, will be the same as username')
parser.add_argument('--iface', default='eth0', help='network interface of ethernet, default is eth0')
args = parser.parse_args()

SAVEDUMP = True  # dump pcap file

# 一些常量
EAPOL_ASF = 4
EAPOL_KEY = 3
EAPOL_LOGOFF = 2
EAPOL_START = 1
EAPOL_EAP_PACKET = 0

EAP_FAILURE = 4
EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_TYPE_ID = 1
EAP_TYPE_MD5 = 4

DRCOM_RESPONSE_FOR_ALIVE = '\x02'
DRCOM_RESPONSE_INFO = '\x04'
DRCOM_MISC_TYPE_2 = '\x02'
DRCOM_MISC_TYPE_4 = '\x04'

drcom_pkt_id = 0  # 之后随着发包而增加
misc_random_4bytes = ''  # misc type 1和type 3都要用到
crc_8byte_for_244byte_info = ''  # 244byte和12s alive都要用到

# 获取认证需要的信息
username = args.username
password = args.password
conf.iface = args.iface
MY_INTERFACE = args.iface
MY_IP = get_if_addr(MY_INTERFACE)  # 调用scapy的函数
MY_IP_HEX = socket.inet_aton(MY_IP)  # 这里调用标准库 不要自己造轮子
MY_MAC = get_if_hwaddr(MY_INTERFACE)  # 调用scapy的函数
MY_MAC_HEX = binascii.a2b_hex(MY_MAC.replace(':', ''))  # 转成十六进制的形式
DST_MAC = 'ff:ff:ff:ff:ff:ff'  # 到时改为由request identity数据包中获取服务器的MAC地址
DST_IP_HEX = '\xca\x26\xd2\x83'  # 学校统一的服务器
MY_PC_NAME = socket.gethostname()  # 获得本机的计算机名

pkts = []  # 捕获的包放到该列表，用于dump pcap

p_start = Ether(src=MY_MAC, dst='01:80:c2:00:00:03', type=0x888e) / EAPOL(version=1, type=1, len=0) / \
          Padding(load=78 * '\x00')

p_identity = Ether(src=MY_MAC, dst=DST_MAC, type=0x888e) / EAPOL(version=1, type=0, len=26) / \
             EAP(code=2, type=1, id=1, len=26) / \
             Raw(load=username + '\x00\x44\x61\x00\x00' + MY_IP_HEX) / Padding(load=52 * '\x00')

p_md5 = Ether(src=MY_MAC, dst=DST_MAC, type=0x888e) / EAPOL(version=1, type=0, len=43) / \
        EAP(code=2, type=4, id=0, len=43) / Raw(
    load='\x10' + 'reseverd_for_md5' + username + '\x00Da*\x00' + MY_IP_HEX) / \
        Padding(load=35 * '\x00')

p_logoff = Ether(src=MY_MAC, dst='01:80:c2:00:00:03', type=0x888e) / EAPOL(version=1, type=2, len=0) / \
           Padding(load=78 * '\x00')

p_udp_start = IP(frag=0L, src=MY_IP, proto=17, tos=0, dst='202.38.210.131', len=36, options=[], version=4L,
                 flags=2L, ihl=5L, ttl=64) / UDP(dport=61440, sport=61440, len=16) / \
              Raw(load='\x07\x00\x08\x00\x01\x00\x00\x00')  # 起始包是固定的

p_udp_244byte_info = IP(frag=0L, src=MY_IP, proto=17, tos=0, dst='202.38.210.131', len=272, options=[], version=4L,
                        flags=2L, ihl=5L, ttl=64) / UDP(dport=61440, sport=61440, len=252) / \
                     Raw(load='')  # 这个load之后再回填

p_udp_misc1 = IP(frag=0L, src=MY_IP, proto=17, tos=0, dst='202.38.210.131', len=68, options=[], version=4L,
                 flags=2L, ihl=5L, ttl=64) / UDP(dport=61440, sport=61440, len=48) / \
              Raw(load='')  # load用到时再改

p_udp_misc3 = IP(frag=0L, src=MY_IP, proto=17, tos=0, dst='202.38.210.131', len=68, options=[], version=4L,
                 flags=2L, ihl=5L, ttl=64) / UDP(dport=61440, sport=61440, len=48) / \
              Raw(load='')  # load用到时再改

p_udp_38byte_alive = IP(frag=0L, src=MY_IP, proto=17, tos=0, dst='202.38.210.131', len=66, options=[], version=4L,
                        flags=2L, ihl=5L, ttl=64) / UDP(dport=61440, sport=61440, len=46) / \
                     Raw(load='')  # load用到时再改


def send_start():
    if SAVEDUMP:
        pkts.append(p_start)
    sendp(p_start, verbose=0)  # 静默发送
    print 'SCUTclient: Start.'


def send_identity():
    if SAVEDUMP:
        pkts.append(p_identity)
    sendp(p_identity, verbose=0)
    print 'SCUTclient: Respond Identity.'


def send_md5():
    if SAVEDUMP:
        pkts.append(p_md5)
    sendp(p_md5, verbose=0)
    print 'SCUTclient: Respond MD5-Challenge.'


def send_logoff():
    if SAVEDUMP:
        pkts.append(p_logoff)
    sendp(p_logoff, verbose=0)
    print 'SCUTclient: Logoff.'


def update_md5_packet(server_md5_info):
    global p_md5  # 更改外部变量
    p_md5 = Ether(src=MY_MAC, dst=DST_MAC, type=0x888e) / EAPOL(version=1, type=0, len=43) / \
            EAP(code=2, type=4, id=0, len=43) / \
            Raw(load='\x10' + md5(
                '\x00' + password + server_md5_info).digest() + username + '\x00Da*\x00' + MY_IP_HEX) / \
            Padding(load=35 * '\x00')


def crc_misc_type_3(data):
    """
        计算data的crc，其中data是 '\xab\xcd' 的形式
        reference: https://github.com/drcoms/drcom-generic/blob/master/analyses/d_keep_alive2.md
    """
    temp = 0
    for i in range(len(data))[::2]:
        temp ^= struct.unpack('H', data[i:i + 2])[0]
    result = struct.pack('I', temp * 711)
    return result


def _crc_drcom(data):  # 由crc_drcom_info_hostname()调用
    result = 0
    for i in range(0, len(data), 4):
        ee = data[i:i + 4]
        result ^= struct.unpack('<I', ee)[0]
        result &= 0xFFFFFFFF
    return result


def crc_drcom_info_hostname(data):  # 外部调用的是这个函数
    crc = (_crc_drcom(data) * 19680126) & 0xFFFFFFFF
    return struct.pack('<I', crc)  # 大小端反过来


def send_udp_start():  # 或者叫request for alive
    if SAVEDUMP:
        pkts.append(p_udp_start)
    send(p_udp_start, verbose=0)
    print 'DrCOM Client: Send request alive.'


def send_udp_computerinfo():
    if SAVEDUMP:
        pkts.append(p_udp_start)
    send(p_udp_244byte_info, verbose=0)
    print 'DrCOM Client: Send information.'


def send_udp_misc1():
    if SAVEDUMP:
        pkts.append(p_udp_misc1)
    send(p_udp_misc1, verbose=0)
    print 'DrCOM Client: Send misc type 1'


def send_udp_misc3():
    if SAVEDUMP:
        pkts.append(p_udp_misc3)
    send(p_udp_misc3, verbose=0)
    print 'DrCOM Client: Send misc type 3'


def send_udp_38byte_alive():
    global p_udp_38byte_alive
    p_udp_38byte_alive.load = '\xff' + crc_8byte_for_244byte_info + p_md5.load[5:17] + 3 * '\x00' + \
                              '\x44\x72\x63\x6f' + DST_IP_HEX + '\x2e\x63' + MY_IP_HEX + '\x41\x68' + '\x00\x00'

    if SAVEDUMP:
        pkts.append(p_udp_38byte_alive)
    send(p_udp_38byte_alive, verbose=0)
    print 'DrCOM Client: Send alive per 12s'


def update_udp_misc1():
    global misc_random_4bytes  # 更改全局变量
    misc_random_4bytes = chr(random.randint(0, 255)) + chr(random.randint(0, 255)) + \
                         chr(random.randint(0, 255)) + chr(random.randint(0, 255))  # 更新4字节的随机值 在2次对话中不变
    global p_udp_misc1  # 更改全局变量
    p_udp_misc1.load = '\x07' + chr(drcom_pkt_id) + '\x28\x00\x0b\x01\xdc\x02' + misc_random_4bytes + 28 * '\x00'
    global drcom_pkt_id
    drcom_pkt_id += 1  # 对话id加1  发送包前先加保证比收到misc 2早


def update_udp_misc3():
    temp = '\x07' + chr(drcom_pkt_id) + '\x28\x00\x0b\x03\x0f\x27' + \
           misc_random_4bytes + 12 * '\x00' + 4 * '\x00' + MY_IP_HEX + 8 * '\x00'  # 4个\x00是因为到时算出4字节crc要填回这个位置
    crc = crc_misc_type_3(temp)
    global p_udp_misc3  # 更改全局变量
    p_udp_misc3.load = '\x07' + chr(drcom_pkt_id) + '\x28\x00\x0b\x03\x0f\x27' + \
                       misc_random_4bytes + 12 * '\x00' + crc + MY_IP_HEX + 8 * '\x00'
    global drcom_pkt_id  # 更改全局变量
    drcom_pkt_id += 1  # 对话id加1  先加保证比收到misc 4早


def alive_per_12s():
    while True:  # 作为一个死循环的线程运行
        time.sleep(9)  # misc 4 后延迟9秒
        send_udp_38byte_alive()
        time.sleep(3)  # 再延时3秒
        update_udp_misc1()  # 发起新一轮的1234对话
        send_udp_misc1()


def sniff_handler(pkt):
    if SAVEDUMP:
        pkts.append(pkt)
    try:
        if pkt.haslayer(EAP) and (pkt[EAP].code == EAP_REQUEST) and (pkt[EAP].type == EAP_TYPE_ID):  # 避免pkt[EAP]不存在时出错
            print 'Server: Request Identity!'
            global DST_MAC  # 在函数内更改外部变量
            DST_MAC = pkt.src  # 把目标MAC改为服务器的MAC
            p_identity.dst = DST_MAC
            p_md5.dst = DST_MAC
            p_identity[EAP].id = pkt[EAP].id  # id要对应，话说以前的版本(pyscutclient)从来不改id也能稳定过认证...
            send_identity()

        elif pkt.haslayer(EAP) and (pkt[EAP].code == EAP_REQUEST) and (pkt[EAP].type == EAP_TYPE_MD5):
            print 'Server: Request MD5-Challenge!'
            server_md5_info = pkt[EAP].load[1:17]  # 提取服务器给出的16字节md5信息 第1个字节是长度要跳过
            update_md5_packet(server_md5_info)  # 使用这个信息更新md5包
            send_md5()

        elif pkt.haslayer(EAP) and (pkt[EAP].code == EAP_SUCCESS):
            print 'Server: Success.'
            send_udp_start()  # 当802.1x验证通过后 马上开始udp认证

        elif pkt.haslayer(EAP) and (pkt[EAP].code == EAP_FAILURE):
            print 'Server: Failure.\nWill retry after 5 seconds.\n'
            time.sleep(5)
            send_start()

        elif pkt.haslayer(UDP) and pkt.dport == 61440 and pkt[UDP].len == 40 and pkt.load[
            4] == DRCOM_RESPONSE_FOR_ALIVE:
            # 这里是udp服务器回应的第一个包 需要提取4字节challenge seed 生成244字节的数据 再求crc 最后回填
            print 'DrCOM: Response for alive!'
            challenge_seed = pkt.load[8:12]  # 提取服务器给出的4byte challenge_seed

            # 这里保证是244 byte 填入challenge_seed和特定的8字节后算crc
            udp_244byte_info = '\x07\x01\xf4\x00\x03\x0c' + MY_MAC_HEX + MY_IP_HEX + '\x02\x22\x00\x2a' + \
                               challenge_seed + '\xc7\x2f\x31\x01\x7e\x00\x00\x00' + username + \
                               MY_PC_NAME + (32 - len(MY_PC_NAME)) * '\x00' + \
                               '\xca\x26\xc1\x21' + 36 * '\x00' + 'DrCOM\x00\xcf\x07\x2a\x00' + 54 * '\x00' + \
                               '915e3d0281c3a0bdec36d7f9c15e7a16b59c12b8' + 24 * '\x00'
            global crc_8byte_for_244byte_info
            crc_8byte_for_244byte_info = crc_drcom_info_hostname(udp_244byte_info)  # 马上计算crc 之后回填
            global p_udp_244byte_info
            p_udp_244byte_info.load = '\x07\x01\xf4\x00\x03\x0c' + MY_MAC_HEX + MY_IP_HEX + '\x02\x22\x00\x2a' + \
                                      challenge_seed + crc_8byte_for_244byte_info + 4 * '\x00' + username + \
                                      MY_PC_NAME + (32 - len(MY_PC_NAME)) * '\x00' + \
                                      '\xca\x26\xc1\x21' + 36 * '\x00' + 'DrCOM\x00\xcf\x07\x2a\x00' + 54 * '\x00' + \
                                      '915e3d0281c3a0bdec36d7f9c15e7a16b59c12b8' + 24 * '\x00'  # 这里保证是244 byte
            send_udp_computerinfo()

        elif pkt.haslayer(UDP) and pkt.dport == 61440 and pkt.load[4] == DRCOM_RESPONSE_INFO:   # 0x04
            print 'DrCOM Server: Response info!'
            time.sleep(random.uniform(1, 1.2))  # 抓包出来的延时量有一点不一样 所以加个随机
            update_udp_misc1()
            send_udp_misc1()

        elif pkt.haslayer(UDP) and pkt.dport == 61440 and pkt.load[4] == DRCOM_MISC_TYPE_2:
            print 'DrCOM Server: Misc Type 2'
            update_udp_misc3()
            send_udp_misc3()

        elif pkt.haslayer(UDP) and pkt.dport == 61440 and pkt.load[4] == DRCOM_MISC_TYPE_4:
            print 'DrCOM Server: Misc Type 4'
            try:
                assert t  # 第一次强行使它出错进入except创建线程 之后就不会再重新创建了
            except BaseException:
                t = threading.Thread(target=alive_per_12s)  #
                t.setDaemon(True)  # 后台运行
                t.start()

    except BaseException as e:  # 捕获所有异常
        print 'Error:', e


if __name__ == '__main__':
    if not username:
        print '\nUsage: sudo python pyscutclient_drcom.py --username USERNAME [--password PASSWORD] [--iface IFACE]'
        exit(1)
    if not password:
        password = username
    try:
        print '\n'
        print '=' * 60
        print '\n    pyscutclient_drcom by 7forz\n'
        print '  Project page at https://github.com/scutclient/pyscutclient_drcom'
        print '=' * 60
        print '\nConfirm your MAC: %s' % MY_MAC
        print 'Confirm your IP: %s' % MY_IP

        send_start()
        sniff(filter="ether proto 0x888e || udp port 61440", prn=sniff_handler)  # 捕获802.1x和udp端口61440，捕获到的包给handler处理
    except KeyboardInterrupt as e:
        print e, '用户手动停止'
    finally:
        send_logoff()  # 退程序时强制logoff
        if SAVEDUMP:
            wrpcap('pyscutclient_drcom.cap', pkts)