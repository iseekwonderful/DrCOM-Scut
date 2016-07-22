# Created by sheep @ 7.16, 2016
# fill your username, password and network interface when using
# require install scapy
# test passed in OSX 10.11 and raspberry pi 3B with raspbian

from scapy.all import *
from multiprocessing import Process
import hashlib
import time
import sh
import traceback


def get_md5_result(id, md5_data, passwd):
    return hashlib.md5(chr(id) + passwd + md5_data).digest()


class ConnectException(Exception):
    def __init__(self):
        Exception.__init__(self)


class DrComSupplicant(Process):
    def __init__(self, username, password, iface):
        Process.__init__(self)
        self.username = username
        self.password = password
        self.iface = iface
        self.is_start_send = False
        self.is_done = False
        self.last_keep_alive = time.time()

    def _force_disconnect(self):
        for x in range(3):
            sendp(Ether(src=get_if_hwaddr(self.iface))/EAPOL(type=2), verbose=False)
            time.sleep(1)

    def run(self):
        print("Start Connect")
        self._force_disconnect()    # clear the history
        sniff(prn=lambda x: self.handle_packet(x), stop_filter=lambda x: True if self.is_done else False)
        print("Start to keep alive")
        self.keep_alive()

    def send_start(self):
        print("Client -> Nearest: Start")
        sendp(Ether(src=get_if_hwaddr(self.iface))/EAPOL(type=1), verbose=False)    # client seek server

    def send_id_response(self):
        print("Client -> Server: Response, ID")
        data = str(self.username) + chr(0) * 9
        response = Ether(dst=self.dst, src=get_if_hwaddr(self.iface)) / EAPOL(version=1) / \
                   EAP(code=2, id=1, type="ID") / Raw(load=data) / Padding(load=chr(0) * 22)
        sendp(response, verbose=False)

    def send_md5_response(self, md5_req):
        print("Client -> Server: Response, MD5")
        md5_con = '\x10' + get_md5_result(md5_req[0].id, md5_req[0].payload.load[1:17], self.password) + \
                  self.password + '\x00Da*\x00}\xd8\xeeV'
        md5_res = Ether(dst=self.dst, src=get_if_hwaddr(self.iface)) / EAPOL(version=1) / EAP(code=2, id=0, type="MD5") \
                  / Raw(load=md5_con) / Padding(load=chr(0) * 36)
        sendp(md5_res, verbose=False)

    def keep_alive(self):
        while True:
            print("Initiative keep alive...")
            self.send_id_response()
            time.sleep(30)

    def handle_packet(self, packet):
        try:
            if self.is_done and time.time() - self.last_keep_alive > 30:
                print("Initiative keep alive...")
                self.send_id_response()
                self.last_keep_alive = time.time()
            if not self.is_start_send:
                self.send_start()
                self.is_start_send = True
                return
            if not packet.type == 0x888e or not packet.dst == get_if_hwaddr(self.iface):
                return
            # check if ID Request
            if packet[EAP].code == 1 and packet[EAP].type == 1:
                print("Server -> Client: Request, ID")
                self.dst = packet.src
                self.last_keep_alive = time.time()
                return self.send_id_response()
            elif packet[EAP].code == 1 and packet[EAP].type == 4:
                print("Server -> Client: Request, MD5")
                return self.send_md5_response(packet)
            elif packet[EAP].code == 3:
                self.is_done = True
                print("SUCCESS")
        except:
            pass


class AccessControl:
    def __init__(self, username, passwd, iface):
        a = DrComSupplicant(username, passwd, iface)
        a.start()
        # waiting for success
        time.sleep(10)
        while True:
            if not AccessControl.test_access():
                print("ReConnecting ...")
                a.terminate()
                a = DrComSupplicant(username, passwd, iface)
                a.start()
            else:
                print("Test pass {}".format(time.strftime("%b %d %Y %H:%M:%S")))
            time.sleep(5)

    @staticmethod
    def test_access():
        try:
            res = sh.ping("-c", "4", "114.114.114.114")
            result = re.findall(r"(\d) received", str(res))[0]
            if int(result[0]) > 0:
                return True
        except:
            print(traceback.format_exc())
            return False
        else:
            return False


if __name__ == '__main__':
    username = "201520133579"
    passwd = "201520133579"
    # in linux may be ethX, in OSX may be enX
    iface = "eth0.2"
    AccessControl(username, passwd, iface)

