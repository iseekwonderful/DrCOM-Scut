import struct
import re


def crc_drcom(data):
    result = 0
    for i in range(0, len(data), 4):
        ee = data[i:i + 4]
        result ^= struct.unpack('<I', ee)[0]
        result &= 0xFFFFFFFF
    return result


def crc_drcom_info_hostname(data):
    crc = (crc_drcom(data) * 19680126) & 0xFFFFFFFF
    return struct.pack('<I', crc)


def packet_CRC(s):
    ret = 0
    for i in re.findall('..', s):
        ret ^= struct.unpack('>h', i)[0]
        ret &= 0xFFFF
    ret = ret * 0x2c7
    return ret


def convert(challenge_seed, MY_MAC_HEX, MY_IP_HEX, username, MY_PC_NAME):
    udp_244byte_info = '\x07\x01\xf4\x00\x03\x0c' + MY_MAC_HEX + MY_IP_HEX + '\x02\x22\x00\x2a' + \
                       challenge_seed + '\xc7\x2f\x31\x01\x7e\x00\x00\x00' + username + \
                       MY_PC_NAME + (32 - len(MY_PC_NAME)) * '\x00' + \
                       '\x00\x00\x00\x00' + 35 * '\x00' + '\x02DrCOM\x00\xcf\x07\x2a\x00' + "\x31\x35\x2e\x36\x2e\x30" +\
                       48 * '\x00' + '9435ae04da51e672cdba11bdd90e5d00638fb25b' + 24 * '\x00'
    return udp_244byte_info


if __name__ == '__main__':
    #source = "0701f400030cfcaa14eedfb37dd8ee56" + "0222002a" + "b01df501" + "c72f31017e000000" + "32303135323031333335373973686565706465694d61632e6c6f63616c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000024472434f4d00cf072a0031352e362e3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000039343335616530346461353165363732636462613131626464393065356430303633386662323562000000000000000000000000000000000000000000000000"
    #expected = "d0e5a43a"
    source = "ff789e55127f404530db16ec2ede4271ca0000004472636fca26d2835ad27dd8ee5601f10000"
    expected = ""
    converted = convert("\x17\xd1\xfb\x01", "\xfc\xaa\x14\xee\xdf\xb3",
                        "\x7d\xd8\xee\x56", "201520133579", "sheepdeiMac.local")
    print converted.encode("hex")
    print crc_drcom_info_hostname(
        source.decode("hex")
    ).encode("hex")
