from scapy.all import *
import binascii
import copy

import threading


def binary_to_string(binary_data):
    # 将二进制数据转换为可见的十六进制字符串表示
    hex_str = binascii.hexlify(binary_data).decode('ascii')
    return hex_str


def string_to_binary(hex_str):
    # 将可见的十六进制字符串表示转换回二进制数据
    binary_data = binascii.unhexlify(hex_str.encode('ascii'))
    return binary_data


def ip_to_hex(ip):
    # 将IP地址转换为二进制格式
    packed_ip = socket.inet_aton(ip)
    # 将二进制格式的IP地址转换为十六进制字符串
    hex_ip = packed_ip.hex()
    return hex_ip


class PppoeClient:
    def __init__(self, iface="eth0", smac="00:11:22:33:44:55", user="test", pwd="test"):
        self.iface = iface
        self.smac = smac
        self.user = user
        self.pwd = pwd
        self.lcp_ack = 0
        self.lcp_id = 1
        self.ipcp_id = 1
        self.pap_id = 0
        self.ipcp_flag = 0
        self.ipcp_ip = "0.0.0.0"
        self.ipcp_dns = "0.0.0.0"
        self.reply_magic_number = ""
        self.send_packet_flag = 1

    def random_magic_number(self, len=8):
        return "".join(random.sample("0123456789abcdef0123456789abcdef", len))

    def random_hostuiq(self):
        return "0103000c" + "".join(random.sample("0123456789abcdef0123456789abcdef", 24))

    def send_packet(self, pkt, iface, flag=0):
        sendp(pkt, iface=iface)

    def hex2bin(self, hexstr):
        len_str = len(hexstr)
        retStr = ""
        for i in range(0, len_str, 2):
            substr = chr(int(hexstr[i:i + 2], 16))
            retStr = retStr + substr
        return retStr

    def bin2hex(self, binstr):
        hexstr = "".join(map(lambda x: "%02X" % (ord(x)), list(binstr)))
        return hexstr

    def str2hex(self, allstr):
        return "".join(map(lambda x: "%02X" % (ord(x)), list(allstr)))

    def send_padi_packet(self):
        """01010000表示server-name为空"""
        loadbin = "01010000" + self.random_hostuiq()
        loadbin = string_to_binary(loadbin)
        padi_discover = Ether(src=self.smac, dst="ff:ff:ff:ff:ff:ff") / \
                        PPPoED(version=1, type=1, code=9, sessionid=0, len=len(loadbin)) / Raw(load=loadbin)
        self.send_packet(padi_discover, iface=self.iface)

    def sniff_and_process(self):
        filter = "!(dns)&&!(tcp)&&!(stp)&&!(lldp)&&!(nbns)&&!(llmnr)&&!(ssdp)&&!(dhcpv6)&&!(browser)"
        sniff(lfilter=lambda d: d.dst == self.smac, prn=self.detect_pppoeclient, iface=self.iface)

    def detect_pppoeclient(self, pkt):
        _type = {
            0x8863: {
                'code': {
                    0x07: self.send_padr_packet,
                    0x65: self.config_lcp_packet
                }
            },
            0x8864: {
                # lcp proto packet
                'proto': {
                    0xc021: self.config_lcp_packet,
                    0xc223: self.send_chap_packet,
                    0xc023: self.send_pap_packet,
                    0x0021: self.send_ip_packet,
                    0x8021: self.send_ipcp_packet,
                    0x8057: self.send_ipv6cp_paket
                }
            }
        }
        if pkt.type in _type.keys():
            # 得到的数据包为PPPOE协议封装的数据包
            _methoddict = _type[pkt.type]
            for k, v in _methoddict.items():
                _kVal = getattr(pkt, k)
                if _kVal in _methoddict[k].keys():
                    _obj = _methoddict[k][_kVal]
                    _obj(pkt)

    def send_padr_packet(self, pkt):
        """解析pado报文，得到ac-cookies然后发送出去"""
        loadbin = "01010000" + self.random_hostuiq()
        pppoe_tags = pkt[PPPoED][PPPoED_Tags]
        for tag in pppoe_tags.tag_list:
            if tag.tag_type == 0x0102:
                "ac-name"
                pass
            elif tag.tag_type == 0x0103:
                "hostuniq"
                pass
            elif tag.tag_type == 0x0104:
                loadbin = loadbin + "0104{:04x}".format(tag.tag_len) + binary_to_string(
                    tag.tag_value)
            elif tag.tag_type == 0x0101:
                "service-name"
                pass

        loadbin = string_to_binary(loadbin)
        raw = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src, type=pkt[Ether].type) / \
              PPPoED(version=1, type=1, code=0x19, sessionid=0, len=len(loadbin)) / Raw(load=loadbin)
        self.send_packet(raw, iface=self.iface)

    def config_lcp_packet(self, pkt):
        # 需要处理lcp请求和lcp-replay
        # lcp请求
        if pkt.type == 0x8863:
            # 0104 05d4 MRU=1492 pap=0304 c023 magicnum=0506
            hexdata = "010405d4" + "0304c023" + "0506" + self.random_magic_number(8)
            loadbin = string_to_binary(hexdata)
            length = len(loadbin) + 4
            # 构建整个PPPoE LCP包
            lcp_request = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoED(version=0x1, type=0x1, code=0x00,
                                                                                sessionid=pkt.sessionid) / PPP(
                proto=0xc021) / PPP_LCP(code=0x1, id=0x1, len=length, data=loadbin)
            self.send_packet(lcp_request, iface=self.iface)
        elif pkt.proto == 0xc021:
            """处理lcp-requests请求，发送lcp-replay"""
            # 把除了mru,pap和magic-number之外的其他字段全部拒绝
            # 先拆包判断是否有其他字段，如果有则加入option中，然后把code=0x4-reject,否则code=2
            # 构建整个PPPoE LCP包
            if pkt[PPP].code == 0x01:
                options = pkt[PPP_LCP_Configure].options
                flag = 0
                lcp_option = ''
                lcp_nak = ""
                nak_flag = 0
                for option in options:
                    if option.type == 0x1 and option.max_recv_unit:
                        flag = flag + 1
                        lcp_option = lcp_option + '0104{:04x}'.format(option.max_recv_unit)
                        # PPP_LCP_MRU_Option(type=1, len=4, max_recv_unit=option.max_recv_unit))
                    elif option.type == 0x03:
                        if option.auth_protocol == 0xc023:
                            flag = flag + 1
                            lcp_option = lcp_option + '03{:02x}{:04x}'.format(option.len, option.auth_protocol)
                            # lcp_option = lcp_option + PPP_LCP_Auth_Protocol_Option(type=3, len=option.len,
                            #                                                        auth_protocol=option.auth_protocol)
                        else:
                            nak_flag = 1
                    elif option.type == 0x05:
                        flag = flag + 1
                        self.reply_magic_number = option.magic_number
                        lcp_option = lcp_option + '05{:02x}{:08x}'.format(option.len, option.magic_number)
                    else:
                        pass
                if flag == 3:
                    # 发送lcp-ack
                    raw = copy.deepcopy(pkt)
                    raw[PPP_LCP_Configure].code = 0x02
                    lcp_ack = Ether(src=pkt.dst, dst=pkt.src, type=pkt.type) / PPPoED(version=0x1, type=0x1, code=0x00,
                                                                                      sessionid=pkt.sessionid) / raw[
                                  PPP]
                    self.send_packet(lcp_ack, iface=self.iface)
                    self.send_pap_packet(pkt)
                elif nak_flag == 1:
                    lcp_nak = Ether(src=pkt.dst, dst=pkt.src, type=pkt.type) / PPPoED(version=0x1, type=0x1, code=0x00,
                                                                                      sessionid=pkt.sessionid) / PPP(
                        proto=0xc021) / PPP_LCP(code=0x3, id=pkt[PPP_LCP_Configure].id, len=0x8,
                                                data=string_to_binary("0304c023"))
                    self.send_packet(lcp_nak, iface=self.iface)
            elif pkt[PPP].code == 0x2:
                """处理lcp-ack"""
                pass
            elif pkt[PPP].code == 0x9:
                """处理lcp-request维护链路报文"""
                print("{} reply".format(self.ipcp_ip))
                raw = copy.deepcopy(pkt)
                raw[PPP].code = 0x0a
                raw[PPP].magic_number = self.reply_magic_number
                lcp_reply = Ether(src=pkt.dst, dst=pkt.src, type=pkt.type) / PPPoED(version=0x1, type=0x1, code=0x00,
                                                                                    sessionid=pkt.sessionid) / raw[
                                PPP]
                self.send_packet(lcp_reply, iface=self.iface, flag=1)
                # self.send_pap_packet(pkt)
            # 实现配置 LCP 数据包的方法
        # pkt 参数是收到的数据包，根据需要处理

    def send_chap_packet(self, pkt):
        # 实现发送 CHAP 数据包的方法
        # pkt 参数是收到的数据包，根据需要处理
        pass

    def send_pap_packet(self, pkt):
        # 实现发送 PAP 数据包的方法
        # pkt 参数是收到的数据包，根据需要处理
        if pkt.proto == 0xc023:
            # receive auth success
            if pkt[PPP].code == 0x2:
                self.send_ipcp_packet(pkt)
            elif pkt[PPP].code == 0x1:
                """发送认证成功"""
                loadhex = "02{:02x}000d08{}".format(pkt[PPP].id, self.str2hex("Login ok"))
                raw = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoE(version=1, type=1, code=0,
                                                                           sessionid=pkt.sessionid,
                                                                           len=15) / PPP(
                    proto=0xc023) / Raw(load=string_to_binary(loadhex))
                self.send_packet(raw, iface=self.iface)
        else:
            # receive lcp packet
            userpwd = [self.user, self.pwd]
            user_len = len(userpwd[0])
            pass_len = len(userpwd[1])
            length_pap = user_len + pass_len + 6
            loadhex = '01' + "{:02x}{:04x}{:02x}".format(self.pap_id, length_pap, user_len) + self.str2hex(
                userpwd[0]) + "%02x" % (pass_len) + self.str2hex(userpwd[1])
            loadbin = string_to_binary(loadhex)
            pppoe_len = length_pap + 2
            raw = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoE(version=1, type=1, code=0,
                                                                       sessionid=pkt.sessionid, len=pppoe_len) / PPP(
                proto=0xc023) / Raw(load=loadbin)
            self.send_packet(raw, iface=self.iface)

    def send_ip_packet(self, pkt):
        # 实现发送 IP 数据包的方法
        # pkt 参数是收到的数据包，根据需要处理
        pass

    def send_ipcp_packet(self, pkt):
        # 实现发送 IPCP 数据包的方法
        # pkt 参数是收到的数据包，根据需要处理
        if PPP_IPCP in pkt:
            code = pkt[PPP_IPCP].code
            if code == 2:  # Configure-Ack
                self.ipcp_ip, self.ipcp_dns = self.get_ipcp_ip_and_dns(pkt)
                if self.ipcp_ip != "0.0.0.0" and self.ipcp_dns != "0.0.0.0":
                    # 获取到地址了，进入lcp维护链路阶段
                    print("\n用户={}拨号成功，IP={}".format(self.user, self.ipcp_ip))
                    self.send_packet_flag = 0
                    return self.get_ipcp_ip()
            elif code == 3:  # Configure-Nak
                self.get_ipcp_ip_and_dns(pkt)
                ipcp_req = PPP_IPCP(code=1, id=pkt[PPP_IPCP].id + 1, len=pkt[PPP_IPCP].len,
                                    options=pkt[PPP_IPCP].options)
                req_pkt = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoE(version=1, type=1, code=0,
                                                                               sessionid=pkt.sessionid) / PPP(
                    proto=0x8021) / ipcp_req
                self.send_packet(req_pkt, iface=self.iface)
            elif code == 4:  # Configure-Reject
                print("收到 IPCP Configure-Reject")
            elif code == 1:  # Configure-Request
                ipcp_ip, ipcp_dns = self.get_ipcp_ip_and_dns(pkt)
                loadbin = ""
                # 如果收到的是ip和dns的request则响应ack
                # ipcp_ack = PPP_IPCP(code=2, id=pkt[PPP_IPCP].id, len=16, options=pkt[PPP_IPCP].options)
                loadbin = ""
                if ipcp_ip != "0.0.0.0":
                    loadbin = loadbin + "0306{}".format(ip_to_hex(ipcp_ip))
                if ipcp_dns != "0.0.0.0":
                    loadbin = loadbin + "8106{}".format(ip_to_hex(ipcp_dns))
                loadbin = string_to_binary(loadbin)
                if loadbin:
                    ack_pkt = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoE(version=1, type=1, code=0,
                                                                                   sessionid=pkt.sessionid) / PPP(
                        proto=0x8021) / PPP_IPCP(code=2, id=pkt[PPP_IPCP].id, len=len(loadbin) + 4,
                                                 options=loadbin)
                    self.send_packet(ack_pkt, iface=self.iface)
                else:
                    print("发送nak报文")
                    ipcp_nak = PPP_IPCP(code=3, id=pkt[PPP_IPCP].id, len=pkt[PPP_IPCP].len,
                                        options=pkt[PPP_IPCP].options)
                    ack_pkt = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoE(version=1, type=1, code=0,
                                                                                   sessionid=pkt.sessionid) / PPP(
                        proto=0x8021) / ipcp_nak
                    self.send_packet(ack_pkt, iface=self.iface)
        else:
            loadbin = "030600000000810600000000"
            ipcp_req = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoE(version=1, type=1, code=0,
                                                                            sessionid=pkt.sessionid) / PPP(
                proto=0x8021) / PPP_IPCP(code=1, id=self.ipcp_id, len=16, options=string_to_binary(loadbin))
            self.send_packet(ipcp_req, iface=self.iface)
            self.ipcp_id += 1

    def send_ipv6cp_paket(self, pkt):
        # 实现发送 IPV6CP 数据包的方法
        # pkt 参数是收到的数据包，根据需要处理
        pass

    def get_ipcp_ip_and_dns(self, pkt):
        ipcp_ip, ipcp_dns = "0.0.0.0", "0.0.0.0"
        for option in pkt[PPP_IPCP].options:
            if option.type == 3:
                ipcp_ip = option.data
            elif option.type == 0x81:
                ipcp_dns = option.data
            else:
                print("不识别的字段type={:02x}".format(option.type))
        return [ipcp_ip, ipcp_dns]

    def parse_tlv_data(self, binary_data):
        result = {}
        index = 0
        while index < len(binary_data):
            # Extract Type
            type_hex = binary_data[index:index + 2]
            type_int = int(type_hex, 16)
            type_key = f"0x{type_hex.upper()}"
            index += 2

            # Extract Length
            length_hex = binary_data[index:index + 4]
            length_int = int(length_hex, 16)
            index += 4

            # Extract Value
            value_hex = binary_data[index:index + (length_int * 2)]
            value_str = ''.join(chr(int(value_hex[i:i + 2], 16)) for i in range(0, len(value_hex), 2))
            index += length_int * 2

            # Store in result dictionary
            result[type_key] = value_str

        return result

    def get_ipcp_ip(self):
        for i in range(1, 30):
            if self.ipcp_ip != "0.0.0.0":
                return self.ipcp_ip
            if i % 10 == 0:
                self.send_padi_packet()
            time.sleep(1)
        return None


def pppoe_dual(iface, smac, user, pwd):
    pppoe_client = PppoeClient(iface=iface, smac=smac, user=user, pwd=pwd)
    thread = threading.Thread(target=pppoe_client.sniff_and_process)
    thread.start()
    pppoe_client.send_padi_packet()
    result = pppoe_client.get_ipcp_ip()
    return result


if __name__ == "__main__":
    result = pppoe_dual(iface="usb", smac="00:11:22:33:44:cc", user="test100", pwd="test")
    print("IP={}".format(result))
    # sniff_and_process 后台thread监听，后面的函数继续执行
