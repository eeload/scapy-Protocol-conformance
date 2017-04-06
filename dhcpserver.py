#! /usr/bin/env python
# -*- coding: utf-8 -*-

u"""
模拟dhcp服务器回应相应的报文
"""

import random
import sys
import string,binascii,signal,sys,threading,socket,struct,getopt
from scapy.all import *
import re,time
import IPy
# from scapy.error import log_interactive
conf.checkIPaddr = False
interface = "eth1"
verbose = True
Debug=False

#用于存放Mac地址获取到的IP地址
class dhcpser_packet(threading.Thread):
    def __init__(self,**kargs):
        threading.Thread.__init__(self)
        self.subnet_mask="255.255.255.0"
        self.router="192.168.3.1"   ;#默认网关
        self.name_server="8.8.8.8" #域名服务器地址
        self.domain="localhost"
        self.broadcast_address="192.168.3.255"
        self.start_sip="192.168.3.2"
        self.start_eip="192.168.3.100"
        self.offer_timeout=0    ;#为0表示不延迟进行回应OFFER报文,为-1表示不回应OFFER报文,为大于1的表示等待该时间回应OFFER
        self.ack_timeout=0  ;#为0 不延迟回应request 为-1不回应 其他为等待回应 
        self.T1=0           ;#为0 不延迟回应  为-1 不回应 为其他延迟回应
        self.T2=0           ;#为0 不延迟回应  为-1 不回应 其他延迟回应
        self.polllist=[]
        self.macip_dict={}
        self.lease_time=30 ;#默认租约时间 4294967295L表示永久租约
        self.server_id="192.168.3.88" ;#DHCP服务器IP地址
        self.renewal_time=self.lease_time/2
        self.rebinding_time = self.lease_time*7/8
        self.parser(**kargs)
        self.filter="arp or icmp or (udp and src port 68 and dst port 67)"
        self.poolInit()
        # print self.start
        # print self.end
    def parser(self,**kargs):
        for key,value in kargs.items():
            if key == "smac" or key == "dmac":
                value = ":".join(value.split("-"))
            setattr(self,key,value)
    def createMac(self,i):
        new_mac="%012x" %(self.start_mac+i)
        ret_mac=re.sub(r"(?<=\w)(?=(\w\w)+$)",":",new_mac)
        return ret_mac
    def poolInit(self):
        self.startIP=self.ipToint(self.start_sip)
        self.endIP=self.ipToint(self.start_eip)
    def poolfree(self,mac):
        #如果mac地址在macip_dict中 则分配该IP地址
        if mac in self.macip_dict.keys():
            return self.macip_dict[mac]
        else:
            for i in range(self.startIP,self.endIP+1):
                cur_ip=self.numToip(i)
                if  cur_ip not in self.polllist:
                    return cur_ip
        return "0.0.0.0"
    def ipToint(self,ip):
        return reduce(lambda a,b: a<<8 | b, map(int, ip.split(".")))
        
    def numToip(self,ip_num):
        return ".".join(map(lambda n: str(ip_num>>n & 0xFF), [24,16,8,0]))
    def parser_mac(self,mac):
        cid=""
        for i in mac.split(":"):
            cid=cid+mac2str(i)
        return cid
    def run(self):
        sniff(filter=self.filter,prn=self.detect_parserdiscovey,store=0,iface=self.intf)
    def detect_parserdiscovey(self,pkt):
        #解析offer报文
        #打开文件进行配置
        # log_interactive.debug("clients=3")
        all_info=""
        if DHCP in pkt:
            #判断是否为Discover 报文
            if pkt[DHCP].options[0][1] == 1 or pkt[DHCP].options[0][1] == 3:
                self.dhcpcount=0
                dhcpsip = pkt[IP].src
                dhcpsmac = pkt[Ether].src
                cli_mac=pkt[Ether].src
                print "cli_mac=",cli_mac
                localxid=pkt[BOOTP].xid
                your_ip=self.poolfree(dhcpsmac)
                if your_ip == "0.0.0.0":
                    #发送Nak报文
                    nak=Ether(src=self.smac,dst="ff:ff:ff:ff:ff:ff")/IP(src=self.server_id,dst="255.255.255.255")/UDP(sport=67,dport=68)/BOOTP(op=2,chaddr=self.parser_mac(cli_mac),xid=localxid,yiaddr=your_ip)/DHCP(options=[("message-type","nak"),("server_id",self.server_id),"end"])
                    sendp(nak,verbose=0,iface=self.intf)
                else:
                    # self.polllist.append(your_ip)
                    if pkt[DHCP].options[0][1] == 1:
                        #这里需要判断是T1单播租约包还是T2广播租约包
                        options_all=[("message-type","offer"),("server_id",self.server_id),('lease_time',self.lease_time),("router",self.router),("subnet_mask",self.subnet_mask),('renewal_time',self.renewal_time),('name_server',self.name_server),('rebinding_time',self.rebinding_time),("broadcast_address",self.broadcast_address)]
                        options_all=self.add_option(options_all)
                        options_all.append("end")
                        dhcp_offer=Ether(src=self.smac,dst=dhcpsmac)/IP(src=self.server_id,dst=dhcpsip)/UDP(sport=67,dport=68)/BOOTP(op=2,chaddr=self.parser_mac(cli_mac),xid=localxid,yiaddr=your_ip)/DHCP(options=options_all)
                        
                        if self.waittimeout(self.offer_timeout):
                            sendp(dhcp_offer,verbose=0,iface=self.intf)
                    elif pkt[DHCP].options[0][1] == 3:
                        options_all=[("message-type","ack"),("server_id",self.server_id),('lease_time',self.lease_time),("router",self.router),("subnet_mask",self.subnet_mask),('renewal_time',self.renewal_time),('name_server',self.name_server),('rebinding_time',self.rebinding_time),("broadcast_address",self.broadcast_address)]
                        options_all=self.add_option(options_all)
                        options_all.append("end")
                        dhcp_ack=Ether(src=self.smac,dst=dhcpsmac)/IP(src=self.server_id,dst=dhcpsip)/UDP(sport=67,dport=68)/BOOTP(op=2,chaddr=self.parser_mac(cli_mac),xid=localxid,yiaddr=your_ip)/DHCP(options=options_all)
                        if pkt[BOOTP].ciaddr == "0.0.0.0":
                            #为回应OFFER的requeest
                            if self.waittimeout(self.ack_timeout):
                                sendp(dhcp_ack,verbose=0,iface=self.intf)
                                self.macip_dict[dhcpsmac]=your_ip
                                self.polllist.append(your_ip)
                        else:
                            if pkt[IP].src == "0.0.0.0":
                                #为T2广播包
                                if self.waittimeout(self.T2):
                                    sendp(dhcp_ack,verbose=0,iface=self.intf)
                                    self.macip_dict[dhcpsmac]=your_ip
                                    self.polllist.append(your_ip)
                            else:
                                #为T1广播包
                                if self.waittimeout(self.T1):
                                    sendp(dhcp_ack,verbose=0,iface=self.intf)
                                    self.macip_dict[dhcpsmac]=your_ip
                                    self.polllist.append(your_ip)
            elif pkt[DHCP].options[0][1] == 4:
                #decline报文的处理,decline报文中会带option 50字段表示冲突的IP地址
                options=pkt[DHCP].options
                optionlen=len(options)
                for i in range(optionlen):
                    if options[i][0] == "requested_addr":
                        self.polllist.append(options[i][1])
                        break
                all_info=all_info+"DECLINE=%s\n" %(options[i][1])
            elif pkt[DHCP].options[0][1] == 7:
                dhcpsip = pkt[IP].src
                dhcpsmac = pkt[Ether].src
                self.polllist.remove(dhcpsmac)
                all_info=all_info+"DECLINE=%s\n" %(dhcpsip)
        elif ICMP in pkt:
            #对arp报文的处理
            smac=pkt[Ether].dst
            if pkt[ICMP].type==8:
                myip=pkt[IP].dst
                mydst=pkt[IP].src
                icmp_req=Ether(src=smac,dst=pkt.src)/IP(src=myip,dst=mydst)/ICMP(type=0,id=pkt[ICMP].id,seq=pkt[ICMP].seq)/"12345678912345678912"
                all_info=all_info+"ICMP_SIP=%s" %(mydst)
        elif ARP in pkt:
            #对arp报文的处理
        # self.writemsg(all_info)
    def unpackMAC(self,binmac):
        mac=binascii.hexlify(binmac)[0:12]
        blocks = [mac[x:x+2] for x in xrange(0, len(mac), 2)]
        return ':'.join(blocks)
    def add_option(self,options_all):
        ret_all=options_all
        if hasattr(self,'static_route_33'):
            ret_all.append(('static_route_33',self.parser_option33(self.static_route_33)))
        if hasattr(self,'static_route_121'):
            ret_all.append(('static_route_121',self.parser_option33(self.static_route_121)))
        if hasattr(self,'static_route_249'):
            ret_all.append(('static_route_249',self.parser_option33(self.static_route_249)))
        print ret_all
        return ret_all
    def parser_option33(self,option):
        #option 33为有类静态路由,option 121位无类静态路由
        header= option[:2]
        if header == "33":
            return self.str2hex(option[3:],flag="ip")
        elif header in "121":
            ip=self.parser_option121(option[3:])
            print "ip=",ip
            return self.str2hex(ip,flag="ip")
    def parser_option121(self,option):
        #传入参数格式为 192.168.1.2/24 192.168.100.1 192.168.2.2/24 192.168.100.1 
        optlist=option.strip().split(" ")
        print "optlist=",optlist
        optlen=len(optlist)
        ret=[]
        for i in range(0,optlen,2):
            dst_net=optlist[i].split("/")
            mask=int(dst_net[1])
            flag=(mask-1)/8+1
            print "dst_net=",dst_net
            print "mask=",mask
            dst=str(IPy.IP(dst_net[0]).make_net(mask)).split("/")[0]
            print "dst=",dst
            ret.append("%d" %(mask))
            ret.extend(dst.split(".")[:flag])
            ret.extend(optlist[i+1].split("."))
        print "ret=",ret
        print ".".join(ret)
        return ".".join(ret)
    def str2hex(self,s_str,flag="ip"):
        if flag == "ip":
            #先把IP地址转换成0x的2位形式
            return "".join(map(lambda x: chr(int(x,16)), self.num2hex(re.split(r'[. ]',s_str))))
        elif flag == "mac":
            #
            return "".join(map(lambda x: chr(int(x,16)), s_str.split(":")))
        else:
            #先把字符串转换成ASCII对应的数字,再转换成十六进制
            return "".join(map(lambda x: chr(int(x,16)), self.toascii(s_str)))
    #对于IP地址192 168 0 1 =>c0 a8 00 01
    def num2hex(self,numlist):
        retlist=[]
        for i in numlist:
            retlist.append("%02x" %(int(i)))
        return retlist
    def toascii(self,s_str):
        retlist=[]
        lenstr=len(s_str)
        for i in range(0,lenstr):
            retlist.append(ord(s_str[i]))
        return num2hex(retlist)
    def waittimeout(self,num):
        num=int(num)
        if num == 0:
            return True
        elif num == -1:
            return False
        elif num >0:
            time.sleep(num)
            return True
    def writemsg(self,msg):
        fd=open(self.filename,"a+")
        fd.write(msg)
        fd.flush()
        fd.close()
if __name__ == '__main__':
    now=time.localtime()
    now_str="%s-%s-%s %s:%s:%s" %(now.tm_year,now.tm_mon,now.tm_mday,now.tm_hour,now.tm_min,now.tm_sec)
    kargs={"smac":"00:11:ab:cd:ef:00","filename":"c:/dhclient.txt","intf":"eth6","T1":"0","T2":"0","static_route_121":"121 192.168.11.10/25 192.168.3.99 192.168.12.10/26 192.168.3.99"}
    #121 192.168.10.128 表示网络位 和网段地址
    for i in range(1, len(sys.argv)):
        print sys.argv[i]
        value=sys.argv[i].split("=")
        if len(value)==2 and len(value[1]) != 0:
            kargs[value[0]]=value[1]
    #
    t=dhcpser_packet(**kargs)
    print id(t)
    t.start()
    # t.join()
    # func=kargs['func']
    # getattr(t, func)()