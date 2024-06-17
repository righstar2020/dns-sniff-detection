

from scapy.all import DNS, IP, UDP, send,DNSQR,RandShort
import random,time
import os
class DNSAttack():
    def __init__(self) -> None:
        self.bad_domains = []
        self.good_domains = []
        self.bad_domains = self.load_domain_file("bad_urls.txt")
        self.good_domains = self.load_domain_file("good_urls.txt")
        self.attack_stop = False
    def load_domain_file(self,file_name):
        # 获取当前脚本所在的目录
        parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # 构建相对于当前脚本的文件路径
        file_path = parent_dir+"/data_set/txt/"+file_name
        print(f"加载域名文件:{file_path}")
        with open(file_path, "r",encoding="utf-8") as file:
            # 读取所有域名到列表中
            domains = file.readlines()     
            # 去除每行末尾的换行符
            domains = [domain.strip() for domain in domains] 
            return domains
    def send_dns_query(self,domain):
        # 构造DNS请求包
        dns_request = DNS(rd=1, qd=DNSQR(qname=domain))  
        # 封装DNS请求到UDP和IP包中
        udpPacket = UDP(sport=RandShort(), dport=53)
        ipPacket = IP(dst="8.8.8.8")  # 使用Google的公共DNS服务器作为示例
        # 组合完整的数据包
        packet = ipPacket/udpPacket/dns_request   
        # 发送数据包并接收响应（这里简化处理，不等待响应）
        send(packet)
        print(f"DNS query for {domain} sent.")
    def send_random_dns_domain(self,domain_type):
        domain=""
        if len(self.bad_domains)>0 and domain_type=="bad":
            domain = random.choice(self.bad_domains)
        if len(self.good_domains)>0 and domain_type=="good":
            domain = random.choice(self.good_domains)

        print(f"send DNS query for {domain},type:{domain_type}")
        self.send_dns_query(domain)
        return domain
    def attack_simulation_loop(self):
        # 每隔一段时间发送一次DNS请求
        time.sleep(1)
        domain_type=random.choice(['bad','good'])
        domain = self.send_random_dns_domain(domain_type)
        return domain_type,domain
        