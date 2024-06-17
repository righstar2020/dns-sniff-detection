
#使用scapy嗅探数据包并每n个包输出为pcap文件
from scapy.all import sniff, wrpcap
import threading
from queue import Queue
import time
from datetime import datetime

# 设置参数
class PacketCapturer:
    """
        iface: 网卡名称
        packets_per_file: 每次保存的包数量
    """
    def __init__(self, iface=None, packets_per_file=200,packet_file_path=''):
        self.iface = iface
        self.packets_per_file = packets_per_file
        self.packet_file_path = packet_file_path+"/"
        self.pkt_queue = Queue()
        self.event_stop = threading.Event()
        self.sniffer_thread = None
        self.saver_thread = None

    def save_packets(self,iface_name,file_index):
        """线程函数，用于处理数据包并保存到 pcap 文件"""
        packet_buffer = []
        
        while not self.event_stop.is_set():
            try:
                # 从队列中获取数据包，如果队列为空则等待
                pkt = self.pkt_queue.get(timeout=1)
                packet_buffer.append(pkt)
                
                # 达到指定数量后保存并清空缓冲区
                if len(packet_buffer) == self.packets_per_file:
                    # 格式化时间，包括年月日时分秒和毫秒
                    timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
                    pcap_filename = f"capture_{iface_name}_{file_index}_{timestamp}.pcap"
                    savePacketFilePath = self.packet_file_path + pcap_filename
                    wrpcap(savePacketFilePath, packet_buffer)
                    print(f"已保存 {self.packets_per_file} 个数据包到 {pcap_filename}")
                    file_index += 1
                    packet_buffer.clear()
            except self.pkt_queue.Empty:
                pass  # 队列为空时直接跳过


    def sniff_packets(self):
        """嗅探线程函数，将嗅探到的数据包放入队列"""
        sniff(iface=self.iface, prn=lambda x: self.pkt_queue.put(x), stop_filter=lambda _: self.event_stop.is_set())
    def stopCaptureThread(self):
        if self.sniffer_thread==None:
            return
        if self.saver_thread == None:
            return
        self.event_stop.set()
        # 等待线程结束
        self.sniffer_thread.join()
        self.saver_thread.join()
        print("嗅探已停止，所有线程已退出。")

    def startCaptureThread(self):
        # 初始化文件序号
        file_index = 1
        self.sniffer_thread = threading.Thread(target=self.sniff_packets, args=(self.iface,file_index,))
        self.saver_thread = threading.Thread(target=self.save_packets)

        # 启动线程
        self.sniffer_thread.start()
        self.saver_thread.start()
        print("嗅探已经开始，按 Ctrl+C 退出...")

        
# capturer = PacketCapturer('eth0')
# try:
#     capturer.startCaptureThread()
# except KeyboardInterrupt:
#     print("嗅探已停止。")
#     capturer.stopCaptureThread()
            