
from PyQt5.QtCore import Qt, QUrl,pyqtSignal,QSize
from PyQt5.QtGui import QIcon, QDesktopServices,QTextCursor
from PyQt5.QtWidgets import (QListWidgetItem, QFrame, QTreeWidgetItem, QHBoxLayout,
                             QTreeWidgetItemIterator, QTableWidgetItem)
from qfluentwidgets import (NavigationItemPosition, MessageBox, setTheme, Theme, FluentWindow,
                            NavigationAvatarWidget, qrouter, SubtitleLabel, setFont, InfoBadge,
                            InfoBadgePosition,TreeWidget)
from qfluentwidgets import FluentIcon as FIF
from ui.Ui_mainWindow import Ui_MainWindow
import time,threading,datetime
from scapy.all import *
from core.network import network
from queue import Queue
# 创建一个全局锁
global_lock = threading.Lock()

class SniffWidget(QFrame,Ui_MainWindow):
    #自定义信号
   
    def __init__(self, text: str, parent=None):
        super().__init__(parent=parent)
        self.setObjectName(text.replace(' ', '-'))
        self.setStyleSheet("background-color:#ffffff")
        #当前嗅探的网卡
        self.current_interface_name=""
        #当前控制台输出
        self.console_content=""
        #初始化当前显示的数据包信息
        self.current_packet_id=-1
        self.current_packet_info=[]

        #信息
        # 代表所抓取的包的序号
        self.index = 0
        # 代表每个数据包的各层信息
        self.traffic_packets_info_list = []
        # 代表所有抓取的包的大致信息
        self.traffic_packets_list = []
        self.traffic_packets_queue = Queue()
        # 创建锁(解决抓包时线程安全问题)
        self.lock = global_lock
        # 代表sniff函数线程
        self.thread_sniff = None
        #是否正在嗅探
        self.is_sniffing = False
        #初始化过滤规则，捕获除icmp的所有数据包
        self.filter_expression="not icmp"

    #防止异步操作造成ui卡死，为需要操作ui的函数上锁
    def synchronized(func):
        def wrapper(*args, **kwargs):
            # 在调用函数之前获取锁
            with global_lock:
                return func(*args, **kwargs)
        return wrapper

    def setupUi(self, Ui_MainWindow):
        super(SniffWidget, self).setupUi(Ui_MainWindow) 
        self.connect_solt_functions()
        self.initSubWidget()
    # 代表统一连接槽函数
    def connect_solt_functions(self):
        #连接信号槽
        self.pushButton_run.clicked.connect(self.startSniff) # 连接槽函数(开始嗅探)
        self.pushButton_stop.clicked.connect(self.stopSniff) # 连接槽函数(停止嗅探)
        self.comboBox_ifaces.currentTextChanged.connect(self.changeIfaces)  # 当选择网卡时，触发槽函数，更改sniff参数
        self.tableWidget_traffic_list.clicked.connect(self.clickPacketRow)   # 连接槽函数(获取每个包所在的行)
        self.treeWidget_packet_info.clicked.connect(self.itemClicked)
        self.checkBox_only_DNS.clicked.connect(self.setTrafficFilter)


    def initSubWidget(self):
        #初始化网卡列表
        self.comboBox_ifaces.addItem('')
        networkUtil=network.NetworkUtil()
        iface_info_list,iface_name_list=networkUtil.get_interface()
        self.redloadIfaceList(iface_name_list)
        #初始化嗅探流量包表
        self.initTrafficTable()
        self.initPacketInfoWidget()
        return
    
    def initTrafficTable(self):
        self.tableWidget_traffic_list.setBorderVisible(True)
        self.tableWidget_traffic_list.setBorderRadius(8)
        self.tableWidget_traffic_list.setWordWrap(False)
        self.tableWidget_traffic_list.setColumnCount(7)
        self.tableWidget_traffic_list.verticalHeader().hide()
        self.tableWidget_traffic_list.setHorizontalHeaderLabels(['ID', 'Time', 'source', 'Destination', 'Protocol','Length','info'])
        self.tableWidget_traffic_list.resizeColumnsToContents()
        self.tableWidget_traffic_list.setColumnWidth(7,100)
    def initPacketInfoWidget(self):
        self.treeWidget_packet_info.setBorderRadius(8)
        self.treeWidget_packet_info.setBorderVisible(True)
        # self.treeWidget_packet_info.styleSheet("QTreeWidget{ border: 1px solid #464646; }")
        # self.treeWidget_packet_info.styleSheet("treeWidget_packet_info{ border: 1px solid #464646; }")
        

    def redloadIfaceList(self,ifaces_list):
        if len(ifaces_list)!=0:
            self.consoleWrite("已获取到网卡信息")
        else:
            self.consoleWrite("获取网卡信息失败")
        for iface_name in ifaces_list:
            self.comboBox_ifaces.addItem(iface_name)

    @synchronized
    def consoleWrite(self,msg):
        current_time=time.strftime('%Y-%m-%d %H:%M:%S',time.localtime())
        self.console_content+=(current_time+':'+msg+"\n")
        self.plainTextEdit_console.setPlainText(self.console_content)
        # Scroll to the bottom
        cursor = self.plainTextEdit_console.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.plainTextEdit_console.setTextCursor(cursor)
        pass
    

    def changeIfaces(self,text):
        self.current_interface_name=text
        pass

    #被调用的函数不用加锁同步
    def outputPacketToTrafficList(self,pkt):
        # 插入新行
        self.tableWidget_traffic_list.insertRow(self.index - 1)
        # 在行中添加列
        for cnt,item in enumerate(pkt):
            table_widget_item = QTableWidgetItem(str(item))
            self.tableWidget_traffic_list.setItem(self.index - 1,cnt,table_widget_item)
        self.tableWidget_traffic_list.resizeColumnsToContents()
        self.tableWidget_traffic_list.scrollToBottom()
    #item被单击
    @synchronized
    def itemClicked(self, item):
        item=self.treeWidget_packet_info.itemFromIndex(item)
        
        if  item.isExpanded():            
            item.setExpanded(False)
        else:
            item.setExpanded(True)

    # 获取包所在的行
    @synchronized
    def clickPacketRow(self,msg):
        # 回显之前，先清空根节点及子节点
        self.treeWidget_packet_info.clear()
        # 获取包的行
        packet_row = msg.row()
        # 提取出包的各层数据，进行页面回显
        self.outputPacketInfoToPacketInfoWidget(self.traffic_packets_info_list[packet_row])
    # 将包的各层信息回显在页InfoWidget上
    #被调用的函数不用加锁同步
    def outputPacketInfoToPacketInfoWidget(self,layers):
        # 如果该层信息不存在
        if len(layers) == 0:
            return
        # 遍历每一层，开始显示信息
        for current_layer in layers:
            # 创建根节点
            root_item_protocol = QTreeWidgetItem(self.treeWidget_packet_info)
            root_item_protocol.setText(0,current_layer.name)
            # 根据各层数据，创建子节点
            #root_item_protocol.setSizeHint(0,QSize(len(str(current_layer.name))*25,30))
            self.treeWidget_packet_info.setColumnWidth(0,300)
            for key,value in current_layer.fields.items():
                # 创建子节点
                child_item_protocol = QTreeWidgetItem(root_item_protocol)
                # 给子节点设置值
                child_item_protocol.setText(0,str(key))
                child_item_protocol.setText(1,str(value))
                # 将子节点添加到根节点中
                child_item_protocol.setSizeHint(0,QSize(len(str(key))*25,30))
                child_item_protocol.setSizeHint(1,QSize(len(str(value))*25,30))
    # 获取包的各个层的生成器函数（从底层到高层）
    def get_packet_layers(self, packet):
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            yield layer
            counter += 1
    # 代表捕获数据包的回调函数
    @synchronized
    def packetHandler(self, packet):
        try:
            # 处理捕获到的数据包
            self.index = self.index + 1
            captured_packet = []
            # 将抓包的时间戳转换成容易阅读的时间格式
            formatted_time = datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S")
            # 获取所抓取的包的源地址
            source_ip=""
            destination_ip=""
            if IP in packet:
                source_ip = packet['IP'].src
                # 获取所抓取的包的目的地址
                destination_ip = packet['IP'].dst
            if IPv6 in packet:
                source_ip = packet['IPv6'].src
                # 获取所抓取的包的目的地址
                destination_ip = packet['IPv6'].dst
            # 获取所抓取包的各层协议对象（list）
            layers = list(self.get_packet_layers(packet))
            self.traffic_packets_info_list.append(layers)

            layer_names = [item.name for item in self.get_packet_layers(packet)]
            # 获取包的最高层
            for i in range(0,len(layer_names),1):
                if layer_names[i] == 'Raw' or layer_names[i] == 'Padding':
                    continue
                maximum_layer_protocol = layer_names[i]
            # 获取所抓取的包的总长度(头部 + 负载)
            total_length = len(packet)
            # 获取所抓取的包的摘要信息
            packet_info = packet.summary()
            # 将上述信息进行获取，并存储在列表中
            captured_packet.extend(
                [self.index, formatted_time,
                source_ip, destination_ip,
                maximum_layer_protocol,
                total_length, packet_info])
            self.traffic_packets_list.append(captured_packet)
            # 发出信号
            self.outputPacketToTrafficList(captured_packet)
            #放入消费队列中(layers也加入到包信息里面)
            queue_captured_packet = captured_packet
            queue_captured_packet.append(packet) 
            self.traffic_packets_queue.put(captured_packet)

        except Exception as e:
             # 捕获所有异常并打印异常信息
            print(f"An exception occurred: {e}")

    def setTrafficFilter(self,check):
        print(check)
        if self.filter_expression=="not icmp":        
            self.filter_expression ="udp port 53"
        else:
            self.filter_expression="not icmp"

    def startSniff(self):
        self.all_clear()
        if self.current_interface_name=="":
            self.consoleWrite("网卡选择不能为空") 
            return 
        if self.is_sniffing:
            self.consoleWrite("已开启嗅探线程") 
            return
        self.consoleWrite("开始嗅探")
        self.consoleWrite("开启嗅探线程")
        self.consoleWrite("当前网卡:"+self.current_interface_name) 
        self.comboBox_ifaces.setEnabled(False)
        self.pushButton_run.setEnabled(False)
        self.checkBox_only_DNS.setEnabled(False)
        self.pushButton_stop.setEnabled(True)
        self.is_sniffing=True
        # 使用异步的sniff函数对指定的网络接口捕获数据包        
        self.thread_sniff = AsyncSniffer(iface=self.current_interface_name,
                                         prn=self.packetHandler,
                                         filter=self.filter_expression)
        self.thread_sniff.start()
        
    def stopSniff(self):
        if not self.is_sniffing:
            return
        if self.thread_sniff!=None:
            self.thread_sniff.stop()
            self.thread_sniff=None
        
        self.consoleWrite("停止嗅探")
        self.pushButton_stop.setEnabled(False)
        self.comboBox_ifaces.setEnabled(True)
        self.pushButton_run.setEnabled(True)
        self.checkBox_only_DNS.setEnabled(True)
        self.is_sniffing=False
    
    # 代表清空所有数据
    @synchronized
    def all_clear(self):  
        self.traffic_packets_info_list = []
        self.traffic_packets_list = []
        self.tableWidget_traffic_list.setRowCount(0)
        self.tableWidget_traffic_list.clearContents()
        self.treeWidget_packet_info.clear()
        self.index = 0
        #清空消费队列
        while not self.traffic_packets_queue.empty():
            self.traffic_packets_queue.get_nowait()