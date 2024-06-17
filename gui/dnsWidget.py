
from PyQt5.QtCore import Qt, QUrl,pyqtSignal,QSize
from PyQt5.QtGui import QIcon, QDesktopServices,QTextCursor,QFont,QColor,QBrush
from PyQt5.QtWidgets import (QListWidgetItem, QFrame, QTreeWidgetItem, QHBoxLayout,QVBoxLayout,
                             QTreeWidgetItemIterator, QTableWidgetItem)
from qfluentwidgets import (NavigationItemPosition, MessageBox, setTheme, Theme, FluentWindow,
                            NavigationAvatarWidget, qrouter, SubtitleLabel, setFont, InfoBadge,
                            InfoBadgePosition,TreeWidget)
from qfluentwidgets import InfoBarIcon, InfoBar, PushButton, setTheme, Theme, FluentIcon, InfoBarPosition, InfoBarManager
from qfluentwidgets import FluentIcon as FIF
from ui.Ui_dnsDetectionWindow import Ui_dnsDetectionWindow
import time,threading,datetime
from scapy.all import DNS, IP, UDP, send,DNSQR,RandShort
from scapy.all import *
from core.network import network
from sniffWidget import SniffWidget
from core.attack.dns_attack import DNSAttack
from core.detection.dns_detection import DNSDetection
from detectionMonitor import DetectionMonitorWidget
from detectionMetricsMonitor import DetectionMetricsMonitorWidget
# 创建一个全局锁
global_lock = threading.Lock()

class DNSWidget(QFrame,Ui_dnsDetectionWindow):

    def __init__(self, text: str, parent=None):
        super().__init__(parent=parent)
        self.setObjectName(text.replace(' ', '-'))
        self.setStyleSheet("background-color:#ffffff")
        self.sniffWidgetInstance = None
        self.index = 0
        self.detect_thread = None
        self.attack_simulation_thread = None
        #是否正在检测
        self.is_detecting = False
        self.is_attacking = False
        self.DNSAttackInstance = DNSAttack()
        self.DNSDetectionInstance = DNSDetection()
        self.detectionMonitorInstance = DetectionMonitorWidget()
        self.detectionMonitorMetricsInstance = DetectionMetricsMonitorWidget()
        self.detection_packet_count = 0
        self.attack_packet_count = 0
        self.detection_true_count = 0 #检测正确的包数量(TP+TN)
        self.detection_false_count = 0 #检测错误的包数量(FP+FN)
        self.traffic_detection_packet_list = []
        self.domain_detection_map = {}
        self.domain_attack_map = {}

    #防止异步操作造成ui卡死，为需要操作ui的函数上锁
    def synchronized(func):
        def wrapper(*args, **kwargs):
            # 在调用函数之前获取锁
            with global_lock:
                return func(*args, **kwargs)
        return wrapper
    def bindSniffWidget(self,sniffWidget:SniffWidget):
        self.sniffWidgetInstance = sniffWidget
    def setupUi(self, Ui_MainWindow):
        super(DNSWidget, self).setupUi(Ui_MainWindow) 
        self.connect_solt_functions()
        #绑定监控器
        layout = QHBoxLayout()
        #恶意DNS包数量监控
        layout.addWidget(self.detectionMonitorInstance)
        self.detectionMonitorInstance.setMaximumHeight(260)
        self.detectionMonitorInstance.setMaximumWidth(380)
        #指标监控器
        layout.addWidget(self.detectionMonitorMetricsInstance)
        self.detectionMonitorMetricsInstance.setMaximumHeight(260)
        self.detectionMonitorMetricsInstance.setMaximumWidth(400)
        #layout样式
        self.widget_detection_chart.setMaximumHeight(320)
        self.widget_detection_chart.setLayout(layout)
        #开启监控器线程
        self.monitor_thread = threading.Thread(target=self.monitorThreadLoop,daemon=True)
        self.monitor_thread.start()
        self.metricMonitor_thread = threading.Thread(target=self.metricMonitorThreadLoop,daemon=True)
        self.metricMonitor_thread.start()
    # 代表统一连接槽函数
    def connect_solt_functions(self):
        #连接信号槽
        self.pushButton_detect.clicked.connect(self.detectButtonClick) # 开始/停止检测
        self.pushButton_attack_simulation.clicked.connect(self.attackSimulationClick) #开始/停止攻击模拟     
        #初始化嗅探流量包表
        self.initTrafficDetectionTable()
        return
    
    def initTrafficDetectionTable(self):
        self.tableWidget_traffic_detection_list.setBorderVisible(True)
        self.tableWidget_traffic_detection_list.setBorderRadius(8)
        self.tableWidget_traffic_detection_list.setWordWrap(False)
        self.tableWidget_traffic_detection_list.setColumnCount(8)
        self.tableWidget_traffic_detection_list.verticalHeader().hide()
        self.tableWidget_traffic_detection_list.setHorizontalHeaderLabels(['ID', 'Time','domain_type','domain', 'source', 'destination', 'protocol','real_domain_type'])
        self.tableWidget_traffic_detection_list.resizeColumnsToContents()
        self.tableWidget_traffic_detection_list.setColumnWidth(7,100)
        pass

    @synchronized
    def detectButtonClick(self,clicked):
        if not self.is_detecting:
            print("开始检测")
            self.startDetectThread()
        else:
            self.stopDetectThread()
    @synchronized
    def attackSimulationClick(self,clicked):
        if not self.is_attacking:
            print("开始模拟")
            self.startAttackSimulationThread()
        else:
            self.stopAttackSimulationThread()
    @synchronized
    def showInfo(self,message):
        def createSuccessInfoBar():
            # convenient class mothod
            InfoBar.success(
                title='提示',
                content=message,
                orient=Qt.Horizontal,
                isClosable=True,
                position=InfoBarPosition.TOP,
                # position='Custom',   # NOTE: use custom info bar manager
                duration=2000,
                parent=self
            )
        createSuccessInfoBar()
    def startDetectThread(self):
        #开始检测时清空所有数据
        self.all_clear()
        self.pushButton_detect.setText("停止检测")
        self.is_detecting=True
        self.detect_thread = threading.Thread(target=self.detectThreadLoop,daemon=True)
        self.detect_thread.start()
    
    def startAttackSimulationThread(self):
        self.pushButton_attack_simulation.setText("停止模拟")
        self.is_attacking=True
        self.attack_simulation_thread = threading.Thread(target=self.attackSimulationThreadLoop,daemon=True)
        self.attack_simulation_thread.start()

    def stopDetectThread(self):
        print("stop detect thread")
        self.pushButton_detect.setText("开始检测")
        self.is_detecting=False
    def stopAttackSimulationThread(self):
        print("stop simulation thread")
        self.pushButton_attack_simulation.setText("攻击模拟")
        self.is_attacking=False
    def detectThreadLoop(self):
        print("start detect thread")
        while self.is_detecting:
            if self.sniffWidgetInstance!=None:
                new_packet_info = self.sniffWidgetInstance.traffic_packets_queue.get()
                proccess_packet_info = self.proccess_packet(new_packet_info)
    def monitorThreadLoop(self):
        print("start monitor thread")
        while True:
            if self.detectionMonitorInstance!=None:
                self.detectionMonitorInstance.addDetectionData(self.detection_packet_count,False)
                self.detectionMonitorInstance.addDetectionData(self.attack_packet_count,True)
                self.detection_packet_count = 0
                self.attack_packet_count = 0
            time.sleep(1)
    def metricMonitorThreadLoop(self):
        print("start metric monitor thread")
        while True:
            if self.detectionMonitorMetricsInstance!=None:
                self.detectionMonitorMetricsInstance.addDetectionMetricsData(self.detection_true_count,True)
                self.detectionMonitorMetricsInstance.addDetectionMetricsData(self.detection_false_count,False)
            time.sleep(1)       
    def proccess_packet(self,pkt_info):       
        #完整包信息中获取域名
        source_ip = pkt_info[2]
        destination_ip = pkt_info[3]
        domain,domain_type = self.proccess_dns_packet(pkt_info[7])
        if destination_ip != '8.8.8.8': #非攻击模拟流量默认都是良性的
            domain_type = 'good'
        #比较预测结果的正确性
        predict_true,real_type=self.is_doamin_predict_true(domain,domain_type)
        new_pkt_info = [pkt_info[0],pkt_info[1],domain_type,domain,pkt_info[2],pkt_info[3],pkt_info[4],real_type]
        if domain!="":
            self.detection_packet_count += 1
            if domain_type == 'bad':
                self.attack_packet_count +=1
            self.traffic_detection_packet_list.append(new_pkt_info)
            self.outputPacketToTrafficDetectionList(new_pkt_info)
        return new_pkt_info
    

    def proccess_dns_packet(self,pkt):
        #如果是DNS数据包则获取数据里面查询的域名
        domain = ""
        predict_domain_type = ""
        try:
            if pkt.haslayer(DNSQR):
                domain = pkt[DNSQR].qname.decode('utf-8').rstrip(".") #去除末尾(.)
            if self.DNSDetectionInstance!=None and domain!="":
                predict_domain_type = self.DNSDetectionInstance.detect_domain(domain)
            self.domain_detection_map[domain]=predict_domain_type
            return domain,predict_domain_type
        except Exception as e:
            return domain,predict_domain_type
    def is_doamin_predict_true(self,detection_domain,predict_domain_type):
        real_domain_type = 'good'
        if detection_domain in self.domain_attack_map.keys():
            real_domain_type = self.domain_attack_map[detection_domain]
        if real_domain_type == predict_domain_type:
            self.detection_true_count +=1          
            return True,real_domain_type
        self.detection_false_count +=1   
        return False,real_domain_type
    def attackSimulationThreadLoop(self):
        while self.is_attacking:
            if self.DNSAttackInstance!=None:
                domain_type,domain = self.DNSAttackInstance.attack_simulation_loop()
                self.domain_attack_map[domain]=domain_type
        print("停止攻击模拟")
    @synchronized
    def outputPacketToTrafficDetectionList(self,pkt_info):
        try:
            # 处理捕获到的数据包
            self.index = self.index + 1
            # 插入新行
            self.tableWidget_traffic_detection_list.insertRow(self.index - 1)
            print(f"packet info:{pkt_info}")
            # 在行中添加列
            for cnt,item in enumerate(pkt_info):
                table_widget_item = QTableWidgetItem(str(item))
                if cnt==2:
                    #domain_type字段高亮处理
                    table_widget_item.setForeground(QBrush(QColor(75,167,10)))
                    table_widget_item.setFont(QFont('微软雅黑',10,QFont.Black))
                    if str(item)=='bad':
                        #domain_type_item = InfoBadge.error(str(item))
                        table_widget_item.setForeground(QBrush(QColor(245,80,0)))
                    #错误的预测标记为灰色
                    if pkt_info[2]!=pkt_info[7]:
                        table_widget_item.setForeground(QBrush(QColor(167,167,167)))
                    
                self.tableWidget_traffic_detection_list.setItem(self.index - 1,cnt,table_widget_item)
            self.tableWidget_traffic_detection_list.resizeColumnsToContents()
            self.tableWidget_traffic_detection_list.setColumnWidth(3, 300) #域名字段防止过长
            self.tableWidget_traffic_detection_list.scrollToBottom()
        except Exception as e:
            print(e)
    # 代表清空所有数据
    def all_clear(self):  
        self.traffic_detection_packet_list = []
        self.tableWidget_traffic_detection_list.setRowCount(0)
        self.tableWidget_traffic_detection_list.clearContents()
        self.index = 0