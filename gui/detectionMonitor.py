
import sys,os,time 

import numpy as np
import matplotlib

import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from matplotlib.animation import FuncAnimation 
import threading
import time
import matplotlib.ticker as ticker
from matplotlib.markers import MarkerStyle
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
# 全局变量及互斥锁
detectionResultDataList = []
detectionAttackResultDataList = []
global_lock = threading.Lock()
matplotlib.use("Agg")      # 或着matplotlib.use(“GTK”)或者matplotlib.use(“Qt5Agg”)
# 线程锁，保证线程安全，防止多线程异常
def synchronized(func):
    def wrapper(*args, **kwargs):
        # 在调用函数之前获取锁
        with global_lock:
            return func(*args, **kwargs)
    return wrapper

class DetectionMonitorWidget(QWidget):
    def __init__(self) -> None:
        super().__init__()
        matplotlib.rcParams['font.sans-serif'] = 'SimHei'  # 设置默认字体为黑体  
        matplotlib.rcParams['axes.unicode_minus'] = False  # 解决保存图像是负号'-'显示为方块的问题  
        self.initDetectionMonitor()
        self.init_clock()
    
    @synchronized
    def addDetectionData(self,count_data,is_attack):
        global detectionResultDataList
        global detectionAttackResultDataList
        if is_attack:
            detectionAttackResultDataList.append(count_data)
        else:
            #detectionResultDataList.append(count_data)
            detectionResultDataList.append(0)
        
    @synchronized
    def initDetectionMonitor(self):  
        # 初始化画图组件
        # 创建一个新的matplotlib Figure对象
        self.detectionFigure = plt.figure(figsize=(6, 5), dpi=100)
        # 将Figure对象封装进FigureCanvas对象中
        self.detectionCanvas = FigureCanvas(self.detectionFigure)
        # 创建一个垂直布局容器
        layout = QVBoxLayout()
        layout.addWidget(self.detectionCanvas)
        #添加为布局
        self.setLayout(layout) 
        self.detectionAx = self.detectionFigure.add_subplot()
        #设置Figure中的图像的标题
        self.detectionFigure.suptitle('DNS检测')
        self.detectionAx.set_ylabel('包数量')
        self.detectionAx.set_xlabel('时间(秒)')
        self.detectionAx.set_xlim(0,1)
        return self
    
    @synchronized
    def updateDetectionData(self):
        """Figure图表更新数据"""
        if len(detectionResultDataList)==0:
            return
        allDetectionDataX=[i for i in range(min(10,max(len(detectionResultDataList),len(detectionResultDataList)-10)))]
        allDetectionDataY=detectionResultDataList[max(0,len(detectionResultDataList)-10):]
        attackDetectionDataX=[i for i in range(min(10,max(len(detectionAttackResultDataList),len(detectionAttackResultDataList)-10)))]
        attackDetectionDataY=detectionAttackResultDataList[max(0,len(detectionAttackResultDataList)-10):]
        # print(dataY)
        self.detectionAx.clear()  # 清除上一帧的数据
        self.plotdetectionResultDataList=self.detectionAx.plot(allDetectionDataY,color='black',label='正常基准',linewidth=1)
        self.plotdetectionAttackResultDataList=self.detectionAx.plot(attackDetectionDataY,color='red',label='恶意DNS包',linewidth=1)
        # 在特定位置添加marker
        markers=[]
        #源IP熵
        for y in allDetectionDataY:
            marker = ''
            if y>75:
               marker='o'
            markers.append(marker)
        for x,y, marker in zip(allDetectionDataY, allDetectionDataX,markers):
            self.detectionAx.plot(x,y, marker=marker, markersize=7,color="red")  # 可调整marker大小和填充方式
        #目的端口熵
        for y in attackDetectionDataY:
            marker = ''
            if y>1:
               marker='o'
            markers.append(marker)
        for x,y, marker in zip(attackDetectionDataY, attackDetectionDataX,markers):
            self.detectionAx.plot(x,y, marker=marker, markersize=7,color="red")  # 可调整marker大小和填充方式

        self.detectionAx.set_ylim(-2, max(max(attackDetectionDataY),max(allDetectionDataY))+3)
        self.detectionAx.set_xlim(allDetectionDataX[0], allDetectionDataX[-1])  # 自动适应最新数据的x轴范围
        self.detectionAx.set_xticks(allDetectionDataX)  # 设置x轴刻度
        self.detectionAx.set_xticklabels([str(i) for i in range(max(0,len(detectionResultDataList)-10),len(detectionResultDataList))])  # 设置x轴标签
        self.detectionAx.set_ylabel('包数量')
        self.detectionAx.set_xlabel('时间(秒)')
        self.detectionFigure.suptitle('DNS检测')
        self.detectionAx.legend()
        # 更新后可能需要重新绘制图形以反映新的刻度
        self.detectionFigure.canvas.draw()
        #self.fig.canvas.draw_idle()
        return self.plotdetectionResultDataList
    
    def init_clock(self): 
        #实例化Figure动画
        #设置定时器，用于更新
        self.detectionWidgetTimer = QTimer(self)
        self.detectionWidgetTimer.timeout.connect(self.updateDetectionData)
        self.detectionWidgetTimer.start(3000)

