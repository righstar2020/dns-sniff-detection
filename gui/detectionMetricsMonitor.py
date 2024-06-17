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
detectionMetricsDataList = [0,0]
global_lock = threading.Lock()
matplotlib.use("Agg")      # 或着matplotlib.use(“GTK”)或者matplotlib.use(“Qt5Agg”)
# 线程锁，保证线程安全，防止多线程异常
def synchronized(func):
    def wrapper(*args, **kwargs):
        # 在调用函数之前获取锁
        with global_lock:
            return func(*args, **kwargs)
    return wrapper
#检测成功率(度量)监控
class DetectionMetricsMonitorWidget(QWidget):
    def __init__(self) -> None:
        super().__init__()
        matplotlib.rcParams['font.sans-serif'] = 'SimHei'  # 设置默认字体为黑体  
        matplotlib.rcParams['axes.unicode_minus'] = False  # 解决保存图像是负号'-'显示为方块的问题  
        self.initDetectionMetricsMonitor()
        self.init_clock()
    
    @synchronized
    def addDetectionMetricsData(self,count_data,is_predict_true):
        global detectionMetricsDataList
        if is_predict_true:
            detectionMetricsDataList[0] = count_data
        else:
            #detectionMetricsDataList.append(count_data)
            detectionMetricsDataList[1] = count_data
        
    @synchronized
    def initDetectionMetricsMonitor(self):  
        # 初始化画图组件
        # 创建一个新的matplotlib Figure对象
        self.detectionMetricsFigure = plt.figure(figsize=(5, 5), dpi=100)
        # 将Figure对象封装进FigureCanvas对象中
        self.detectionMetricsCanvas = FigureCanvas(self.detectionMetricsFigure)
        # 创建一个垂直布局容器
        layout = QVBoxLayout()
        layout.addWidget(self.detectionMetricsCanvas)
        #添加为布局
        self.setLayout(layout) 
        self.detectionMetricsAx = self.detectionMetricsFigure.add_subplot()
        #设置Figure中的图像的标题
        self.detectionMetricsFigure.suptitle('预测度量')
        self.detectionMetricsAx.set_ylabel('包数量')
        return self
    
    @synchronized
    def updateDetectionMetricsData(self):
        """Figure图表更新数据"""
        global detectionMetricsDataList
        if len(detectionMetricsDataList)==0:
            return
        # 数据和对应的标签
        data = detectionMetricsDataList
        subject = ['正确预测', '错误预测']
        colors = ['blue', 'gray']
        width = 0.35  # 设置柱子的宽度
        self.detectionMetricsAx.clear()  # 清除上一帧的数据
        # 绘制柱状图并分别为每个柱子添加标签
        for i, (value, name, color) in enumerate(zip(data, subject, colors)):
            self.detectionMetricsAx.bar(name, value,width = width, color=color, label=name)  # 只为第一个柱子添加图例标签以避免重复

        self.detectionMetricsAx.set_ylabel('包数量')
        self.detectionMetricsFigure.suptitle('预测度量')
        self.detectionMetricsAx.legend()
        # 更新后可能需要重新绘制图形以反映新的刻度
        self.detectionMetricsFigure.canvas.draw()
        return data
    
    def init_clock(self): 
        #实例化Figure动画
        #设置定时器，用于更新
        self.detectionMetricsWidgetTimer = QTimer(self)
        self.detectionMetricsWidgetTimer.timeout.connect(self.updateDetectionMetricsData)
        self.detectionMetricsWidgetTimer.start(3000)