# coding:utf-8
import sys
import os
#设置项目根目录不然没法跨文件夹调用模块
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)
from PyQt5.QtWidgets import QMainWindow, QMessageBox
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt, QUrl
from PyQt5.QtGui import QIcon, QDesktopServices
from PyQt5 import QtGui
from PyQt5.QtWidgets import QApplication, QFrame, QHBoxLayout
from qframelesswindow import FramelessWindow, StandardTitleBar, AcrylicWindow
from qfluentwidgets import (NavigationItemPosition, MessageBox, setTheme, Theme, FluentWindow,
                            NavigationAvatarWidget, qrouter, SubtitleLabel, setFont, InfoBadge,
                            InfoBadgePosition,MSFluentWindow)
from qfluentwidgets import FluentIcon as FIF
from  sniffWidget import SniffWidget
from  dnsWidget import DNSWidget



class MainWindow(MSFluentWindow):

    def __init__(self):
        super().__init__()

        # create sub interface
        sniffWidget = SniffWidget('sniff widget', self)
        
        dnsWidget = DNSWidget('dns widget', self)
        sniffWidget.setupUi(sniffWidget)
        self.sniffWidgetInterface = sniffWidget
        dnsWidget.setupUi(dnsWidget)
        self.dnsWidgetInterface = dnsWidget
        #把SniffWidget绑定到DNS检测模块
        dnsWidget.bindSniffWidget(sniffWidget)

        self.initNavigation()
        self.initWindow()

    def initWindow(self):
        self.resize(1050, 750)
        self.setResizeEnabled(False)
        #self.setMaximumSize(1050,700)
        #self.setMinimumSize(1050, 700)
        self.setWindowTitle('DNS sniff V1.0 by GZHU')
        self.setWindowIcon(QIcon(':/qfluentwidgets/images/logo.png'))

        desktop = QApplication.desktop().availableGeometry()
        w, h = desktop.width(), desktop.height()
        self.move(w//2 - self.width()//2, h//2 - self.height()//2)

    def initNavigation(self):
        self.addSubInterface(self.sniffWidgetInterface, FIF.GLOBE, 'sniff', FIF.GLOBE)
        self.addSubInterface(self.dnsWidgetInterface, FIF.IOT, 'detection', FIF.IOT)
        self.navigationInterface.addItem(
            routeKey='Help',
            icon=FIF.HELP,
            text='帮助',
            onClick=self.showMessageBox,
            selectable=False,
            position=NavigationItemPosition.BOTTOM,
        )
        self.navigationInterface.setCurrentItem(self.sniffWidgetInterface.objectName())
    def switchToSample(self, routeKey, index):
        """ switch to sample """
        interfaces = self.findChildren(self)
        for w in interfaces:
            if w.objectName() == routeKey:
                self.stackedWidget.setCurrentWidget(w, False)
                w.scrollToCard(index)
    def showMessageBox(self):
        w = MessageBox(
            'Author',
            'rightstar from GZHU 🥤🥤🥤',
            self
        )
        w.yesButton.setText('确定')
        w.cancelButton.setText('取消')

        if w.exec():
            #QDesktopServices.openUrl(QUrl("https://baidu.com"))
            pass


    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        print("触发主窗口关闭事件")
        return
        # if int(self.is_autoScan) == 1:
            # event.accept()
            # return

        reply = QMessageBox.question(self, 'Message', '您确定要关闭吗？',
                                               QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
        if reply == QMessageBox.No:
            event.ignore()

def main():
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)
    app = QApplication(sys.argv)
    #父类QMainWindow
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
