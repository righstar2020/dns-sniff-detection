# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'd:\CWord\课程学习\网络安全协议分析\DNS_sniff\gui\ui\mainWindow.ui'
#
# Created by: PyQt5 UI code generator 5.15.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.setEnabled(True)
        MainWindow.resize(1069, 771)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(MainWindow)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtWidgets.QLabel(MainWindow)
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.comboBox_ifaces = ComboBox(MainWindow)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.comboBox_ifaces.sizePolicy().hasHeightForWidth())
        self.comboBox_ifaces.setSizePolicy(sizePolicy)
        self.comboBox_ifaces.setMinimumSize(QtCore.QSize(180, 0))
        self.comboBox_ifaces.setMaximumSize(QtCore.QSize(50, 16777215))
        self.comboBox_ifaces.setCurrentText("")
        self.comboBox_ifaces.setObjectName("comboBox_ifaces")
        self.horizontalLayout.addWidget(self.comboBox_ifaces)
        self.pushButton_run = PrimaryPushButton(MainWindow)
        self.pushButton_run.setObjectName("pushButton_run")
        self.horizontalLayout.addWidget(self.pushButton_run)
        self.pushButton_stop = PushButton(MainWindow)
        self.pushButton_stop.setObjectName("pushButton_stop")
        self.horizontalLayout.addWidget(self.pushButton_stop)
        self.checkBox_only_DNS = CheckBox(MainWindow)
        self.checkBox_only_DNS.setObjectName("checkBox_only_DNS")
        self.horizontalLayout.addWidget(self.checkBox_only_DNS)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.verticalLayout.addLayout(self.horizontalLayout)
        spacerItem1 = QtWidgets.QSpacerItem(20, 2, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        self.verticalLayout.addItem(spacerItem1)
        self.tableWidget_traffic_list = TableWidget(MainWindow)
        self.tableWidget_traffic_list.setMinimumSize(QtCore.QSize(900, 0))
        self.tableWidget_traffic_list.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.tableWidget_traffic_list.setObjectName("tableWidget_traffic_list")
        self.tableWidget_traffic_list.setColumnCount(0)
        self.tableWidget_traffic_list.setRowCount(0)
        self.verticalLayout.addWidget(self.tableWidget_traffic_list)
        self.treeWidget_packet_info = TreeWidget(MainWindow)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.treeWidget_packet_info.sizePolicy().hasHeightForWidth())
        self.treeWidget_packet_info.setSizePolicy(sizePolicy)
        self.treeWidget_packet_info.setMaximumSize(QtCore.QSize(16777215, 200))
        self.treeWidget_packet_info.setEditTriggers(QtWidgets.QAbstractItemView.CurrentChanged|QtWidgets.QAbstractItemView.EditKeyPressed|QtWidgets.QAbstractItemView.SelectedClicked)
        self.treeWidget_packet_info.setExpandsOnDoubleClick(True)
        self.treeWidget_packet_info.setColumnCount(2)
        self.treeWidget_packet_info.setObjectName("treeWidget_packet_info")
        self.treeWidget_packet_info.headerItem().setText(0, "1")
        self.treeWidget_packet_info.headerItem().setText(1, "2")
        self.treeWidget_packet_info.header().setVisible(False)
        self.verticalLayout.addWidget(self.treeWidget_packet_info)
        self.plainTextEdit_console = TextEdit(MainWindow)
        self.plainTextEdit_console.setEnabled(True)
        self.plainTextEdit_console.setMaximumSize(QtCore.QSize(16777215, 120))
        self.plainTextEdit_console.setReadOnly(True)
        self.plainTextEdit_console.setObjectName("plainTextEdit_console")
        self.verticalLayout.addWidget(self.plainTextEdit_console)
        spacerItem2 = QtWidgets.QSpacerItem(20, 3, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        self.verticalLayout.addItem(spacerItem2)
        self.horizontalLayout_2.addLayout(self.verticalLayout)

        self.retranslateUi(MainWindow)
        self.comboBox_ifaces.setCurrentIndex(-1)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "DNS sniff V1.0 by GZHU"))
        self.label.setText(_translate("MainWindow", "监听网卡"))
        self.pushButton_run.setText(_translate("MainWindow", "开始抓包"))
        self.pushButton_stop.setText(_translate("MainWindow", "停止"))
        self.checkBox_only_DNS.setText(_translate("MainWindow", "DNS协议"))
from qfluentwidgets import CheckBox, ComboBox, PrimaryPushButton, PushButton, TextEdit, TreeWidget
from qfluentwidgets  import TableWidget
