# coding:utf-8
import sys

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication, QWidget, QStackedWidget, QVBoxLayout, QLabel, QHBoxLayout

from qfluentwidgets import Pivot, setTheme, Theme, FluentIcon, SegmentedToggleToolWidget, SegmentedToolWidget


class Demo(QWidget):

    def __init__(self):
        super().__init__()
        # setTheme(Theme.DARK)
        self.setStyleSheet("""
            Demo{background: white}
            QLabel{
                font: 20px 'Segoe UI';
                background: rgb(242,242,242);
                border-radius: 8px;
            }
        """)
        self.resize(400, 400)

        # self.pivot = SegmentedToolWidget(self)
        self.pivot = SegmentedToggleToolWidget(self)
        self.stackedWidget = QStackedWidget(self)

        self.hBoxLayout = QHBoxLayout()
        self.vBoxLayout = QVBoxLayout(self)

        self.songInterface = QLabel('Song Interface', self)
        self.albumInterface = QLabel('Album Interface', self)
        self.artistInterface = QLabel('Artist Interface', self)

        # add items to pivot
        self.addSubInterface(self.songInterface, 'songInterface', FluentIcon.MUSIC)
        self.addSubInterface(self.albumInterface, 'albumInterface', FluentIcon.ALBUM)
        self.addSubInterface(self.artistInterface, 'artistInterface', FluentIcon.PEOPLE)

        self.hBoxLayout.addWidget(self.pivot, 0, Qt.AlignCenter)
        self.vBoxLayout.addLayout(self.hBoxLayout)
        self.vBoxLayout.addWidget(self.stackedWidget)
        self.vBoxLayout.setContentsMargins(30, 10, 30, 30)

        self.stackedWidget.currentChanged.connect(self.onCurrentIndexChanged)
        self.stackedWidget.setCurrentWidget(self.songInterface)
        self.pivot.setCurrentItem(self.songInterface.objectName())

    def addSubInterface(self, widget: QLabel, objectName, icon):
        widget.setObjectName(objectName)
        widget.setAlignment(Qt.AlignCenter)
        self.stackedWidget.addWidget(widget)
        self.pivot.addItem(
            routeKey=objectName,
            onClick=lambda: self.stackedWidget.setCurrentWidget(widget),
            icon=icon
        )

    def onCurrentIndexChanged(self, index):
        widget = self.stackedWidget.widget(index)
        self.pivot.setCurrentItem(widget.objectName())


if __name__ == '__main__':
    # enable dpi scale
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)

    app = QApplication(sys.argv)
    w = Demo()
    w.show()
    app.exec_()