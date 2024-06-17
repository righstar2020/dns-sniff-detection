from scapy.all import *
#   导入scapy包
from scapy.arch.windows import get_windows_if_list
import platform
class NetworkUtil(): 
    def check_os_Window(self):
        # 获取当前操作系统名称
        os_name = platform.system()
        if os_name == "Windows":
            print("当前系统为 Windows")
            return True
        else:
            print("当前系统不是 Windows")
            return True
    #代表获得网卡名称的函数
    def get_interface(self):
        #   获取网卡名称信息，并存入列表
        interface_info_list=[]
        interface_names_list=[]
        if self.check_os_Window():       
            for interface in get_windows_if_list():
                interface_info_list.append(interface)
                interface_names_list.append(interface.get('name'))
        if len(interface_names_list)==0:
            interface_names_list=conf.ifaces
        return interface_info_list,interface_names_list