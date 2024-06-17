import random
import string
from datetime import date

def generate_dga_domain():
    """
    生成一个简单的DGA域名。
    使用当前日期年月日作为基础种子，结合随机字符串生成域名。
    域名结构为: prefix + random_chars + suffix + TLD
    """
    # 假设前缀和后缀以及顶级域名(TLD)
    prefix = "malware"
    suffix = "bot"
    tld = ["com", "net", "org", "info", "biz"]  # 可能的顶级域名列表
    
    # 当前日期转换为字符串并取后六位作为种子的一部分
    seed_str = str(date.today())[-6:]
    
    # 使用日期种子初始化随机数生成器，确保一定程度的可重复性
    random.seed(int(seed_str))
    
    # 生成随机字符串，长度自定，这里设定为8
    random_chars = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    # 拼接完整的域名
    domain = f"{prefix}{random_chars}.{suffix}.{random.choice(tld)}"
    
    return domain