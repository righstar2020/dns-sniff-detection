from scapy.all import sniff, DNS
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
import os
"""
    DNS检测模块
"""
class DNSDetection():
    def __init__(self) -> None:
        self.text_vectorizer = None
        self.domain_detect_model = None
        self.load_detect_model()
        # 获取当前脚本所在的目录
        
    def load_detect_model(self):
        parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        detect_model_path = parent_dir+"/data_set/model_save/逻辑回归.pkl"
        detect_vectorizer_path = parent_dir+'/data_set/model_save/tfidf_vectorizer.pickle'
        print(f"加载模型文件:{detect_model_path}")
        print(f"加载词向量器:{detect_vectorizer_path}")
        #加载检测模型
        with open(detect_model_path, 'rb') as file:
            self.domain_detect_model = pickle.load(file)    
        #从文件加载vectorizer(tfidf文本向量处理器,保证文本处理后向量维度相同)
        with open(detect_vectorizer_path, 'rb') as file:
            self.text_vectorizer = pickle.load(file)
        
    #预处理文本
    def preprocess_text_to_vector(self,text):
        #使用Tfidf将文本转化为向量
        X = None
        if self.text_vectorizer!=None:
            X = self.text_vectorizer.transform([text])
        return X
    def detect_domain(self,domain):
        predict_domain_type = 'good'
        if self.domain_detect_model!=None:
            try:
                prediction = self.domain_detect_model.predict(self.preprocess_text_to_vector(domain))[0]
                if prediction==0:
                    predict_domain_type = 'bad'
            except Exception as e:
                print(f"error:{e}")
        print(f"{domain} is {predict_domain_type}")
        return predict_domain_type
        
