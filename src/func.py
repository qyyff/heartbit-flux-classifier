import pickle
from sklearn.metrics import precision_score
from sklearn.metrics import accuracy_score
from sklearn.metrics import recall_score
from scapy.all import *
import csv
import base64
import numpy as np
import os

#返回阿里心跳流特征项集匹配向量
def match_vector_ali(payloadlist):
    with open('.\\data\\itemset_ali.pickle', 'rb') as f:
        results = pickle.load(f)
    n_data = len(payloadlist)  # 数据点个数
    n_itemsets = len(results)  # 频繁项集个数
    feature_matrix = [[0] * n_itemsets for _ in range(n_data)] # 频繁项集匹配矩阵
    #遍历每个负载的每个项集
    for i, payload in enumerate(payloadlist):
        for j, itemset in enumerate(results):
            if set(itemset.items).issubset(payload):
                feature_matrix[i][j] = 1
    feature_matrix = np.array(feature_matrix)
    #计算每列平均值，转为一维列表，表示每一个心跳流与频繁项集的匹配程度
    mean_list = np.mean(feature_matrix, axis=0)
    return mean_list

#返回腾讯心跳流特征项集匹配向量
def match_vector_tx(payloadlist):
    with open('.\\data\\itemset_tx.pickle', 'rb') as f:
        results = pickle.load(f)
    n_data = len(payloadlist)  # 数据点个数
    n_itemsets = len(results)  # 频繁项集个数
    feature_matrix = [[0] * n_itemsets for _ in range(n_data)]
    for i, payload in enumerate(payloadlist):
        for j, itemset in enumerate(results):
            if set(itemset.items).issubset(payload):
                feature_matrix[i][j] = 1
    feature_matrix = np.array(feature_matrix)
    #计算每列平均值，转为一维列表，表示每一个心跳流与频繁项集的匹配程度
    mean_list = np.mean(feature_matrix, axis=0)
    return mean_list

#因相对路径问题，供测试函数使用
def match_vector_ali1(payloadlist):
    with open('..\\data\\itemset_ali.pickle', 'rb') as f:
        results = pickle.load(f)
    n_data = len(payloadlist)  # 数据点个数
    n_itemsets = len(results)  # 频繁项集个数
    feature_matrix = [[0] * n_itemsets for _ in range(n_data)] # 频繁项集匹配矩阵
    #遍历每个负载的每个项集
    for i, payload in enumerate(payloadlist):
        for j, itemset in enumerate(results):
            if set(itemset.items).issubset(payload):
                feature_matrix[i][j] = 1
    feature_matrix = np.array(feature_matrix)
    #计算每列平均值，转为一维列表，表示每一个心跳流与频繁项集的匹配程度
    mean_list = np.mean(feature_matrix, axis=0)
    return mean_list

#因相对路径问题，供测试函数使用
def match_vector_tx1(payloadlist):
    with open('..\\data\\itemset_tx.pickle', 'rb') as f:
        results = pickle.load(f)
    n_data = len(payloadlist)  # 数据点个数
    n_itemsets = len(results)  # 频繁项集个数
    feature_matrix = [[0] * n_itemsets for _ in range(n_data)]
    for i, payload in enumerate(payloadlist):
        for j, itemset in enumerate(results):
            if set(itemset.items).issubset(payload):
                feature_matrix[i][j] = 1
    feature_matrix = np.array(feature_matrix)
    #计算每列平均值，转为一维列表，表示每一个心跳流与频繁项集的匹配程度
    mean_list = np.mean(feature_matrix, axis=0)
    return mean_list

#读取单个阿里心跳流pcap文件
def read_testpcap_ali(filename):
    payloadlist=[]
    lenlist=[]
    timelist=[]
    packets = rdpcap(filename)
    ipflag=''
    readflag=0
    for j in range(len(packets)):
        if TCP in packets[j]:
            lenlist.append(len(packets[j][TCP].payload))
        else:
            lenlist.append(0)
        if((ipflag==packets[j][IP].dst)and(packets[j].time-temptime)>1):
            timelist.append(round(packets[j].time-temptime))
            ipflag=''
            readflag=0
        else: 
            if(readflag==0):
                ipflag=packets[j].dst
                temptime=packets[j].time
                readflag=1
        if TCP in packets[j]:
            payloadlist.append(base64.b64encode(bytes(packets[j][TCP].payload)))
        else:
            payloadlist.append(base64.b64encode(bytes(packets[j][UDP].payload)))
    plist=match_vector_ali(payloadlist)
    lenarray=np.array(lenlist)
    timearray=np.array(timelist)
    alist=[np.amax(lenarray),np.amin(lenarray),np.std(lenarray),np.argmax(np.bincount(timearray)),]
    finlist=list(plist)+alist
    return finlist

#读取单个腾讯心跳流pcap文件
def read_testpcap_tx(filename):
    payloadlist=[]
    lenlist=[]
    timelist=[]
    packets = rdpcap(filename)
    ipflag=''
    readflag=0
    for j in range(len(packets)):
        if TCP in packets[j]:
            lenlist.append(len(packets[j][TCP].payload))
        else:
            lenlist.append(0)
        if((ipflag==packets[j][IP].dst)and(packets[j].time-temptime)>1):
            timelist.append(round(packets[j].time-temptime))
            ipflag=''
            readflag=0
        else: 
            if(readflag==0):
                ipflag=packets[j].dst
                temptime=packets[j].time
                readflag=1
        if TCP in packets[j]:
            payloadlist.append(base64.b64encode(bytes(packets[j][TCP].payload)))
        else:
            payloadlist.append(base64.b64encode(bytes(packets[j][UDP].payload)))
    plist=match_vector_tx(payloadlist)
    lenarray=np.array(lenlist)
    timearray=np.array(timelist)
    alist=[np.amax(lenarray),np.amin(lenarray),np.std(lenarray),np.argmax(np.bincount(timearray)),]
    finlist=list(plist)+alist
    return finlist

#阿里单条心跳流分类
def classfy_ali(aliclassfy,filename):
    list=read_testpcap_ali(filename)
    result=aliclassfy.predict([list])
    if result==1:
        return("该心跳流归属于阿里服务")
    else:
        return("该心跳流不属于阿里服务")

#腾讯单条心跳流分类   
def classfy_tx(aliclassfy,filename):
    list=read_testpcap_tx(filename)
    result=aliclassfy.predict([list])
    if result==1:
        return("该心跳流归属于腾讯服务")
    else:
        return("该心跳流不属于腾讯服务")

#输入文件夹路径，批量导入心跳流并提取其心跳流长度最大值、最小值、方差、间隔、频繁项集匹配向量，返回最后一列为istarget的特征矩阵，用于对模型进行测试或批量读取数据用于分类
#type为0表示提取的特征用于阿里分类模型,type为1表示提取的特征用于腾讯分类模型。istarget为该报文对应的标签，1为阿里/腾讯，0为其他，-1表示数据用于分类，标签未知（两者以不同的特征项集来计算匹配向量）
def read_heartbit(folder_path,dataList,istarget,type,progressbarOne):
    payloadlist=[]
    lenlist=[]
    timelist=[]
    payloadlist=[]
    k=0
    if not os.path.exists(folder_path):
        print("文件夹路径不存在")
        exit()
    #计算文件总数
    files = os.listdir(folder_path)
    count = len(files)
    for file_name in os.listdir(folder_path):
        if file_name.endswith(".pcap"):
            file_path = os.path.join(folder_path, file_name)
            try:
                k+=1
                progressbarOne["value"] = k*100/count
                progressbarOne.update()
                packets = rdpcap(file_path)
            except:
                continue
        #标记是否已记录提取间隔需要的标记IP
        ipflag1=''
        ipflag2=''
        readflag1=0
        readflag2=0
        try:
            for j in range(2,len(packets)):
                if TCP in packets[j]:
                    lenlist.append(len(packets[j][TCP].payload))
                else:
                    lenlist.append(0)
                if((ipflag1==packets[j][IP].dst)and(packets[j].time-temptime1)>1):
                    timelist.append(round(packets[j].time-temptime1))
                    ipflag1=''
                    readflag1=0
                else: 
                    if(readflag1==0):
                        ipflag1=packets[j].dst
                        temptime1=packets[j].time
                        readflag1=1
                if((ipflag2==packets[j][IP].src)and(packets[j].time-temptime2)>1):
                    timelist.append(round(packets[j].time-temptime2))
                    ipflag2=''
                    readflag2=0
                else: 
                    if(readflag2==0):
                        ipflag2=packets[j].src
                        temptime2=packets[j].time
                        readflag2=1
                if TCP in packets[j]:
                    payloadlist.append(base64.b64encode(bytes(packets[j][TCP].payload)))
                else:
                    payloadlist.append(base64.b64encode(bytes(packets[j][UDP].payload)))
            if type==0:
                plist=match_vector_ali(payloadlist)
            if type==1:
                plist=match_vector_tx(payloadlist)
            lenarray=np.array(lenlist)
            timearray=np.array(timelist)
            payloadlist=[]
            lenlist=[]
            timelist=[]
            alist=[np.amax(lenarray),np.amin(lenarray),np.std(lenarray),np.argmax(np.bincount(timearray)),file_name,istarget]
            finlist=list(plist)+alist
            dataList.append(finlist)
        except:
            continue
#输入文件夹路径，批量导入心跳流并提取其心跳流长度最大值、最小值、方差、间隔、频繁项集匹配向量，返回最后一列为istarget的特征矩阵，用于对模型进行测试或批量读取数据用于分类
#type为0表示提取的特征用于阿里分类模型,type为1表示提取的特征用于腾讯分类模型。istarget为该报文对应的标签，1为阿里/腾讯，0为其他，-1表示数据用于分类，标签未知（两者以不同的特征项集来计算匹配向量）
def read_heartbit_test(folder_path,dataList,istarget,type):
    payloadlist=[]
    lenlist=[]
    timelist=[]
    payloadlist=[]
    if not os.path.exists(folder_path):
        print("文件夹路径不存在")
        exit()
    #计算文件总数
    files = os.listdir(folder_path)
    count = len(files)
    for file_name in os.listdir(folder_path):
        if file_name.endswith(".pcap"):
            file_path = os.path.join(folder_path, file_name)
            try:
                packets = rdpcap(file_path)
            except:
                continue
        #标记是否已记录提取间隔需要的标记IP
        ipflag1=''
        ipflag2=''
        readflag1=0
        readflag2=0
        try:
            for j in range(2,len(packets)):
                if TCP in packets[j]:
                    lenlist.append(len(packets[j][TCP].payload))
                else:
                    lenlist.append(0)
                if((ipflag1==packets[j][IP].dst)and(packets[j].time-temptime1)>1):
                    timelist.append(round(packets[j].time-temptime1))
                    ipflag1=''
                    readflag1=0
                else: 
                    if(readflag1==0):
                        ipflag1=packets[j].dst
                        temptime1=packets[j].time
                        readflag1=1
                if((ipflag2==packets[j][IP].src)and(packets[j].time-temptime2)>1):
                    timelist.append(round(packets[j].time-temptime2))
                    ipflag2=''
                    readflag2=0
                else: 
                    if(readflag2==0):
                        ipflag2=packets[j].src
                        temptime2=packets[j].time
                        readflag2=1
                if TCP in packets[j]:
                    payloadlist.append(base64.b64encode(bytes(packets[j][TCP].payload)))
                else:
                    payloadlist.append(base64.b64encode(bytes(packets[j][UDP].payload)))
            if type==0:
                plist=match_vector_ali1(payloadlist)
            if type==1:
                plist=match_vector_tx1(payloadlist)
            lenarray=np.array(lenlist)
            timearray=np.array(timelist)
            payloadlist=[]
            lenlist=[]
            timelist=[]
            alist=[np.amax(lenarray),np.amin(lenarray),np.std(lenarray),np.argmax(np.bincount(timearray)),istarget]
            finlist=list(plist)+alist
            dataList.append(finlist)
        except Exception as e:
            print(f"Compilation error: {e}")

#批量阿里心跳流分类
def batch_classfy_ali(dataList,aliclassfy):
    data = np.array(dataList)
    col=data.shape[1]
    name=data[:,-2]
    X = data[:, :(col-2)].astype(np.float64)
    y_pred=aliclassfy.predict(X)
    print(y_pred)
    with open('./test/output.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['文件名称', '分类结果'])
        for i in range(len(name)):
            if(y_pred[i]==1):
                writer.writerow([name[i], "阿里"])
            else:
                writer.writerow([name[i], "其他"])

#批量腾讯心跳流分类
def batch_classfy_tx(dataList,txclassfy):
    data = np.array(dataList)
    col=data.shape[1]
    name=data[:,-2]
    X = data[:, :(col-2)].astype(np.float64)
    y_pred=txclassfy.predict(X)
    with open('./test/output.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['分类名称', '分类结果'])
        for i in range(len(name)):
            if(y_pred[i]==1):
                writer.writerow([name[i], "腾讯"])
            else:
                writer.writerow([name[i], "其他"])

#用于对模型进行测试
def test_classfy(dataList,classfy):
    data = np.array(dataList)
    col=data.shape[1]
    y=data[:,-1].astype(np.float64)
    X = data[:, :(col-2)].astype(np.float64)
    y_pred=classfy.predict(X)
    p=precision_score(y,y_pred)
    a=accuracy_score(y,y_pred)
    r=recall_score(y, y_pred, pos_label=1)
    result="模型精确度:"+str(p)+"\n"+"模型准确率:"+str(a)+"\n"+"模型召回率:"+str(r)
    return(result)