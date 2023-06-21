import tkinter as tk
import func
import os
from tkinter import *
from tkinter.ttk import *
from tkinter import filedialog
import pickle
from tkinter.messagebox import showinfo

def Filechoose():
    if var_1.get()=='单条分类':
        btn_add1.place_forget()
        btn_add2.place_forget()
        progressbarOne.place_forget()
        lb_3.place_forget()
        path = filedialog.askopenfilename(filetypes=[("PCAP",".pcap")],title="数据流文件选择")
        txt_1.delete(1.0,"end")
        lb_2.place(x=50,y=97,width=80,height=15)
        txt_2.place(x=130,y=95,width=280,height=20)
        txt_2.delete(1.0,"end")
        txt_1.insert(1.0,path)
    if var_1.get()=='批量分类':
        lb_2.place_forget()
        txt_2.place_forget()
        btn_add1.place_forget()
        btn_add2.place_forget()
        path = filedialog.askdirectory(title="文件夹选择")
        lb_3.place(x=50,y=97,width=80,height=20)
        progressbarOne.place(x=130,y=95,width=280,height=25)
        progressbarOne['value'] = 0
        txt_1.delete(1.0,"end")
        txt_1.insert(1.0,path)
    if var_1.get()=='测试':
        lb_2.place_forget()
        txt_2.place_forget()
        path = filedialog.askdirectory(title="文件夹选择")
        btn_add1.place(x=140,y=150,width=100,height=30)
        btn_add2.place(x=20,y=150,width=100,height=30)
        lb_3.place(x=50,y=97,width=80,height=20)
        progressbarOne.place(x=130,y=95,width=280,height=25)
        progressbarOne['value'] = 0
        txt_1.delete(1.0,"end")
        txt_1.insert(1.0,path)

def Addtest_goal():
    progressbarOne['value']=0
    filename = txt_1.get(1.0,"end")[:-1]
    global global_list
    if var.get()==0:
        func.read_heartbit(filename,global_list,1,0,progressbarOne)
    if var.get()==1:
        func.read_heartbit(filename,global_list,1,1,progressbarOne)
    showinfo(title = "提示",message = '导入成功')

def Addtest_other():
    progressbarOne['value']=0
    filename = txt_1.get(1.0,"end")[:-1]
    global global_list
    if var.get()==0:
        func.read_heartbit(filename,global_list,0,0,progressbarOne)
    if var.get()==1:
        func.read_heartbit(filename,global_list,0,1,progressbarOne)
    showinfo(title = "提示",message = '导入成功')


def Classify():
    filename = txt_1.get(1.0,"end")[:-1]
    #判断，0为阿里，1为腾讯
    if var_1.get()=="单条分类":
        if var.get()==0:
            str = func.classfy_ali(aliclassfy,filename)
            txt_2.delete(1.0,"end")
            txt_2.insert(1.0,str)
        else:
            str = func.classfy_tx(txclassfy,filename)
            txt_2.delete(1.0,"end")
            txt_2.insert(1.0,str)
    else:
        #批量处理和测试下
        if var_1.get()=="批量分类":
            if var.get()==0:
                #进度条
                progressbarOne['value']=0
                #读取开始
                testList=[]
                func.read_heartbit(filename,testList,-1,0,progressbarOne)
                func.batch_classfy_ali(testList,aliclassfy)
                testList=[]
                showinfo(title = "提示",message = "分类结束,结果已生成于test目录下")
            if var.get()==1:
                #进度条
                progressbarOne['value']=0
                #读取开始
                testList=[]
                func.read_heartbit(filename,testList,-1,1,progressbarOne)
                func.batch_classfy_tx(testList,txclassfy)
                testList=[]
                showinfo(title = "提示",message = "分类结束,结果已生成于test目录下")
        if var_1.get()=="测试":
            global global_list
            if var.get()==0:
                result=func.test_classfy(global_list,aliclassfy)
                global_list=[]
                showinfo(title = "提示",message = result)
            if var.get()==1:
                result=func.test_classfy(global_list,txclassfy)
                global_list=[]
                showinfo(title = "提示",message = result)


#主函数：
global_list=[]
with open('./data/aliclassfy.pkl', 'rb') as f:
                aliclassfy = pickle.load(f)
with open('./data/txclassfy.pkl', 'rb') as f:
                txclassfy = pickle.load(f)
#主窗口
root =tk.Tk()
root.title('阿里巴巴心跳流分类器')
#宽x高+x轴y轴
root.geometry("500x200+400+200")
root.resizable(width=False,height=False)

#单选框2
var=IntVar()
rd_1 = Radiobutton(root,text="阿里巴巴",variable=var,value=0)
rd_1.place(x=180,y=20,width=90,height=30)
rd_1 = Radiobutton(root,text="腾讯",variable=var,value=1)
rd_1.place(x=280,y=20,width=80,height=30)

var_1 = StringVar()
comb_1 = Combobox(root,state='readnoly',font=("黑体",9),textvariable=var_1,values=['单条分类','批量分类','测试',])
comb_1.place(x=60,y=25,width=90,height=20)

#comb.bind('<<ComboboxSelected>>',)

#按钮组件
btn_file = tk.Button(root,command=Filechoose)
btn_file["text"]="选择文件"
btn_file.place(x=260,y=150,width=100,height=30)
#btn_file.bind('<1>',Filechoose)

btn_classify = tk.Button(root,command=Classify)
btn_classify["text"]="分类"
btn_classify.place(x=380,y=150,width=100,height=30)

btn_add1 = tk.Button(root,command=Addtest_goal)
btn_add1["text"]="导入目标"
btn_add1.place(x=120,y=150,width=100,height=30)
btn_add1.place_forget()

btn_add2 = tk.Button(root,command=Addtest_other)
btn_add2["text"]="导入其他"
btn_add2.place(x=0,y=150,width=100,height=30)
btn_add2.place_forget()

#内容主体
lb_1=tk.Label(root,text='文件路径:',font=("黑体",10))
lb_1.place(x=50,y=62,width=80,height=15)
txt_1=tk.Text(root)
txt_1.place(x=130,y=60,width=280,height=20)
lb_2=tk.Label(root,text='分类结果:',font=("黑体",10))
lb_2.place(x=50,y=97,width=80,height=15)
txt_2=tk.Text(root)
txt_2.place(x=130,y=95,width=280,height=20)
lb_2.place_forget()
txt_2.place_forget()

#进度条
lb_3=tk.Label(root,text='读取进度:',font=("黑体",10))
progressbarOne = tk.ttk.Progressbar(root)
progressbarOne.pack(pady=10)
progressbarOne.place(x=130,y=95,width=280,height=25)
# 进度值最大值
progressbarOne['maximum'] = 100
# 进度值初始值
progressbarOne['value'] = 0
progressbarOne.place_forget()
root.mainloop()

    