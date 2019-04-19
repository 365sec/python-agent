import pickle

from django.http import HttpResponse, response, StreamingHttpResponse
from .settings import *
from django.shortcuts import render, redirect
import os
import pymysql.cursors
import json
from django.views.decorators.csrf import csrf_exempt

def index(request):
    return render(request, 'index.html', {})

# writefile
# readfile()
#
# uploadfile
def readfile(request):
    f= open("11.txt","r")
    return HttpResponse("read file! ")
def writefile(request):
    cwd=os.getcwd()
   # os.chdir("e:")
    f= open("11.txt","w")
    print(type(f))
    f.write('aaaa')
    f.close()
    return HttpResponse("write file! ")

def multipart_mysql(request,*args):

    connect = pymysql.connect(
        host='127.0.0.1',
        port=3306,
        user='root',
        passwd='123456',
        db='test'
    )
    # 获取游标
    cursor = connect.cursor()
    sql=request.GET.get('id')
    cursor.execute(sql)
    # 提交到数据库执行
    connect.commit()
    results = cursor.fetchall()
    cursor.close()
    connect.close()
    results=json.dumps(results)
    return HttpResponse(results)

@csrf_exempt
def upload_file(request):
    if request.method == "POST":    # 请求方法为POST时，进行处理

        myFile =request.FILES.get("file", None)    # 获取上传的文件，如果没有文件，则默认为None
        if not myFile:
            return HttpResponse("no files for upload!")
        destination = open(os.path.join("E:\\upload",myFile.name),'wb+')    # 打开特定的文件进行二进制的写操作
        for chunk in myFile.chunks():      # 分块写入文件
            destination.write(chunk)
        destination.close()
    return HttpResponse("upload over!")

def windows_querystring_none(request,*args):
    string=""
    # print(os.system('ping wwww.baidu.com'))
    cmd ='dir'
    cmd=request.GET.get('cmd')
    string= os.system(cmd)
    return HttpResponse(string)

def windows_querystring_str(request,*args):
    string=""
    # print(os.system('ping wwww.baidu.com'))
    cmd ='dir'
    cmd=request.GET.get('cmd')
    string= os.popen(cmd)
    return HttpResponse(string)

class aA:
    name="1111"
    def aaa(self):
        pass
    def __reduce__(self):
        return (os.system,('dir',))
a = aA()
def transformer(request):
    # dic = {'age': 23, 'job': 'student'}
    # byte_data = pickle.dumps(dic)
    # # out -> b'\x80\x03}q\x00(X\x03\x00\x00\...'
    # # print(byte_data)
    # dic1=pickle.loads(byte_data)
    # # print(type(dic1))

        # 序列化
    # with open('abc.pkl', 'wb') as f:
    #     pickle.dump(a, f)
    # # 反序列化
    # with open('abc.pkl', 'rb') as f:
    #     # print(f.read())
    #     aa = pickle.load(f)
    #     # print(aa)
    #     # print(type(f))
    #     # print(type(aa))  # <class 'dict'>
        return HttpResponse("transformer")

def dir_none(request,*args):

    dirname=request.GET.get('dirname')
    files = os.listdir(dirname)

    return HttpResponse("\n".join(files))


def dir_join(request):
    files = os.listdir('./static')
    print(files)
    return HttpResponse(files)
