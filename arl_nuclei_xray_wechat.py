#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# author:Cedric1314

import requests,json,sys,time,socket
from time import strftime,gmtime
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import datetime
import os
Token=''
ids=[]

# 配置
arl_url='https://ip:port/'
username='username'
password='password'
time_sleep = 1000
get_size = 5

def push_wechat_group(content):
    webhook_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxxxxxxxxxxxx"
    try:
        # print('开始推送')
        # 这里修改为自己机器人的webhook地址
        resp = requests.post(webhook_url,
                             json={"msgtype": "markdown",
                                   "markdown": {"content": content}})
        print(content)
        if 'invalid webhook url' in str(resp.text):
            print('企业微信key 无效,无法正常推送')
            sys.exit()
        if resp.json()["errcode"] != 0:
            raise ValueError("push wechat group failed, %s" % resp.text)
    except Exception as e:
        print(e)
########################################################################################################################

def nuclei(scan_list):
    print(scan_list)
    with open("newurls.txtls","w",encoding='utf-8') as f:
        for scan in scan_list:
            if scan != '':
                f.writelines(scan+"\n")
    os.system("echo \"开始使用 /opt/nuclei 对新增资产进行漏洞扫描\"")
    os.system("cat newurls.txtls | proxychains /opt/nuclei -rl 300 -bs 35 -c 30  -mhe 10 -ni -o res-all-vulnerability-results-$(date +%F-%T).txt -stats -silent -severity critical,medium,high")
    os.system("echo \"/opt/nuclei 漏洞扫描结束\"")
    os.system("cat res-all-vulnerability-results-$(date +%F-%T).txt >> temp1.txt")
    if os.path.getsize('temp1.txt') == 0:
         print('这是空文件')
    else:
        with open("temp1.txt", "r", encoding='utf-8') as f:
            data = f.read()
            f.close()
        push_wechat_group(str(data))     #推送nuclei扫描结果
    os.system('rm -rf temp1.txt') 
    os.system('rm -rf newurls.txtls')   

def xray(scan_list):
    print(scan_list)
    with open("newurls2.txtls", "w", encoding='utf-8') as f:
        for scan in scan_list:
            if scan != '':
                f.writelines(scan + "\n")
    os.system("echo \"开始使用 xray 对新增资产进行漏洞扫描\"")
    os.system("proxychains /opt/xray_linux_amd64 webscan  --url-file newurls2.txtls --json-output temp.json --html-output xray-new-$(date +%F-%T).html")

    with open('temp.json', 'r', encoding='utf-8') as f:
        data = json.load(f)
        f.close()

    for i in range(len(data)):
        current_date = str(strftime("%Y-%m-%d %H:%M:%S", gmtime()))
        message_push = "xray漏洞推送:" + '\n' + current_date + '\n'
        message_push = message_push + "漏洞类型:" + str(data[i]['plugin']) + '\n' + "目标:" + str(
            data[i]['target']) + '\n' + "payload:" + str(data[i]['detail']['payload']) + '\n' + '\n'
        try:
          if 'nginx-wrong-resolve' not in str(message_push) and 'server-error' not in str(message_push) and 'cors' not in str(message_push) and 'dedecms' not in str(message_push) and 'crossdomain' not in str(message_push) and 'dedecms' not in str(message_push):  #过滤掉xray扫描无用的结果           
            push_wechat_group(message_push)   #推送xray扫描结果
        except Exception as e:
            print('推送错误')
    os.system('rm -rf temp.json')
    os.system('rm -rf newurls2.txtls')

while True:
    try:
        data = {"username":username,"password":password}
        headers = {'Content-Type': 'application/json; charset=UTF-8'}
        logreq=requests.post(url=arl_url+'/api/user/login',data=json.dumps(data),headers=headers,timeout=30, verify=False)
        result = json.loads(logreq.content.decode())
        if result['code']==401:
            print(data,'登录失败')
            sys.exit()
        if result['code']==200:
            print(data, '登录成功',result['data']['token'])
            Token=result['data']['token']
        headers = {'Token': Token,'Content-Type': 'application/json; charset=UTF-8'}
        print('开始获取最近侦察资产')
        req =requests.get(url=arl_url+'/api/task/?page=1&size='+str(get_size), headers=headers,timeout=30, verify=False)
        result = json.loads(req.content.decode())
        for xxx in result['items']:
            if xxx['status']=='done':
                ids= []
                ids.append(xxx['_id'])
        ids=str(ids).replace('\'','"')
        ids_result = json.loads(ids)
        data = {"task_id":ids_result}
        req2=requests.post(url=arl_url+'/api/batch_export/site/',data=json.dumps(data),headers=headers,timeout=30, verify=False)
        if '"not login"' in str(req2.text):
            ids = []
            continue
        target_list=req2.text.split()
        file_list=open('./cache.txt', 'r', encoding='utf-8').read().split('\n')
        add_list=set(file_list).symmetric_difference(set(target_list))
        current_time=str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')).replace(' ','-').replace(':','-')
        for xxxx in add_list:
            if xxxx in target_list:
                caches_file=open('./cache.txt', 'a', encoding='utf-8')
                caches_file.write(xxxx+'\n')
                caches_file.close()
                get_log=open('get_log/'+current_time+'.txt','a+', encoding='utf-8')
                get_log.write(xxxx+'\n')
                get_log.close()
                print(xxxx)
        nuclei(add_list)
        xray(add_list)
        time.sleep(int(time_sleep))
        Token = ''
        ids = []

    except Exception as e:
        print(e,'出错了，请排查')