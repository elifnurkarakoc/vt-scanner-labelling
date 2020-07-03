#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import requests
from prettytable import PrettyTable

def table_horizontal(dict_):  
    
    x = PrettyTable()
    
    x.field_names =dict_.keys()
    
    x.add_row(dict_.values())
        
    print(x)
def table_vertical(dict_):
    x = PrettyTable()
    
    x.field_names =["Antivirus","Result"]
    
    for key,value in dict_.items():
        x.add_row([key,value])
        
    print(x)
    
def label_url(result_dic):
    
    label_dic={}
    
    for key,value in result_dic.items():
      value=value.replace(" site","")
      label_dic[str(value)]=0
      
    for key,value in result_dic.items():
      value=value.replace(" site","")
      label_dic[str(value)]+=1
      
    url_label=max(label_dic, key=label_dic.get)
    
    return label_dic,url_label


def get_result(result):
    
    result_dic={}
    
    if result['positives']!=0:
        for scan in result['scans']:
          for value in result['scans'][str(scan)]:
            if value=="detected":
              if result['scans'][str(scan)]["detected"]==True:
                result_dic[str(scan)]=result['scans'][str(scan)]["result"]
                
    return result_dic

def label_malware_file(result_dic):
    malware={"Trojan":0,"Worms":0,"Rootkit":0,"Agent":0,"Crypt":0,"Downloader":0,"Dropper":0,"Backdoor":0,"Spam":0,"Ransomware":0,"Keylogger":0,"Spyware":0,"Riskware":0,"Virus":0,"Adware":0,"Malware":0}
    for key,value in result_dic.items():
      for key_,value_ in malware.items():
        if key_ in value:
          malware[key_]+=1
    label=max(malware, key=malware.get)
    return malware,label

def file_scan(filepath,apikey):
    vt_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': apikey}
    files={'file': (str(filepath), open(str(filepath), 'rb'))}
    response = requests.post(vt_url, files=files, params=params, allow_redirects=False)
    if str(response.status_code)=="200":
      result = response.json()
      return result['md5']
    return ""


def file_scan_result(file_hash,apikey):
    vt_url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': apikey,
              'resource': file_hash}
    response = requests.get(vt_url, params=params)
    time.sleep(2) 
    if str(response.status_code)=="200":
      result = response.json()    
      if result['response_code'] == 0:
        print('VT: %0')
      else:
        response_dic={"MD5":str(result['md5']),"SHA1":str(result['sha1']),"SHA256":str(result['sha256']),"Total":str(result['total']),'Positives':str(result['positives']),"VirusTotal%":str(str(result['positives']/result['total'])),"Scan date":str(result['scan_date'])}
        table_horizontal(response_dic)
        result_dic=get_result(result)
        if result_dic!={}:
            malware,label=label_malware_file(result_dic)
            result_dic.update({"VT Scanner Label":str(label)})
            if len(result_dic)<9:
                table_horizontal(result_dic)
            if len(result_dic)>9:
                table_vertical(result_dic)
    else:
      print(response.status_code)


def url_report(url,apikey):
    vt_url="https://www.virustotal.com/vtapi/v2/url/report"
    params = {'apikey': apikey,
              'resource': url}
    response = requests.get(vt_url, params=params)
    time.sleep(2) 
    if str(response.status_code)=="200":
      result = response.json()  
      if result['response_code'] == 0:
        print('VT: %0')
      else:     
        response_dic={"Total":str(result['total']),'Positives':str(result['positives']),"VirusTotal%":str(str(result['positives']/result['total'])),"Scan date":str(result['scan_date'])}
        table_horizontal(response_dic)
        result_dic={}
        for scan in result['scans']:
          for value in result['scans'][str(scan)]:
             if result['scans'][str(scan)]["result"]!='clean site':
                 if result['scans'][str(scan)]["result"]!='unrated site':
                     result_dic[str(scan)]=result['scans'][str(scan)]["result"]
        label_dic,url_label=label_url(result_dic)
        result_dic.update({"VT Scanner Label":str(url_label)})
        if len(result_dic)<9:
            table_horizontal(result_dic)
        if len(result_dic)>9:
            table_vertical(result_dic)
