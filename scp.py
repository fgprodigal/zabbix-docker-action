#!/usr/bin/env python3

import argparse
import datetime
import json
import uuid
from urllib.parse import urlparse
import hashlib
import hmac
import requests
from requests import auth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

BASE_URL = 'https://localhost/janus'
ACCESS_KEY = ''
SECRET_KEY = ''
AUTH = ''
HEADERS = {}

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Ec2Signer(object):
    """EC2签名工具类"""
    def __init__(self, secret_key):
        self.secret_key = secret_key.encode() if not isinstance(secret_key, bytes) else secret_key
        self.hmac = hmac.new(self.secret_key, digestmod=hashlib.sha1)
        if hashlib.sha256:
            self.hmac_256 = hmac.new(self.secret_key, digestmod=hashlib.sha256)
    
    def generate(self, credentials):
        """根据凭证生成签名"""
        # 假设我们使用的是v4签名
        return self._calc_signature_4(
            credentials['params'],
            credentials['verb'],
            credentials['host'],
            credentials['path'],
            credentials['headers'],
            credentials['body_hash']
        )
    
    def _get_utf8_value(self, value):
        """获取值的UTF8编码版本"""
        if not isinstance(value, (bytes, str)):
            value = str(value)
        if isinstance(value, str):
            return value.encode('utf-8')
        else:
            return value
    
    def _calc_signature_4(self, params, verb, server_string, path, headers, body_hash):
        """生成AWS签名版本4"""
        def sign(key, msg):
            return hmac.new(key, self._get_utf8_value(msg), hashlib.sha256).digest()
        
        def signature_key(datestamp, region_name, service_name):
            """签名密钥生成"""
            k_date = sign(self._get_utf8_value(b"AWS4" + self.secret_key), datestamp)
            k_region = sign(k_date, region_name)
            k_service = sign(k_region, service_name)
            k_signing = sign(k_service, "aws4_request")
            return k_signing
        
        # 从Authorization头或X-Amz-Date参数获取日期
        amz_date = headers.get('X-Amz-Date')
        
        # 从日期中提取日期部分(YYYYMMDD)
        datestamp = amz_date[0:8]
        
        # 提取区域和服务信息
        credential = headers['Authorization'].split(' ')[1].split(',')[0]
        region = credential.split('/')[2]
        service = credential.split('/')[3]
        
        # 创建规范请求
        canonical_uri = path
        canonical_querystring = ''
        
        # 创建规范请求头
        canonical_headers = ''
        signed_headers = 'cookie;x-amz-date'
        for header_name in signed_headers.split(';'):
            canonical_headers += f"{header_name}:{headers.get(header_name, '')}\n"
        
        # 创建规范请求
        canonical_request = f"{verb}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{body_hash}"
        
        # 创建签名字符串
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
        string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        
        # 计算签名
        signing_key = signature_key(datestamp, region, service)
        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        
        return signature

class EC2RequestAuth(auth.AuthBase):
    """EC2 签名类"""

    def __init__(self, access_key, secret_key, region, service):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.service = service

    def __call__(self, r, *args, **kwargs):
        ec2_headers = self.get_ec2_request_headers_handler(r)
        r.headers.update(ec2_headers)
        return r

    def get_ec2_request_headers_handler(self, r):
        """获取EC2请求头句柄
        如果 get_ec2_request_headers 无法满足需求时，可以继承 EC2 签名类，然后重写该
        函数。
        """
        return self.get_ec2_request_headers(r=r,
                                            access_key=self.access_key,
                                            secret_key=self.secret_key)

    def get_ec2_request_headers(self, r, access_key, secret_key):
        """获取EC2请求头
        :param r: request 请求实例
        :param access_key: AK
        :param secret_key: SK
        :return: EC2 签名头, e.g
        {
        'Authorization': 'AWS4-HMAC-SHA256 Credential={AK}/20210105/cn-south-1/sdk/a
        ws4_request, '
        'SignedHeaders=path;x-amz-date, '
        'Signature=fff5b016763f84b5feb10d84296da4251b919c2e10e703a7
        9dfea2a1fe1f151d',
        'x-amz-date': '20210105T112300Z'
        }
        """
        signer = Ec2Signer(secret_key)
        algorithm = 'AWS4-HMAC-SHA256'
        t = datetime.datetime.now()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')
        headers = r.headers.copy()
        # 注意：目前不支持使用host作为签名头，其他只要存在与headers中的字段均可用来做签名头。
        signed_headers = 'cookie;x-amz-date'
        credential_scope = '/'.join([
            datestamp, self.region, self.service, 'aws4_request'
        ])
        authorization_header = '{} Credential={}/{}, SignedHeaders={}'.format(
            algorithm, access_key, credential_scope, signed_headers)
        headers.update({
            'Authorization': authorization_header,
            'X-Amz-Date': amzdate
        })
        _, host, path, _, _, _ = urlparse(r.url)
        body = r.body or ''
        try:
            body_hash = hashlib.sha256(body.encode()).hexdigest()
        except AttributeError:
            body_hash = hashlib.sha256(body).hexdigest()
        credentials = {
            'params': {},
            'verb': r.method,
            'host': host,
            'path': path,
            'headers': headers,
            'body_hash': body_hash
        }
        signature = signer.generate(credentials)
        authorization_header += ', Signature=%s' % signature
        headers.update({
            'Authorization': authorization_header
        })
        return headers

def discovery(discovery_type):
  if discovery_type == 'hosts':
    url = f'{BASE_URL}/20190725/hosts?page_size=1000'
    
    response = requests.get(url, auth=AUTH, headers=HEADERS, verify=False)
    response.raise_for_status()
    data = response.json()
    
    hosts = data['data']['data']
    filtered_hosts = { 'data': [] }
    for host in hosts:
        if host['cluster_type'] == 'hci':
          filtered_hosts["data"].append({
              '{#HOST_NAME}': host['name'],
              '{#CLUSTER_NAME}': host['cluster_name'],
              '{#CLUSTER_TYPE}': host['cluster_type'],
              '{#HOST_ID}': host['id'],
              '{#HOST_TYPE}': host['type'],
              '{#HOST_STATUS}': host['status'],
              '{#CLUSTER_ID}': host['cluster_id']
          })
    return json.dumps(filtered_hosts, indent=2, ensure_ascii=False)
  elif discovery_type == 'servers':
    url = f'{BASE_URL}/20200725/servers?page_size=1000'
    
    response = requests.get(url, auth=AUTH, headers=HEADERS, verify=False)
    response.raise_for_status()
    data = response.json()
    
    servers = data['data']['data']
    filtered_servers = { 'data': [] }
    for server in servers:
        if server['type'] == 'hci':
          filtered_servers["data"].append({
              '{#SERVER_NAME}': server['name'],
              '{#OS_NAME}': server['os_name'],
              '{#SERVER_ID}': server['id'],
              '{#VM_ID}': server['vm_id'],
              '{#HOST_ID}': server['host_id'],
              '{#VMTYPE}': server['vmtype'],
              '{#UPTIME}': server['uptime'],
              '{#TYPE}': server['type'],
              '{#STATUS}': server['status'],
              '{#AZ_NAME}': server['az_name'],
              '{#AZ_ID}': server['az_id']
          })
    return json.dumps(filtered_servers, indent=2, ensure_ascii=False)
  elif discovery_type == 'clusters':
    url = f'{BASE_URL}/20210725/clusters?page_size=1000'
    
    response = requests.get(url, auth=AUTH, headers=HEADERS, verify=False)
    response.raise_for_status()
    data = response.json()
  
    clusters = data['data']['data']
    # 只保留name, id, type, status和az_id字段
    filtered_clusters = { 'data': [] }
    for cluster in clusters:
        filtered_clusters["data"].append({
            '{#CLUSTER_NAME}': cluster['name'],
            '{#CLUSTER_ID}': cluster['id'],
            '{#CLUSTER_TYPE}': cluster['type'],
            '{#CLUSTER_STATUS}': cluster['status'],
            '{#CLUSTER_AZ_ID}': cluster['az_id']
        })
    return json.dumps(filtered_clusters, indent=2, ensure_ascii=False)

def server(server_id):
  url = f'{BASE_URL}/20200725/servers?page_size=1000'

  if server_id!='all':
    url = f'{url}/{server_id}'
    
  response = requests.get(url, auth=AUTH, headers=HEADERS, verify=False)
  response.raise_for_status()
  data = response.json()

  return json.dumps(data['data']['data'], indent=2, ensure_ascii=False)

def alarms(object_id):
  if object_id!='all':
    url = f'{BASE_URL}/20190725/alarms?page_size=1000&status=open&object_id={object_id}'
  else:
    url = f'{BASE_URL}/20190725/alarms?page_size=1000&status=open'
    
  response = requests.get(url, auth=AUTH, headers=HEADERS, verify=False)
  response.raise_for_status()
  data = response.json()

  return json.dumps(data['data']['data'], indent=2, ensure_ascii=False)

def main():
  scp_parser = argparse.ArgumentParser()
  scp_parser.add_argument("--api_ip", type=str, required=True)
  scp_parser.add_argument("--api_port", type=str, required=True)
  scp_parser.add_argument("--api_ak", type=str, required=True)
  scp_parser.add_argument("--api_sk", type=str, required=True)
  
  group = scp_parser.add_mutually_exclusive_group(required=True)
  group.add_argument("--discovery", type=str, choices=["hosts", "servers", "clusters"])
  group.add_argument("--server", type=str)
  group.add_argument("--alarms", type=str)
  
  arguments = scp_parser.parse_args()
  
  global BASE_URL, ACCESS_KEY, SECRET_KEY, AUTH, HEADERS
  BASE_URL = f'https://{arguments.api_ip}:{arguments.api_port}/janus'
  ACCESS_KEY = arguments.api_ak
  SECRET_KEY = arguments.api_sk
  AUTH = EC2RequestAuth(
        access_key=ACCESS_KEY,
        secret_key=SECRET_KEY,
        region='regionOne',
        service='sdk-api'
    )
  # 添加aCMPAuthToken字段
  HEADERS = {'Cookie': 'aCMPAuthToken=%s' % uuid.uuid4().hex}
  
  if arguments.discovery:
    return discovery(arguments.discovery)
  elif arguments.server:
    return server(arguments.server)
  elif arguments.alarms:
    return alarms(arguments.alarms)

if __name__ == "__main__":
  result = main()
  print(result)
