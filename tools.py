# -*- coding: utf-8 -*-
"""
Created on Jan 22 2018

@author: manbu
"""
import re
import socket
import struct
import time
import redis
import datetime
import hashlib
from collections import OrderedDict

__all__ = ['strip', 'is_duplicate', 'is_null', 'query_address', 'create_remarks', 'transform_date', 'create_id', 'ip2long']

strip = lambda x: x.strip()
def is_duplicate(lis, dic):
    if lis[0] in dic:  # key 重复，values值累加
        dic[lis[0]] += '|*&' + lis[1]
    else:
        dic[lis[0]] = lis[1]
    return dic[lis[0]]


def is_null(item):
    new = OrderedDict()
    for key, values in item.items():
        if isinstance(values, dict):
            new[key] = is_null(values)
        elif isinstance(values, list):
            new[key] = [is_null(__) if isinstance(__, dict) else __ for __ in values ]
        else:
            if  not values:
                continue
            else:
                new[key] = values
    return  new

def create_remarks(item):
    return ['remarks: '+__.decode('utf-8', errors='ignore') for __ in item.get('remarks').split('|*&')]

def query_address(item):
    return '，'.join(reversed(list(set(item.get('address').split('|*&'))))).decode('utf-8', errors='ignore')

def create_id():
    # ipmd5 = hashlib.md5(ip).hexdigest()
    vn = '0'
    cm = '0'
    vn = bin(int(vn, 16))[2:].zfill(4)
    cm = bin(int(cm, 16))[2:].zfill(4)
    client = redis.StrictRedis(host='10.24.45.99', port=6379, db=0)
    a = client.evalsha(
        "6d6815c1216ebce83bc03de59fa2df4d4de1d199", 2, "test", "hydra1")
    workerid = bin(a[0])[2:].zfill(8)
    incnum = bin(a[1])[2:].zfill(12)
    time = bin(a[2])[2:].zfill(32)
    seqnumber_time = workerid + incnum + time

    source = '050d'
    source = bin(int(source, 16))[2:].zfill(16)
    type2 = bin(int('11', 16))[2:].zfill(8)
    return hex(int(vn+type2+seqnumber_time+source+cm, 2))[2:-1].zfill(21)


def transform_date(date):
    patt = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')
    match = patt.search(date)
    if match:
        date = match.group()
        dt = time.strptime(date, '%Y-%m-%dT%H:%M:%SZ')
        time_stamp = int(time.mktime(dt))
        return time_stamp


def ip2long(ip):
    packed_ip = socket.inet_aton(ip)
    return struct.unpack("!L", packed_ip)[0]



