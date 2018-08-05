# -*- coding: utf-8 -*-
"""
Created on Jan 22 2018

@author: manbu
"""
import re
import socket
import time
import sys
import json
from collections import OrderedDict
# 导入本地数据
from tools import *
from reMatch import re_list, re_list_dict

reload(sys)
sys.setdefaultencoding("utf-8")

FAIL_MATCH_IP = []
INETNUM_LIST = set()


def get_ipwhois(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(6)
    try:
        s.connect(('whois.apnic.net', 43))
        s.send((ip + '\r\n').encode())
    except:
        pass
    else:
        try:
            text = ''
            while True:
                recv_info = s.recv(4096)
                if not recv_info:
                    break
                text += recv_info
            return text
        except socket.error:
            pass


def match_text(text, model):
    if model == 1:
        if text.find('This network range is not allocated to APNIC') != -1:
            return False
    re_tuple = ()
    num = 0
    i = 0
    while i < len(re_list):  # 获取re_list中的正则表达式来循环匹配，一旦匹配到，就跳出循环
        patt = re.compile(re_list[i], re.S)
        result = patt.search(text)
        if result:
            re_tuple, num = result.groups(), i
            break
        i += 1
    return re_tuple, num


def parse_text(text, num):
    re_lis = re_dict[num]
    key_list = []
    for para, dic in zip(text, re_lis):  # 段落
        lines_list = para.split('\n')
        lines_list = [un_null for un_null in lines_list if un_null]  # 删除空行
        for index, item in enumerate(lines_list):  # 每行建立索引，可以返回上一行取key值
            item_split = item.split(':', 1)  # 将每行拆封成 键值对
            item_split = map(strip, item_split)
            if len(item_split) == 2:
                if item_split[0] == 'inetnum':
                    if item_split[1] in INETNUM_LIST:
                        return
                    INETNUM_LIST.add(item_split[1])
                dic[item_split[0]] = is_duplicate(item_split, dic)
            else:  # 该行没有key
                times = 0
                while times < 4:  # 最多回溯4行
                    lines_split = lines_list[index-1].split(':', 1)
                    lines_split = map(strip, lines_split)
                    if len(lines_split) == 2:
                        dic[lines_split[0]] = is_duplicate(lines_split, dic)
                        break
                    else:
                        index -= 1  # 回溯上一行
                        times += 1
        # 取每个段落的前12个字符，当做字典的key值
        key_list.append(para[:12].strip().rstrip(':'))
    return dict(zip(key_list, re_lis))


def make_dict(text_dict):
    dic = dict()
    dic['contacts'] = []  # 将 person，role 归纳到 contacts中
    for key, values in text_dict.items():
        if key == 'person':
            dic['contacts'].append(values)
        elif key == 'role':
            dic['contacts'].append(values)
            values['person'] = values.pop('role')  # 将 key值 role 替换为person
        else:
            dic[key] = values
    return dic


def json_dumps(dic):
    new_dict, irt, organisation, temp, router, index_dict = OrderedDict(
    ), OrderedDict(), OrderedDict(), OrderedDict(), OrderedDict(), OrderedDict()    # 有序字典
    # new_dict, irt, organisation, temp, router, index_dict = {}, {},{},{},{},{}    # 无序字典
    contacts = list()
    ip_range = dict()
    new_dict['type'] = 'ip-whois'
    # new_dict['id'] = create_id()               # 生成id
    new_dict['id'] = id                                                             # 引用id
    new_dict['created_by'] = "050d"
    new_dict['first_seen'] = transform_date(
        dic['inetnum'].get('last-modified'))
    new_dict['last_seen'] = transform_date(
        dic['inetnum'].get('last-modified'))
    new_dict['modified'] = int(time.time())
    new_dict['created'] = int(time.time())
    new_dict['net_range'] = dic['inetnum'].get('inetnum')
    new_dict['net_name'] = dic['inetnum'].get('netname')
    new_dict['net_type'] = dic['inetnum'].get('status')
    new_dict['last_updated'] = transform_date(
        dic['inetnum'].get('last-modified'))
    ip_range['start_ip'] = new_dict['net_range'].split('-')[0].strip()
    ip_range['end_ip'] = new_dict['net_range'].split('-')[-1].strip()
    new_dict['ip_range'] = ip_range

    if dic.get('irt'):
        irt['name'] = dic['irt'].get('irt')
        irt['country'] = country
        irt['street_address'] = query_address(dic['irt'])
        irt['admin_c'] = dic['irt'].get('admin-c')
        irt['tech_c'] = dic['irt'].get('tech-c')
        irt['abuse_c'] = dic['irt'].get('abuse-mailbox')
        irt['last_updated'] = transform_date(dic['irt'].get('last-modified'))
        irt['phone_number'] = dic['irt'].get('phone')
        irt['email_address'] = dic['irt'].get('e-mail')
        irt['fax_number'] = dic['irt'].get('fax-no')
        irt['managed'] = dic['irt'].get('mnt-by')
        irt['auth'] = dic['irt'].get('auth')
        if dic['irt'].get('remarks'):
            irt['remarks'] = create_remarks(dic['irt'])
        new_dict['irt'] = irt

    if dic.get('organisation'):
        organisation['name'] = dic['organisation'].get('organisation')
        organisation['country'] = dic['organisation'].get('country')
        organisation['country'] = country
        organisation['street_address'] = query_address(dic['organisation'])
        organisation['last_updated'] = transform_date(
            dic['organisation'].get('last-modified'))
        organisation['admin_c'] = dic['organisation'].get('admin-c')
        organisation['tech_c'] = dic['organisation'].get('tech-c')
        organisation['abuse_c'] = dic['organisation'].get('abuse-mailbox')
        organisation['phone_number'] = dic['organisation'].get('phone')
        organisation['email_address'] = dic['organisation'].get('e-mail')
        organisation['fax_number'] = dic['organisation'].get('fax-no')
        if dic['organisation'].get('remarks'):
            organisation['remarks'] = create_remarks(dic['organisation'])
        new_dict['organization'] = organisation

    for person in dic['contacts']:
        temp['name'] = person.get('person')
        temp['country'] = country
        temp['street_address'] = query_address(person)
        temp['last_updated'] = transform_date(person.get('last-modified'))
        temp['phone_number'] = person.get('phone')
        temp['email_address'] = person.get('e-mail')
        temp['fax_number'] = person.get('fax-no')
        temp['managed'] = person.get('mnt-by')
        if person.get('remarks'):
            temp['remarks'] = create_remarks(person)
        contacts.append(temp)
    new_dict['contacts'] = [eval(__) for __ in list(set([repr(_) for _ in contacts]))]  # 去重， 解决badcase

    if dic.get('route'):
        router['cidr'] = dic['route'].get('route')
        router['origin'] = dic['route'].get('origin')
        router['country'] = dic['route'].get('country')
        router['last_updated'] = transform_date(
            dic['route'].get('last-modified'))
        router['managed'] = dic['route'].get('mnt-by')
        if dic['route'].get('remarks'):
            router['remarks'] = create_remarks(dic['route'])
        new_dict['router'] = router

    mnt_by = dic['inetnum'].get('mnt-by', '0')
    mnt_lower = dic['inetnum'].get('mnt-lower', '0')
    mnt_routes = dic['inetnum'].get('mnt-routes', '0')
    mnt_irt = dic['inetnum'].get('mnt-irt', '0')
    remarks_list = ['mnt_by: ' + mnt_by,
                    'mnt_lower: ' + mnt_lower,
                    'mnt_routes: ' + mnt_routes,
                    'mnt_irt: ' + mnt_irt]
    remarks_list = [__ for __ in remarks_list if __.split(':')[-1].strip() != '0']  # 去空
    new_dict['remarks'] = remarks_list

    if dic['inetnum'].get('remarks'):
        remarks = create_remarks(dic['inetnum'])
        new_dict['remarks'].extend(remarks)
    new_dict = is_null(new_dict)

    # index_dict['id'] = new_dict['id']
    # index_dict['ip'] = '-'.join([str(ip2long(ip_range['start_ip'])), str(ip2long(ip_range['end_ip']))])

    # json_body = [json.dumps(new_dict, ensure_ascii=False), json.dumps(index_dict)]
    json_body = [json.dumps(new_dict, ensure_ascii=False)]
    return json_body


def main_all(ip):
    global FAIL_MATCH_IP
    global fp
    model = 0  # 全部返回模式
    max_times = 5    # 解决socket.error
    for i in range(max_times):
        text = get_ipwhois(ip)
        if text:
            break
    if not text:
        print '{}:Error, can not get data from source'.format(ip)
        return
    re_tuple, num = match_text(text, model)
    if not re_tuple:
        print "Error, can not match the text of {}".format(ip)
        FAIL_MATCH_IP.append(ip)
        return
    text_dict = parse_text(re_tuple, num)
    if not text_dict:
        print '{}:repeat net_ranges'.format(ip)
        return
    textDict = make_dict(text_dict)
    return json_dumps(textDict)


def main_single(ip):
    model = 1  # 单条返回模式
    patt = re.compile(
        '\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b')
    match = patt.match(ip)
    if not match:
        return 'Error: Illegal ip'
    text = get_ipwhois(ip)
    if not text:
        return 'Error, try again later'
    if not match_text(text, model):
        return 'This network range({}) is not allocated to APNIC'.format(ip)
    re_tuple, num = match_text(text, model)
    if not re_tuple:
        return "Cant not  match the text of {}".format(ip)
    text_dict = parse_text(re_tuple, num)
    if not text_dict:
        return "The ip-whois message is already in data"
    textDict = make_dict(text_dict)
    return json_dumps(textDict)


if __name__ == '__main__':

    if len(sys.argv) >= 2:
        for index, ip in enumerate(sys.argv):
            re_dict = re_list_dict()
            if index == 0:
                continue
            print main_single(ip)
            print '\n'
    else:
        print 'Json data and index information of ipv4 is producing...... '
        start_time = time.time()
        with open('ipv4.txt', 'r') as ipv4:
            ip_test_list = ipv4.readlines()
            with open('json_20180419.txt', 'a+') as g:
                # with open('index.txt', 'a+') as k:
                with open('origin_index.txt', 'r') as k:
                    index_list = k.readlines()
                    for lines, index_line in zip(ip_test_list, index_list):
                        re_dict = re_list_dict()
                        ip_unit = lines.split('|')
                        id = json.loads(index_line)['id']
                        country = ip_unit[1]
                        ip = ip_unit[3]
                        json_body = main_all(ip)
                        if json_body:
                            g.write(json_body[0])
                            g.write('\n')
                            # k.write(json_body[1])
                            # k.write("\n")
        print 'FAIL_MATCH_IP:{}'.format(FAIL_MATCH_IP)
        print 'Cost time：{}'.format(time.time()-start_time)
        print 'All work is done'
