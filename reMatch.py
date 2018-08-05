# -*- coding: utf-8 -*-


re_list = [
    r'.*?(inetnum.*?source:\s+?APNIC).*?([^-]irt.*?source:\s+?APNIC).*?(organisation.*?source:\s+?APNIC).*?(person.*?source:\s+?APNIC).*?(person.*?source:\s+?APNIC).*?(route.*?source:\s+?APNIC)',
    r'.*?(inetnum.*?source:\s+?APNIC).*?([^-]irt.*?source:\s+?APNIC).*?((?:person|role).*?source:\s+?APNIC).*?((?:person|role).*?source:\s+?APNIC).*?((?:person|route).*?source:\s+?APNIC)',
    r'.*?(inetnum.*?source:\s+?APNI).*?([^-](?:irt|person|role).*?source:\s+?APNIC).*?((?:organisation|person|role).*?source:\s+?APNIC).*?((?:person|role|route).*?source:\s+?(?i)APNIC)',
    r'.*?(inetnum.*?source:\s+?APNIC).*?([^-](?:irt|person|role).*?source:\s+?APNIC).*?((?:person|role|route).*?source:\s+?(?i)APNIC)',
    r'.*?(inetnum.*?source:\s+?APNIC).*?([^-](?:irt|person|role).*?source:\s+?(?i)APNIC)'
]



def re_list_dict():
    # 根据正则匹配，构建匹配字典
    re_dict = {0: [{}, {}, {}, {}, {}, {}],
               1: [{}, {}, {}, {}, {}],
               2: [{}, {}, {}, {}],
               3: [{}, {}, {}],
               4: [{}, {}]
               }
    return re_dict


__all__ = ['re_list', 're_list_dict']
