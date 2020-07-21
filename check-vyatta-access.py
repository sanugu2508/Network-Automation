#!/usr/bin/env python
import re
from netaddr import IPAddress
import ipaddr
from collections import OrderedDict
import sys

'''
input1 = sys.argv[1]
input2 = sys.argv[2]
if not (sys.argv[1] and sys.argv[2]):
    print 'incorrect syntax use example below'
    print 'vyatta.py 10.84.24.20 10.185.16.16'
    exit()
'''
config = [line.split('\r\n') for line in open('vyatta.txt')]
routes = [line.split('\r\n') for line in open('vyatta-routes.txt')]

route_dict = {}
for route in routes:
    route = route[0]
    if '*>' in route:
        line = route.split(',')
        i = line[0].find(' ',10)
        entry = line[0][8:i]
        val1 = line[1].strip(' ')
        route_dict.update({entry: val1})
        
def expandrange(ip1, ip2):
#        print ipaddr.summarize_address_range(ipaddr.IPv4Address(ip1),ipaddr.IPv4Address(ip2))
        #print listx
        listrange = []
        range1 = [fipaddr.with_prefixlen  for fipaddr in ipaddr.summarize_address_range(ipaddr.IPv4Address(ip1),ipaddr.IPv4Address(ip2))]
        for q in range1:
            #print q
            ipraw = str(q) 
            #ipraw = ipraw.replace('/', ' ')
            #print ipraw
            listrange.append(ipraw)
        return listrange
        listrange 
            

def fetch_zone(interface):
    for line in config:
        if 'set security zone-policy zone' in line[0]:
            #print line[0]
            zone = line[0].replace('set security zone-policy zone ','')
            #print zone
            names = re.findall(r'(.*) interface (.*)',zone, re.X|re.M)
            if names:
                iface = names[0][1].replace("'",'')
                iface =iface.lstrip()
                if iface == interface:
                    zone =  names[0][0]
                    return zone
        
# def validator(ip1,ip2):
#     #print ip1,ip2
#     a = ipaddr.IPAddress(ip1)
#     n = ipaddr.IPNetwork(ip2)
#     if n.Contains(a):
#         return True
def validator(ip1,ip2):
    a = ipaddr.IPNetwork(ip1)
    n = ipaddr.IPNetwork(ip2)
    if n.Contains(a):
        return ip2,n.prefixlen
def fetch_rulename(fromtozone):
    for line in config:
        #print line[0]
        if fromtozone in line[0]:
            #print line[0]
            rulename = line[0].replace(fromtozone,'')
            rulename = rulename.replace("'", '')
            return rulename    
    
#ip1 = '10.184.216.144'
# def iphunter(ip1):
#     for key, val in route_dict.iteritems():
#         #print ip1,key
#         if validator(ip1,key):
#             return ip1,key,route_dict[key]
#             #print ip1,key,route_dict[key]
#             break


def iphunter(ip1):
    pflenlist = []
    pfdict={}
    for key, val in route_dict.iteritems():
        #print ip1,key
        if validator(ip1,key):
            ip2,pflen = validator(ip1, key)
            pfdict.update({pflen:ip2})
            pflenlist.append(pflen)
    pflenlist.sort()
    key = pfdict[pflenlist[-1]]
    #print key
    return ip1,key,route_dict[key]
    #print ip1,key,route_dict[key]
def iface_find(ip1):            
    if iphunter(ip1):
        return (iphunter(ip1))
        #return givenip, subnet,interface
#     else:
#         if validator(ip1,'10.0.0.0/8'):
#             givenip = ip1
#             subnet = '10.0.0.0/8'
#             interface = 'dp0bond0'
#             return givenip, subnet,interface
#         elif validator(ip1,'0.0.0.0/0'):
#             givenip = ip1
#             subnet = '0.0.0.0/0'
#             interface = 'dp0bond1'
#             return givenip, subnet,interface

address_book = {}
for line in config:
    if 'set resources group address-group ' in line[0]:
        entry = line[0].replace('set resources group address-group ','')
        if 'address ' in entry:
            pagetoip = entry.split(' address ')
            bookkey = pagetoip[0]
            bookkey = bookkey.replace("'",'')
            bookvalue = pagetoip[1]
            bookvalue = bookvalue.replace("'",'')
            if address_book.has_key(bookkey):
                subnet = address_book[bookkey]
                subnet.append(bookvalue)
                address_book.update({bookkey: subnet})
            else:
                subnet = [bookvalue]
                address_book.update({bookkey: subnet})
        elif 'address-range' in entry:
            pagetoip = entry.split(' address-range ')
            bookkey = pagetoip[0]
            bookkey = bookkey.replace("'",'')
            bookvalue = pagetoip[1]
            bookvalue = bookvalue.replace("'",'')
            rangeval = bookvalue.split(' to ')
            if address_book.has_key(bookkey):
                subnet = address_book[bookkey]
                valuelist = expandrange(rangeval[0],rangeval[1])
                subnet = subnet+valuelist
                address_book.update({bookkey: subnet})      
            else:
                valuelist = expandrange(rangeval[0],rangeval[1])
                address_book.update({bookkey: valuelist})

port_group = {}
for line in config:
    if 'set resources group port-group ' in line[0]:
        entry = line[0].replace('set resources group port-group ','')
        #print entry
        if 'port ' in entry:
            grouptoport = entry.split(' port ')
            #print grouptoport
            portkey = grouptoport[0]
            portkey = portkey.replace("'",'')
            portvalue = grouptoport[1]
            portvalue = portvalue.replace("'",'')
            #print portkey,portvalue
            if port_group.has_key(portkey):
                portlist = port_group[portkey]
                portlist.append(portvalue)
                port_group.update({portkey: portlist})
            else:
                portlist = [portvalue]
                port_group.update({portkey: portlist})
                
def return_ruledict(rulename):
    ruleconstruct = 'set security firewall name%s' % rulename
    rule_dict = {}
    mini_dict = {}
    for line in config:
        if ruleconstruct in line[0]:
            ruleentry = line[0].replace(ruleconstruct,'')
            ruleentrylist = ruleentry.split(' ')
            if 'default-action' in ruleentry:
                dactionlist = ruleentry.split(' ')
                daction = dactionlist[2] 
                #print daction
            #daction = re.findall(r"^default-action\s'(\S+)'",ruleentry, re.X|re.M)
            state = re.findall(r"^\srule\s(\d+)\sstate\s'(\S+)'",ruleentry, re.X|re.M)
            action = re.findall(r"^\srule\s(\d+)\saction\s'(\S+)'",ruleentry, re.X|re.M)
            protocol = re.findall(r"^\srule\s(\d+)\sprotocol\s'(\S+)'",ruleentry, re.X|re.M)
            protocolgroup = re.findall(r"^\srule\s(\d+)\sprotocol-group\s'(\S+)'",ruleentry, re.X|re.M)
            saddress = re.findall(r"^\srule\s(\d+)\ssource\saddress\s'(\S+)'",ruleentry, re.X|re.M)
            daddress = re.findall(r"^\srule\s(\d+)\sdestination\saddress\s'(\S+)'",ruleentry, re.X|re.M)
            dport = re.findall(r"^\srule\s(\d+)\sdestination\sport\s'(\S+)'",ruleentry, re.X|re.M)
            key = ruleentrylist[2]
            #print protocolgroup
            if rule_dict.has_key(key):
                if daction:
                    #print daction
                    mini_dict.update({'default-action': daction})
                    rule_dict.update({key: mini_dict})
                if protocol:
                    mini_dict.update({'protocol': protocol[0][1]})
                    rule_dict.update({key: mini_dict})
                if protocolgroup:
                    mini_dict.update({'protocol': protocolgroup[0][1]})
                    rule_dict.update({key: mini_dict})                
                if saddress:
                    mini_dict.update({'saddress':saddress[0][1]})
                    rule_dict.update({key: mini_dict})
                if daddress:
                    mini_dict.update({'daddress':daddress[0][1]})
                    rule_dict.update({key: mini_dict})
                if dport:
                    mini_dict.update({'dport':dport[0][1]})
                    rule_dict.update({key: mini_dict})
            elif action:
                mini_dict = {}
                mini_dict.update({'action': action[0][1]})
                rule_dict.update({action[0][0]: mini_dict})
    return rule_dict


                
def matchips(ip1,ip2):
    result = ''
    # search routing table find matching interface for given source and return, source ip, source subnet and interface name
    sip, snet, siface = iface_find(ip1)
    dip, dnet, diface = iface_find(ip2)
    #search for zone name that is binded to interface
    szone = fetch_zone(siface)
    dzone = fetch_zone(diface)
    if szone==dzone:
        return 'given source and destination are behind the same interafe. {sip}: {szone}, {dip}: {dzone}'.format(sip=sip,dip=dip,szone=szone,dzone=dzone)
        exit()
    #compose syntax for firewall policy name with zones
    fromtozone = 'set security zone-policy zone %sto %sfirewall' % (szone, dzone)
    #fetch firewall policy name that is binding to zones
    rulename = fetch_rulename(fromtozone)
    #create a dictionary of object-group or address-books, this will limit the search.
    rule_dict = return_ruledict(rulename)
    #entering into the dictionary.
    for key, val in rule_dict.items():
        #looping keys and vals in dictionary and searching if at all "saddress" is present in keys. It is found that some access rules do not have sourceip, strange.
        if 'saddress' in rule_dict[key]:
            #fetching source ip or source subnet
            snet = rule_dict[key]['saddress']
            #checking if address-book dictionary has sourceip or subnet
            if snet in address_book:
                #looping if there are more than once sourceips
                for subnet in address_book[snet]:
                    #This is where it matches for source. First success
                    if validator(ip1,subnet):
                        #checking if rule has destination address present at all. It is found that some rules do not have destination ip. Strange
                        if'daddress' in rule_dict[key]:
                            #checking if destination address is present in address-book.
                            if rule_dict[key]['daddress'] in address_book:
                                #looping through all addresses in the book.
                                for dnet in address_book[rule_dict[key]['daddress']]:
                                    #This is where it searches for destination. Second success. if both source and destination match, continues.
                                    if validator(ip2,dnet):
                                        if 'dport' in rule_dict[key]:
                                            s=  '''
Firewall Policy: {fromtozone}
Firewall Rule Name: {rulename}
Firewall Rule Default-Action:{daction}
Rule: {key}
Action: {action}
Entered Source IP: {ip1}
Entered Destination IP: {ip2}
Matching Souce: {snet}
Matching Destinaton: {dnet}
Matching Port: {dport}
List of Additional Sources: {slist}
List of Additional Destinations: {dlist}
Protocol: {protocol}
All Allowed Ports: {plist}
'''.format(fromtozone=fromtozone, rulename = rulename, daction=rule_dict[key]['default-action'], plist = port_group[rule_dict[key]['dport']], slist = address_book[snet], dlist = address_book[rule_dict[key]['daddress']], key=key, action=rule_dict[key]['action'], ip1=ip1, ip2=ip2,protocol=rule_dict[key]['protocol'], snet=snet,dnet=rule_dict[key]['daddress'],dport=rule_dict[key]['dport']) 
                                            ##print key,ip1,ip2,subnet,dnet
                                            delim = 120*'='
                                            result = result+'\n'+delim+'\n'+s
                                            #return rule_dict[key]
                                        else:
                                            s=  '''
Firewall Policy: {fromtozone}
Firewall Rule Name: {rulename}
Firewall Rule Default-Action:{daction}
Rule: {key}
Action: {action}
Entered Source IP: {ip1}
Entered Destination IP: {ip2}
Protocol: {protocol}
Matching Souce: {snet}
Matching Destinaton: {dnet}
List of Additional Sources: {slist}
List of Additional Destinations: {dlist}
'''.format(fromtozone=fromtozone, rulename = rulename, daction=rule_dict[key]['default-action'], slist = address_book[snet], dlist = address_book[rule_dict[key]['daddress']], key=key, action=rule_dict[key]['action'], ip1=ip1, ip2=ip2,protocol=rule_dict[key]['protocol'], snet=snet,dnet=rule_dict[key]['daddress'])                                            ##print key,ip1,ip2,subnet,dnet
                                            delim = 120*'='
                                            result = result+'\n'+delim+'\n'+s
                                            #return rule_dict[key]

                            else:
                                if validator(ip2,rule_dict[key]['daddress']):
                                    if 'dport' in rule_dict[key]:
                                        if rule_dict[key]['dport'] in port_group:
                                            s=  '''
Firewall Policy: {fromtozone}
Firewall Rule Name: {rulename}
Firewall Rule Default-Action:{daction}
Rule: {key}
Action: {action}
Entered Source IP: {ip1}
Entered Destination IP: {ip2}
Matching Souce: {snet}
Matching Destinaton: {dnet}
Protocol: {protocol}
All Allowed Ports: {plist}

List of Additional Sources: {slist}
'''.format(fromtozone=fromtozone, rulename = rulename, daction=rule_dict[key]['default-action'], slist = address_book[snet], key=key, action=rule_dict[key]['action'], ip1=ip1, ip2=ip2, snet=subnet,dnet=rule_dict[key]['daddress'],plist = port_group[rule_dict[key]['dport']],dport=rule_dict[key]['dport'],protocol=rule_dict[key]['protocol'])
                                            delim = 120*'='
                                            result = result+'\n'+delim+'\n'+s
                                            #return rule_dict[key]
                                        else:
                                            s=  '''
Firewall Policy: {fromtozone}
Firewall Rule Name: {rulename}
Firewall Rule Default-Action:{daction}
Rule: {key}
Action: {action}
Entered Source IP: {ip1}
Entered Destination IP: {ip2}
Matching Souce: {snet}
Matching Destinaton: {dnet}
Protocol: {protocol}
Port: {plist}

List of Additional Sources: {slist}

'''.format(fromtozone=fromtozone, rulename = rulename, daction=rule_dict[key]['default-action'], slist = address_book[snet], key=key, action=rule_dict[key]['action'], ip1=ip1, ip2=ip2, snet=subnet,dnet=rule_dict[key]['daddress'],plist = rule_dict[key]['dport'],protocol=rule_dict[key]['protocol'])
                                            delim = 120*'='
                                            result = result+'\n'+delim+'\n'+s
                                            #return rule_dict[key]


                                    else:

                                            s=  '''
Firewall Policy: {fromtozone}
Firewall Rule Name: {rulename}
Firewall Rule Default-Action:{daction}
Rule: {key}
Action: {action}
Entered Source IP: {ip1}
Entered Destination IP: {ip2}
Matching Souce: {snet}
Matching Destinaton: {dnet}
List of Additional Sources: {slist}
'''.format(fromtozone=fromtozone, rulename = rulename, daction=rule_dict[key]['default-action'], slist = address_book[snet], key=key, action=rule_dict[key]['action'], ip1=ip1, ip2=ip2, snet=subnet,dnet=rule_dict[key]['daddress']) 
                                            delim = 120*'='
                                            result = result+'\n'+delim+'\n'+s
                                            #return rule_dict[key]

                                        
            else:
                
                snet = rule_dict[key]['saddress']
                ##print snet
                if not '/' in snet:
                    snet = snet+'/32'

                if validator(ip1,snet):
                    ##print key, ip1, snet
                    if 'daddress' in rule_dict[key]:
                        if rule_dict[key]['daddress'] in address_book:
                            #, ,address_book[rule_dict[key]['daddress']]
                            for dnet in address_book[rule_dict[key]['daddress']]:
                                ##print dnet
                                if validator(ip2,dnet):
                                    if 'dport' in rule_dict[key]:
                                        if rule_dict[key]['dport'] in port_group:
                                            s=  '''
Firewall Policy: {fromtozone}
Firewall Rule Name: {rulename}
Firewall Rule Default-Action:{daction}
Rule: {key}
Action: {action}
Entered Source IP: {ip1}
Entered Destination IP: {ip2}
Protocol: {protocol}
Matching Souce: {snet}
Matching Destinaton: {dnet}
All Allowed Ports: {plist}

List of Additional Destinations: {dlist}
'''.format(fromtozone=fromtozone, rulename = rulename, daction=rule_dict[key]['default-action'], dlist = address_book[rule_dict[key]['daddress']], key=key, action=rule_dict[key]['action'], ip1=ip1, ip2=ip2, snet=snet,dnet=dnet,plist = port_group[rule_dict[key]['dport']],protocol=rule_dict[key]['protocol']) 
                                            delim = 120*'='
                                            result = result+'\n'+delim+'\n'+s
                                            #return rule_dict[key]
                                        else:
                                            s=  '''
Firewall Policy: {fromtozone}
Firewall Rule Name: {rulename}
Firewall Rule Default-Action:{daction}
Rule: {key}
Action: {action}
Entered Source IP: {ip1}
Entered Destination IP: {ip2}
Matching Souce: {snet}
Matching Destinaton: {dnet}
Protocol: {protocol}
All Allowed Ports: {plist}

List of Additional Destinations: {dlist}

'''.format(fromtozone=fromtozone, rulename = rulename, daction=rule_dict[key]['default-action'], dlist = address_book[rule_dict[key]['daddress']], key=key, action=rule_dict[key]['action'], ip1=ip1, ip2=ip2, snet=snet,dnet=dnet,plist = rule_dict[key]['dport'],protocol=rule_dict[key]['protocol']) 
                                            delim = 120*'='
                                            result = result+'\n'+delim+'\n'+s
                                            #return rule_dict[key]
                                            
                                    else:

                                        s=  '''
Firewall Policy: {fromtozone}
Firewall Rule Name: {rulename}
Firewall Rule Default-Action:{daction}
Rule: {key}
Action: {action}
Entered Source IP: {ip1}
Entered Destination IP: {ip2}
Matching Souce: {snet}
Matching Destinaton: {dnet}

List of Additional Destinations: {dlist}
'''.format(fromtozone=fromtozone, rulename = rulename, daction=rule_dict[key]['default-action'], dlist = address_book[rule_dict[key]['daddress']], key=key, action=rule_dict[key]['action'], ip1=ip1, ip2=ip2, snet=snet,dnet=dnet) 
                                        delim = 120*'='
                                        result = result+'\n'+delim+'\n'+s
                                        #return rule_dict[key]
                                        

                                                                           
                        else:
                            ##print ip1,ip2,subnet,rule_dict[key]['daddress']
                            if validator(ip2,rule_dict[key]['daddress']):
                                if 'dport' in rule_dict[key]:
                                    if rule_dict[key]['dport'] in port_group:
                                        s=  '''
Firewall Policy: {fromtozone}
Firewall Rule Name: {rulename}
Firewall Rule Default-Action:{daction}
Rule: {key}
Action: {action}
Entered Source IP: {ip1}
Entered Destination IP: {ip2}
Matching Souce: {snet}
Matching Destinaton: {dnet}
Protocol: {protocol}
All Allowed Ports: {plist}
'''.format(fromtozone=fromtozone, rulename = rulename, daction=rule_dict[key]['default-action'], plist = port_group[rule_dict[key]['dport']], key=key, action=rule_dict[key]['action'], ip1=ip1, ip2=ip2, snet=snet,dnet=rule_dict[key]['daddress'],protocol=rule_dict[key]['protocol']) 
                                        delim = 120*'='
                                        result = result+'\n'+delim+'\n'+s
                                        #return rule_dict[key]
                                    else:
                                        ##print fromtozone,rulename,key, rule_dict[key] 
                                        s=  '''
Firewall Policy: {fromtozone}
Firewall Rule Name: {rulename}
Firewall Rule Default-Action:{daction}
Rule: {key}
Action: {action}
Entered Source IP: {ip1}
Entered Destination IP: {ip2}
Matching Souce: {snet}
Matching Destinaton: {dnet}
Protocol: {protocol}
All Allowed Ports: {plist}
'''.format(fromtozone=fromtozone, rulename = rulename, daction=rule_dict[key]['default-action'], plist = rule_dict[key]['dport'], key=key, action=rule_dict[key]['action'], ip1=ip1, ip2=ip2, snet=snet,dnet=rule_dict[key]['daddress'],protocol=rule_dict[key]['protocol']) 
                                        delim = 120*'='
                                        result = result+'\n'+delim+'\n'+s
                                        #return rule_dict[key]

                                        
                                else:
                                    s=  '''
Firewall Policy: {fromtozone}
Firewall Rule Name: {rulename}
Firewall Rule Default-Action:{daction}
Rule: {key}
Action: {action}
Entered Source IP: {ip1}
Entered Destination IP: {ip2}
Matching Souce: {snet}
Matching Destinaton: {dnet}
'''.format(fromtozone=fromtozone, rulename = rulename, daction=rule_dict[key]['default-action'],key=key, action=rule_dict[key]['action'], ip1=ip1, ip2=ip2, snet=snet,dnet=rule_dict[key]['daddress']) 
                                    delim = 120*'='
                                    result = result+'\n'+delim+'\n'+s
                                    #return rule_dict[key]
    if result:
        return result
    else:
        s=  '''
Firewall Policy: {fromtozone}
Firewall Rule Name: {rulename}
Entered Source IP: {ip1}
Entered Destination IP: {ip2}
Action: No matching rule found.
'''.format(fromtozone=fromtozone, rulename = rulename, ip1=ip1,ip2=ip2)
        delim = 120*'='
        result = delim+'\n'+s
        return result

