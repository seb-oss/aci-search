from __future__ import print_function
import sys
import math
import re
import json
import csv
import cobra.mit.naming
import inspect
import ipaddress

showClasses = ['fvBD', 'fvRsCtx', 'fvSubnet', 'fvRsBDToOut', 'fvCtx', 'fvRsCtxToBgpCtxAfPol', 'bgpRtTarget', 'bgpRtTargetP', 'fvRtCtx', 'fabricNode', 'infraAttEntityP', 'fvAEPg', 'infraAccBndlGrp', 'infraAccPortGrp']
showValues = ['name', 'nameAlias', 'description', 'ipLearning', 'arpFlood', 'unkMcastAct', 'unkMacUcastAct', 'multiDstPktAct', 'configIssues', \
        'tnFvCtxName', 'ip', 'scope', 'tnL3extOutName', 'rt', 'type', 'targetAf', 'tnBgpCtxAfPolName', 'tDn']

def ipCalc(subnet, mask=None):
    in_net = None
    if mask is None:
        try:
            in_net, in_mask = subnet.split('/', 1)
        except ValueError:
            in_net, in_mask = subnet, None
        if not in_mask:
            in_mask = '32'
    else:
        in_net = subnet
        in_mask = mask

    IP = unicode(in_net)
    MASK = unicode(in_mask)
    net = ipaddress.IPv4Network(IP + '/' + MASK, False)
    bc = net.broadcast_address
    gw = str(bc - 1)
    return str(net.network_address), str(gw), str(in_mask)


def eprint(*args, **kwargs):
    print('! ', *args, file=sys.stderr, **kwargs)

def printNode(node, sys, json=False, short=False, pretty=False):
    if json:
        arrayPrintJSON(node, short, pretty)
    else:
        if not sys:
            print('ID: {:5s} | Name: {:9s} | Role: {:12s} | Status: {:10s} | Model: {:17s} | Serial: {:12s}'.\
                format(str(node.id), str(node.name), str(node.role), str(node.fabricSt), str(node.model), str(node.serial)))
        else:
            print('ID: {:5s} | Name: {:9s} | Role: {:12s} | Status: {:10s} | Model: {:17s} | Serial: {:12s} | Mgmt: {:16s}'.\
                format(str(node.id), str(node.name), str(node.role), str(node.fabricSt), str(node.model), str(node.serial), str(sys.oobMgmtAddr)))

def printInterface(i):
    print('{:7s} | descr: {:24s} | adminSt: {:5s}'.format(str(i.id), str(i.descr), str(i.adminSt)), end='')
    for child in i.children:
        if child.meta.moClassName == 'ethpmPhysIf':
            print (' | operSt: {:5s} | operQual: {:12s} | operSpeed: {:4s}'.format(str(child.operSt), str(child.operStQual), str(child.operSpeed)), end='')
    for child in i.children:
        if child.meta.moClassName == 'l1RsAttEntityPCons':
            print (' | AEP: {}'.format(str(child.tDn).replace('uni/infra/attentp-', '')), end='')
    print()


def printClass(entity, indent = 0, debug_flag=False):
    if entity.meta.moClassName not in showClasses and not debug_flag:
        printChildren(entity, indent, debug_flag)
    else:
        print ('--| {} ({})'.format(entity.meta.moClassName, entity.meta.label))
        indent = indent + 1
        printAttributes(entity, indent, debug_flag)
        printChildren(entity, indent, debug_flag)
        indent = indent - 1

def printAttributes(entity, indent = 0, debug_flag=False):
    attributes = [a for a in dir(entity) if not a.startswith('_')]
    for attr in attributes:
        val = getattr(entity, attr)
        if (isinstance(val, (str, unicode, int)) or attr in ['status', 'state', 'dn']) and str(val) != '':
            print (instr * indent + '{:24} : {}'.format(attr, val))

def printChildren(entity, indent = 0, debug_flag=False):
    for child in entity.children:
        if child.meta.moClassName not in showClasses and not debug_flag:
            printChildren(child, indent, debug_flag)
        else:
            print (instr * indent + '--| {} ({})'.format(child.meta.moClassName, child.meta.label))
            indent = indent + 1
            printAttributes(child, indent, debug_flag)
            printChildren(child, indent, debug_flag)
            indent = indent - 1

# https://keepalives.wordpress.com/2013/06/05/sorting-cisco-interface-names-in-python/
def switchportCmp(a, b):
    match_a = re.match('\D+', a)
    match_b = re.match('\D+', b)
    if match_a and match_b:
        if match_a.group(0).lower() < match_b.group(0).lower(): return -1
        if match_a.group(0).lower() > match_b.group(0).lower(): return 1
        else:
            if len(match_a.group(0)) < len(a) or len(match_b.group(0)) < len(b):
                return switchportCmp(a[match_a.end(0):], b[match_b.end(0):])
    match_a = re.match('\d+', a)
    match_b = re.match('\d+', b)
    if match_a and match_b:
        if int(match_a.group(0)) < int(match_b.group(0)): return -1
        if int(match_a.group(0)) > int(match_b.group(0)): return 1
        else:
            if len(match_a.group(0)) < len(a) or len(match_b.group(0)) < len(b):
                return switchportCmp(a[match_a.end(0):], b[match_b.end(0):])
    return 0

# Function for sorting by instance type
def typeCmp(a, b):
    def getWeight(i):
        if isinstance(i, str):
            return 3
        elif isinstance(i, dict):
            return 2
        elif isinstance(i, list):
            return 1
        else:
            return 0
    aWeight = getWeight(a[0])
    bWeight = getWeight(b[0])
    if aWeight < bWeight:
        return -1
    if aWeight > bWeight:
        return 1
    else:
        return 0

def printJSON(obj, allprops=True, pretty=False):
    try:
       print (toJSONStr(obj, includeAllProps=allprops, prettyPrint=pretty))
    except AttributeError as e:
        print ('Error: %s' % e)
        sys.exit()

def getJSON(obj, allprops=True, pretty=False):
    try:
        return (toJSONStr(obj, includeAllProps=allprops, prettyPrint=pretty))
    except AttributeError as e:
        print ('Error: %s' % e)
        sys.exit()

def getDict(obj, allprops=True, pretty=False):
    try:
        js = (toJSONStr(obj, includeAllProps=allprops, prettyPrint=pretty))
        dictionary = json.loads(js)
        return dictionary
    except AttributeError as e:
        sys.exit('Error: {}'.format(e))

def printDict(item, indent = 0, debug_flag=False):
    for k, v in sorted(item.iteritems(), cmp=typeCmp):
        if isinstance(v, dict):
            indent = indent + 1
            if debug_flag:
                print ('\t' + '-' * indent + '-| {}'.format(k))
            else:
                print ('-' * indent + '-| {}'.format(k))
            printDict(v, indent, debug_flag)
            indent = indent - 1
        elif isinstance(v, list):
            indent = indent + 1
            for i in v:
                if debug_flag:
                    print ('\t' + '-' * indent + '-| {}'.format(k))
                else:
                    print ('-' * indent + '-| {}'.format(k))
                printDict(i, indent, debug_flag)
            indent = indent - 1
        else:
            if debug_flag:
                if not v or v == '':
                    continue
                print ('\t' + '  '*indent + '{:30s}: {:15s}'.format(k, v))
            else:
                print ('  '*indent + '{:30s}: {:15s}'.format(k, v))

def parseHports(dn):
    # Input: uni/infra/accportprof-FLACC1101/hports-eth01-01-typ-range
    node = re.search('accportprof-(\D+\d+)', dn)
    name = node.group(1)
    node = re.search('(eth\d+-\d+)', dn)
    port = node.group(1)
    port = port.replace('-', '/')
    return (name, port)

def WriteCSV(fileName, arrayIn):
    # Input Array of Dictionaries
    # Use first dictionary to build CSV column headers
    with open(fileName, 'w') as csvfile:
        fieldnames = arrayIn[0].keys()
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for in_dict in arrayIn:
            writer.writerow(in_dict)

def switchportCsv(item, parent=None):
    usefullFields = ["operMode", "operSpeed", "lastErrors", "operDuplex", "primaryVlan", "nativeVlan", "autoNeg", "name", "adminSt", "operSt", "descr", "gw", "fabricSt", "serial", "mgmt_addr", "role", "model", "interfaces", "switchName", "switchId"]
    keys = item.keys()
    node = {}
    for k in keys:
        data = item[k]['attributes']
        del item[k]
        data['switchName'] = data['name']
        data['switchId'] = data['id']
        for key in data.keys():
            if key not in usefullFields:
                del data[key]
        item = data.copy()

    intParameters = []
    interfaces = item['interfaces']
    del item['interfaces']
    for interface in interfaces:
        tmpdict = {}
        tmpdict['interface'] = interface
        for k in interfaces[interface].keys():
            d = interfaces[interface][k]
            for k2, v2, in d.iteritems():
                if tmpdict.get(k2):
                    del tmpdict[k2]
                else:
                    if k2 in usefullFields:
                        tmpdict[k2] = v2
        intParameters.append(tmpdict.copy())

    WriteCSV('test.csv', intParameters)

def __toJSONDict(mo, includeAllProps=False, prettyPrint=False, excludeChildren=False):
    meta = mo.meta
    className = meta.moClassName
    label = meta.label

    moDict = {}
    attrDict = {}
    attrDict['meta.label'] = label
    for propMeta in meta.props:
        name = propMeta.name
        moPropName = propMeta.moPropName
        value = None
        if propMeta.isDn:
            if includeAllProps:
                value = str(mo.dn)
        elif propMeta.isRn:
            if includeAllProps:
                value = str(mo.rn)
        elif propMeta.isNaming or includeAllProps or mo.isPropDirty(name):
            value = getattr(mo, name)

        if value is not None:
            attrDict[moPropName] = {}
            attrDict[moPropName] = str(value)

    if len(attrDict) > 0:
        moDict['attributes'] = attrDict

    if not excludeChildren:
        childrenArray = []
        for childMo in mo.children:
            childMoDict = __toJSONDict(childMo, includeAllProps, prettyPrint, excludeChildren)
            childrenArray.append(childMoDict)
        if len(childrenArray) > 0:
            moDict['children'] = childrenArray

    return {className: moDict}


def toJSONStr(mo, includeAllProps=False, prettyPrint=False, excludeChildren=False):
    jsonDict = __toJSONDict(mo, includeAllProps, prettyPrint, excludeChildren)
    indent = 2 if prettyPrint else None
    jsonStr = json.dumps(jsonDict, indent=indent)

    return jsonStr
