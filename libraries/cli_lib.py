import sys
import re
import socket
import time
import json
from libraries.generic import printClass

def listVrfs(session):
    vrfs = session.md.lookupByClass('fvCtx', parentDn='uni/tn-common')
    return vrfs

def listTenants(session):
    tenants = session.md.lookupByClass('fvTenant')
    return tenants

def getTenant(session, tenantName):
    tenantDn = 'uni/tn-{}'.format(tenantName)
    tenant = session.md.lookupByDn(tenantDn)
    return tenant

def getSchedulerProfiles(session):
    schedP = session.md.lookupByClass('trigSchedP', subtree='children', subtreeClassFilter='trigRecurrWindowP')
    return schedP

def listAppProfiles(session, parent=None):
    if parent:
        appProfiles = session.md.lookupByClass('fvAp', parentDn = parent)
    else:
        appProfiles = session.md.lookupByClass('fvAp')

    return appProfiles

def getDhcpClient(session, serialNumber):
    return session.md.lookupByDn('client-[{}]'.format(serialNumber))

def getFwGrp(session, grpName):
    return session.md.lookupByDn('uni/fabric/fwgrp-{}'.format(grpName), subtreeInclude='relations')

def getCurrentVersion(session):
    fwGrp = getFwGrp(session, 'Fabric')
    return fwGrp.version

def listAEPs(session):
    return session.md.lookupByClass('infraAttEntityP', subtree='full', subtreeClassFilter='infraGeneric,infraRtAttEntP,infraRsFuncToEpg')

def findAEP(session, AEPname=''):
    AEPname = '(?i)' + AEPname
    return session.md.lookupByClass('infraAttEntityP', propFilter='wcard(infraAttEntityP.name, "{}")'.format(AEPname), subtree='full', subtreeClassFilter='infraGeneric,infraRtAttEntP,infraRsFuncToEpg')

def getAEPs(session, AEPname):
    return session.md.lookupByClass('infraAttEntityP', propFilter='eq(infraAttEntityP.name, "{}")'.format(AEPname), subtree='full', subtreeClassFilter='infraGeneric,infraRtAttEntP,infraRsFuncToEpg')

def getAEP_by_dn(session, aepDn):
    return session.md.lookupByDn(aepDn, subtree='full', subtreeClassFilter='infraGeneric,infraRtAttEntP,infraRsFuncToEpg')

def listVpcPPG(session):
    return session.md.lookupByClass('infraAccBndlGrp', subtree='children', subtreeClassFilter='infraRsAttEntP,infraRtAccBaseGrp')

def listAccessPPG(session):
    return session.md.lookupByClass('infraAccPortGrp', subtree='children', subtreeClassFilter='infraRsAttEntP,infraRtAccBaseGrp')

def getVpcPPG(session, ppgName):
    return session.md.lookupByClass('infraAccBndlGrp', subtree='children', subtreeClassFilter='infraRsAttEntP,infraRtAccBaseGrp', propFilter='eq(infraAccBndlGrp.name, "{}")'.format(ppgName))

def getAccessPPG(session, ppgName):
    return session.md.lookupByClass('infraAccPortGrp', subtree='children', subtreeClassFilter='infraRsAttEntP,infraRtAccBaseGrp', propFilter='eq(infraAccPortGrp.name, "{}")'.format(ppgName))

def listPPG(session):
    PPGs = []
    access = session.md.lookupByClass('infraAccPortGrp', subtree='children', subtreeClassFilter='infraRsAttEntP,infraRtAccBaseGrp')
    if len(access) > 0:
        for item in access:
            PPGs.append(item)
    vpc = session.md.lookupByClass('infraAccBndlGrp', subtree='children', subtreeClassFilter='infraRsAttEntP,infraRtAccBaseGrp')
    if len(vpc) > 0:
        for item in vpc:
            PPGs.append(item)
    return PPGs

def getLLDP(session):
    lldpAdjEps = session.md.lookupByClass('lldpAdjEp')
    return lldpAdjEps

def getCDP(session, node=None):
    pass

def getPPG(session, ppgName):
    PPGs = []
    ppgName = '(?i)' + ppgName
    access = session.md.lookupByClass('infraAccPortGrp', subtree='children', subtreeClassFilter='infraRsAttEntP,infraRtAccBaseGrp', propFilter='wcard(infraAccPortGrp.name, "{}")'.format(ppgName))
    if len(access) > 0:
        for item in access:
            PPGs.append(item)
    vpc = session.md.lookupByClass('infraAccBndlGrp', subtree='children', subtreeClassFilter='infraRsAttEntP,infraRtAccBaseGrp', propFilter='wcard(infraAccBndlGrp.name, "{}")'.format(ppgName))
    if len(vpc) > 0:
        for item in vpc:
            PPGs.append(item)
    return PPGs

def getPPG_byDn(session, ppg_dn):
    ppg = session.md.lookupByDn(ppg_dn, subtree='children', subtreeClassFilter='infraRsAttEntP,infraRtAccBaseGrp')
    return ppg

def listEpgs(session, parent=None):
    if parent:
        return session.md.lookupByClass('fvAEPg', parentDn = parent)
    else:
        return session.md.lookupByClass('fvAEPg')

def getEpgs(session, epgName):
    return session.md.lookupByClass('fvAEPg', propFilter='eq(fvAEPg.name, "{}")'.format(epgName))

def getHPortS(session, nodeName):
    hports = session.md.lookupByClass('infraAccPortP', subtree='full', subtreeClassFilter='infraHPortS', subtreeInclude='required', propFilter='eq(infraAccPortP.name, "{}")'.format(nodeName))
    return hports

def getLeafPortProfile(session, nodeName, portName):
    port = portName.lstrip('eth')
    module, port = port.split('/')

    portName = 'eth{:02d}-{:02d}'.format(int(module),int(port))

    lp = session.md.lookupByClass('infraAccPortP', propFilter='eq(infraAccPortP.name, "{}")'.format(nodeName), subtree='full', subtreeClassFilter='infraHPortS,infraRtAccPortP,infraRsAccBaseGrp', subtreePropFilter='eq(infraHPortS.name, "{}")'.format(portName))
    return lp


def findEPG(session, subnet):
    # Replace '/' with '-' when looking for subnet in EPG name
    if if_ip(subnet):
        subnet = re.sub('/', '-', subnet)

    EPGs = session.md.lookupByClass('fvAEPg', propFilter='or(wcard(fvAEPg.name, "{0}")wcard(fvAEPg.nameAlias, "{0}"))'.format(subnet))
    if len(EPGs) == 0:
        return None
    return EPGs

def AepExists(session, AepName):
    AEP = session.md.lookupByClass('infraAttEntityP', propFilter='eq(infraAttEntityP.name, "{}")'.format(AepName))
    if len(AEP) > 0:
        return True
    return False

def guessVlan(nameAlias):
    regex = re.compile('(?:^VL|^VL-|^vl|^vl-|^VLAN|^VLAN-|^vlan|^vlan-)')
    if re.match(regex, nameAlias):
        match = re.search('(^VL|^VL-|^vl|^vl-|^VLAN|^VLAN-|^vlan|^vlan-)', nameAlias)
        vlan = nameAlias.split(match.group(0))[1].strip('-')
        return 'vlan-' + vlan
    else:
        sys.exit('Failed to parse VLAN from EPG nameAlias: {}'.format(EPG.nameAlias))

def getLeafVpcPairs(session):
    groups = session.md.lookupByClass('fabricExplicitGEp')
    pairs = []
    for grp in groups:
        pair = []
        vpcPairs = session.md.lookupByClass('fabricNodePEp', parentDn=grp.dn)
        for p in vpcPairs:
            pair.append(int(p.id))
        pair.sort()
        pairs.append(pair)

    return pairs

def getNodes(session, nodeFilter):
    if nodeFilter == '*':
        try:
            nodes = session.md.lookupByClass('fabricNode')
        except Exception as e:
            sys.exit('Error: {}'.format(e))
    else:
        if ',' in nodeFilter:
            nodeIds = nodeFilter.split(',')
            filters = []
            for Id in nodeIds:
                prefix, nodeId = re.split('(\d+)', Id)[:2]
                filters.append(('eq(fabricNode.id, "{}")'.format(nodeId)))
            filter_string =  ''.join(filters)
            nodeFilter = 'or({})'.format(filter_string)

        else:
            prefix, nodeId = re.split('(\d+)', nodeFilter)[:2]
            nodeFilter='eq(fabricNode.id, "{}")'.format(nodeId)

        try:
            nodes = session.md.lookupByClass('fabricNode', propFilter=nodeFilter)
        except Exception as e:
            sys.exit('Error: {}'.format(e))

    return nodes

def getNodesByPod(session, pod, filt=None):
    nodes = session.md.lookupByClass('fabricNode', parentDn=pod.dn, propFilter=filt)
    return nodes

def getNode_byDn(session, dn):
    node = session.md.lookupByDn(dn)
    return node

def getNodePort(dn):
    try:
        node = re.search('protpaths-(\d+)-(\d+)', dn)
        name = node.group(1) + '-' + node.group(2)
        node = re.search('pathep-\[(.*?)\]', dn)
        vpc = node.group(1)
        port = None
    except AttributeError:
        node = re.search('paths-(\d+)', dn)
        name = node.group(1)
        node = re.search('\[(eth\d+/\d+)\]', dn)
        port = node.group(1)
        port = port.replace('/', '-')
        vpc = None

    return (name, port, vpc)

def getInterfaces(session, nodeDn, portId=None):
    if not str(nodeDn).endswith('/sys'):
        dn = str(nodeDn) + '/sys'
    else:
        dn = str(nodeDn)

    # Build interface filter properties
    portFilter = None
    # Filter specific interfaces if argument -port was given
    if portId:
        if '-' in portId:
            if not portId.startswith('eth'):
                portId = 'eth' + portId
            portLow, portHigh = portId.split('-')
            prefix, suffix = portLow.split('/')
            portHigh = prefix + '/' + portHigh
            # Create filter for port range
            portFilter = 'and(ge(l1PhysIf.id, "{}")le(l1PhysIf.id, "{}"))'.format(portLow, portHigh)

        elif ',' in portId:
            ports = portId.split(',')
            filters = []
            for num in range(len(ports)):
                portId = ports[num]
                if not portId.startswith('eth'):
                    portId = 'eth' + portId

                filters.append(('eq(l1PhysIf.id, "{}")'.format(portId)))
            filter_string =  ''.join(filters)
            portFilter = 'or({})'.format(filter_string)

        else:
            if not portId.startswith('eth'):
                portId = 'eth' + portId
            portLow = portHigh = portId
            portFilter = 'and(ge(l1PhysIf.id, "{}")le(l1PhysIf.id, "{}"))'.format(portLow, portHigh)

        '''
        # if you want to use built in regex support with wildcard search:
        portId = 'eth' + portId
        portFilter = 'wcard(l1PhysIf.id, "{}")'.format(portId)
        '''

    try:
        interfaces = session.md.lookupByClass('l1PhysIf', parentDn=dn, propFilter = portFilter, subtree='full',\
                                                subtreeClassFilter='ethpmPhysIf,l1RsAttEntityPCons,rmonIfIn,rmonIfOut,rmonEtherStats,rmonEgrCounters,rmonIngrCounters')
    except Exception as e:
        try:
            interfaces = session.md.lookupByClass('l1PhysIf', parentDn=dn, propFilter = portFilter, subtree='full',\
                                                    subtreeClassFilter='ethpmPhysIf,l1RsAttEntityPCons,rmonIfIn,rmonIfOut')

        except Exception as e:
            sys.exit('! Error: {}'.format(e))

    return interfaces

def searchDescription(session, descr):
    tmp_dict = {}
    ints = []
    descr = '(?i)' + descr
    interfaces = session.md.lookupByClass('l1PhysIf', propFilter = 'wcard(l1PhysIf.descr, "{}")'.format(descr))
    for i in interfaces:
        tmp_dict[i.dn] = i

    for interface in sorted(tmp_dict.values(), key=lambda k: k.id):
        ints.append(interface)

    return ints

def getSys(session, nodeDn):
    try:
        return session.md.lookupByDn(str(nodeDn)+'/sys')
    except Exception as e:
        print ('Error: {}'.format(e))
        return None

def get_node_name_port(dn):
    node = re.search('node-(\d+)', dn)
    name = node.group(1)
    node = re.search('\[(eth\d+/\d+)\]', dn)
    port = node.group(1)
    port = port.replace('/', '-')
    return '{}_{}'.format(name,port)

def remove_mask(net):
    regex = re.compile("\/[0-9]{1,2}$")
    r = regex.search(net)
    if r:
        new_net, mask = net.split('/')
        return new_net, mask
    else:
        return net, None

def if_ip(ip):
    ip, mask = remove_mask(ip)

    # Check if mask is valid
    if mask:
        if int(mask) < 0 or int(mask) > 32:
            return False

    # Check if provided ip has 4 octets
    if len(ip.split('.')) != 4:
        return False

    else:
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            return False

def if_mac(mac):
    mac = mac.translate(None, ',.-:').upper()
    regex = re.compile("^([0-9A-F]{12})$")
    if len(mac) == 12 and re.match(regex, mac):
        return True
    else:
        return False

def is_int(i):
    try:
        i = int(i)
        return i
    except:
        return False


def vrf_check(session, vrfid):
    vrfId = str(format(int(vrfid), '03d'))
    vrfId = 'vrf' + vrfId
    vrfs = session.md.lookupByClass("fvCtx", parentDn='uni/tn-common')
    for vrf in vrfs:
        if vrf.name == vrfId:
            return vrf

    return False

def vrfLookupByAlias(session, vrfAlias):
    vrfs = session.md.lookupByClass("fvCtx", parentDn='uni/tn-common')
    vrfAlias = vrfAlias.strip()
    for vrf in vrfs:
        if vrf.nameAlias == vrfAlias:
            return vrf

    return False

def generic_check(session, **in_dict):
    if in_dict.get('subnet'):
        if not if_ip(in_dict['subnet']):
            sys.exit('Error. Bad subnet input: %s' % in_dict['subnet'])

    if in_dict.get('gateway'):
        if not if_ip(in_dict['gateway']):
            sys.exit('Error. Bad gateway input: %s' % in_dict['gateway'])

    if in_dict.get('ipaddrMask'):
        if not if_ip(in_dict['ipaddrMask']):
            sys.exit('Error. Bad ipaddrMask input: %s' % in_dict['ipaddrMask'])

    if in_dict.get('vrfId'):
        vrfId = is_int(in_dict['vrfId'])

    if in_dict.get('device') == '':
        sys.exit('Error. Device name should not be empty')

    # Check valid tenants in APIC
    if in_dict.get('tenant'):
        tenants = listTenants(session)
        for tenant in tenants:
            if tenant.name == in_dict['tenant']:
                return True

        sys.exit('Tenant "{}" not found in {} environment'.format(in_dict['tenant'], session.env))

def nslookup(hostname):
    try:
        addr = socket.gethostbyname(hostname)
        return addr
    except Exception as e:
        return False
