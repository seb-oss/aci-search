#!/usr/bin/env python2.7
from __future__ import print_function
import sys
sys.dont_write_bytecode = True
import argparse
import yaml
import os
import json
import re
import operator
import cobra.mit.request
import cobra.mit.naming
import hashlib
import time
import ipaddress
from datetime import datetime
from signal import signal, SIGPIPE, SIG_DFL
try:
    from libraries.aci_obj import *
except ImportError:
    # Fix python PATH to find aci libraries
    sys.path.append(os.path.dirname(__file__) + '/../')
    from libraries.aci_obj import *
from libraries import login, cli_lib, sql
from libraries.generic import switchportCmp, typeCmp, printDict, switchportCsv, getDict, printClass, parseHports, toJSONStr, printNode, printInterface, eprint, printJSON, getJSON, ipCalc

# Change the way IOError are handled when using PIPE |
# This is needed if you want to use GNU utilities like grep with pipe
signal(SIGPIPE, SIG_DFL)

fault_blacklist = { 'F3083': 'config-error', # Sample of blacklist. Do not show Duplicate MAC faults
                    }

def main():
    '''
    Main function that takes in user arguments and parses them
    '''
    parser = argparse.ArgumentParser(description='Script argument parser.')
    parser.add_argument('env', nargs='?', choices=('fabric1_alias', 'fabric2_alias'),
                        help='select environment to connect to')
    parser.add_argument('--node', dest='node', metavar='SwitchID',
                        help='input: switch/nodeId. Lookup switchport info by node')
    parser.add_argument('--pod', metavar='PodID', type=int,
                        help='input: <podId>')
    parser.add_argument('--port', metavar='PortID', type=str,
                        help='input port. Use with --node <nodeId>. Filter specific port')
    parser.add_argument('--bd', type=str,
                        help='lookup Bridge Domain')
    parser.add_argument('--ppg', metavar='PortPolicy', type=str,
                        help='lookup Port Policy Groups')
    parser.add_argument('--aep', type=str,
                        help='lookup Access Entity Profile by name. Wildcard --aep=*')
    parser.add_argument('--epg', type=str,
                        help='lookup End-Point Group by name. Wildcard --epg=*')
    parser.add_argument('--lldp', action='store_true', default=False,
                        help='lookup LLDP neighbors')
    parser.add_argument('-i', '--ip', type=str,
                        help='search for Endpoint by IP or partial IP')
    parser.add_argument('--mac', type=str,
                        help='search for Endpoint by MAC')
    parser.add_argument('--cdp', action='store_true', default=False,
                        help='lookup CDP neighbors')
    parser.add_argument('-d', '--description',
                        help='interface search based on description')
    parser.add_argument('--vrf',
                        help='lookup existing VRFs. Wildcard --vrf=*')
    parser.add_argument('--route', default=False, nargs='*',
                        help='show ip route for given node. Use in conjunction with --node <nodeId> --route')
    parser.add_argument('--faults', default=False, nargs='*',
                        help='Show faults in Fabric')
    parser.add_argument('--dn', type=str,
                        help='lookup ACI object by DN')
    parser.add_argument('--cls', metavar='Class', type=str,
                        help='lookup ACI object by Class')
    parser.add_argument('-s', '--short', action='store_false', default=True,
                        help='output short JSON format')
    parser.add_argument('--pretty', action='store_true', default=False,
                        help='pretty print the JSON')
    parser.add_argument('--json', action='store_true',
                        help='return JSON object directly from ACI')
    parser.add_argument('-f', '--file', metavar='file', type=str,
                        help='file path and name where to print the output')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='turn ON debug')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='verbose output. Show usage of the object or print some additional details')
    parser.add_argument('--error', action='store_true', default=False,
                        help='display interface errors/discards. Use with --node --port')
    parser.add_argument('--test', action='store_true', default=False,
                        help='test stuff')

    if len(sys.argv[1:]) == 0:
        parser.print_help()

    try:
        args = parser.parse_args()
    except Exception as e:
        print ('! ERROR: {}'.format(e))
        parser.print_help()
        sys.exit()

    if not args.env:
        eprint('Please specify environment [prod|infraver|bdc] -h for more help')
        sys.exit()

    elif args.env and len(sys.argv[1:]) == 1:
        parser.print_help()
        sys.exit()

    if args.debug:
        print ('--- DEBUG Input Arguments:')
        print ('\t {}\n'.format(args))

    execute(args)

def execute(args):
    '''
    Function that checks user input and executes search functions
    '''
    session = login.Session(args.env, debug_flag = args.debug, verbose_flag = args.verbose)
    session.logIntoEnvironment()

    if args.ppg:
        PPGs = None
        if args.ppg == '*':
            PPGs = cli_lib.listPPG(session)
        else:
            PPGs = cli_lib.getPPG(session, args.ppg)

        for PPG in PPGs:
            c_ppg = cls_ppg()
            c_ppg.setup(PPG)
            if session.verbose_flag:
                c_ppg.get_all(session)
            c_ppg.pp(verbose_flag=session.verbose_flag, json_flag=args.json, pretty=args.pretty)

    if args.aep:
        #AEPs = cli_lib.listAEPs(session)
        if args.aep == '*':
            AEPs = cli_lib.findAEP(session)
        else:
            AEPs = cli_lib.findAEP(session, args.aep)

        for AEP in AEPs:
            c_aep = cls_aep()
            c_aep.setup(AEP)
            if session.verbose_flag:
                c_aep.get_ppgs(session)
            else:
                c_aep.get_epgs(session)
            c_aep.pp(verbose_flag=session.verbose_flag, json_flag=args.json, pretty=args.pretty)

    if args.node and not isinstance(args.route, list):
        nodes = cli_lib.getNodes(session, nodeFilter=args.node)
        nodes = sorted(nodes, key=lambda k: int(k.id))
        show_ports = False
        if args.port:
            show_ports = True
        for node in nodes:
            c_node = cls_node()
            c_node.setup(node)
            c_node.get_sys(session)
            c_node.get_version(session)
            if show_ports:
                if args.port == '*':
                    args.port = None
                c_node.get_ports(session, args.port)
                c_node.port_pp(verbose_flag=session.verbose_flag, json_flag=args.json, pretty=args.pretty, error_flag=args.error)
            else:
                c_node.pp(verbose_flag=session.verbose_flag, json_flag=args.json, pretty=args.pretty, error_flag=args.error)

    if isinstance(args.route, list):
        def showAllRoutes(session, args):
            if args.node:
                print ('Show all routes on node: {}'.format(args.node))
                nodes = cli_lib.getNodes(session, nodeFilter=args.node)
                for node in nodes:
                    c_node = cls_node()
                    c_node.setup(node)
                    c_node.get_route(vrf=args.vrf, subnet=None)
                    c_node.pp()
            else:
                print ('Show all routes on all nodes')

        def showRoute(session, args):
            prefix = args.route[0]
            if args.node:
                print ('Show all routes on node: {}'.format(args.node))
                nodes = cli_lib.getNodes(session, nodeFilter=args.node)
                for node in nodes:
                    c_node = cls_node()
                    c_node.setup(node)
                    c_node.get_route(vrf=args.vrf, subnet=args.route[0])
                    c_node.pp()
            else:
                prefix, gw, mask = ipCalc(args.route[0])
                print ('Show route for prefix {}/{} on all nodes'.format(prefix, mask))
                net = '{}/{}'.format(prefix, mask)
                rt = cls_routes(prefix=net)
                rt.get_route(session)
                rt.print_routes()

            pass

        if len(args.route) == 0:
            pass
            showAllRoutes(session, args)
        else:
            showRoute(session, args)

    if args.pod:
        pods = session.md.lookupByClass("fabricPod", parentDn='topology', propFilter='and(eq(fabricPod.id, "{}"))'.format(args.pod))
        for pod in pods:
            nodes = cli_lib.getNodesByPod(session, pod)
            nodes = sorted(nodes, key=lambda k: int(k.id))
            for node in nodes:
                c_node = cls_node()
                c_node.setup(node)
                c_node.get_sys(session)
                c_node.get_version(session)
                if session.verbose_flag:
                    c_node.get_ports(session, args.port)
                c_node.pp(verbose_flag=session.verbose_flag, json_flag=args.json, pretty=args.pretty, error_flag=args.error)

    if args.description:
        found_interfaces = cli_lib.searchDescription(session, args.description)

        for i in found_interfaces:
            try:
                node = re.search('node-(\d+)', str(i.parentDn)).group(1)
            except:
                sys.exit('! ERROR: failed to parse node')

            try:
                node = cli_lib.getNodes(session, nodeFilter=node)[0]
            except Exception as e:
                sys.exit('! ERROR: failed to fetch node. {}'.format(e))

            c_port = cls_port()
            c_port.node = node.name
            c_port.setup(i)
            c_port.get_physical(session)
            if session.verbose_flag:
                c_port.get_logical(session)
            c_port.pp(verbose_flag=session.verbose_flag, json_flag=args.json, pretty=args.pretty)

    if args.vrf and not isinstance(args.route, list):
        if args.vrf != '*':
            vrfId = cli_lib.is_int(args.vrf)
            if vrfId:
                vrfId = str(format(vrfId, '03d'))
                vrfId = 'vrf' + vrfId
                vrfFilter = 'and(wcard(fvCtx.name, "{}"))'.format(vrfId)
            else:
                # search by name 'vrfxxx'
                vrfFilter = 'and(wcard(fvCtx.nameAlias, "{}"))'.format(args.vrf)

            vrfs = session.md.lookupByClass("fvCtx", parentDn='uni/tn-common', propFilter=vrfFilter)
        else:
            vrfs = session.md.lookupByClass("fvCtx", parentDn='uni/tn-common')

        for vrf in vrfs:
            c_vrf = cls_vrf()
            c_vrf.setup(vrf)
            c_vrf.pp(verbose_flag=session.verbose_flag, json_flag=args.json, pretty=args.pretty)

    if args.bd:
        if args.bd == '*':
            BDs = session.md.lookupByClass('fvBD', subtree='full')
        else:
            BDs = session.md.lookupByClass('fvBD', propFilter='or(wcard(fvBD.name, "{0}")wcard(fvBD.nameAlias, "{0}"))'.format(args.bd), subtree='full')

        for BD in BDs:
            c_bd = cls_bd()
            c_bd.setup(BD)
            c_bd.get_all()
            c_bd.pp(verbose_flag=session.verbose_flag, json_flag=args.json, pretty=args.pretty)


    if args.epg:
        if args.epg == '*':
            EPGs = session.md.lookupByClass('fvAEPg')
        else:
            EPGs = session.md.lookupByClass('fvAEPg', propFilter='or(wcard(fvAEPg.name, "{0}")wcard(fvAEPg.nameAlias, "{0}"))'.format(args.epg))

        for epg in EPGs:
            c_epg = cls_epg()
            c_epg.setup(epg)
            c_epg.get_aep(session)
            if session.verbose_flag:
                c_epg.get_ep(session)
            c_epg.pp(verbose_flag=session.verbose_flag, json_flag=args.json, pretty=args.pretty)

    if args.lldp:
        lldpAdjEps = cli_lib.getLLDP(session)
        for adjEp in lldpAdjEps:
            localNode, localPort = localNodePort(str(adjEp.dn))
            print ('Local device: {:5s} | Local port: {:8s} | Remote device: {:25s} | Remote port: {:17s} | Descr: {}'.\
                    format(localNode, localPort, adjEp.sysName.replace('.sebank.se', ''), adjEp.portIdV, adjEp.portDesc))

    if args.cdp:
        cdpAdjEps = session.md.lookupByClass('cdpAdjEp')
        for adjEp in cdpAdjEps:
            localNode, localPort = localNodePort(str(adjEp.dn))
            devId = re.split('(.sebank.se)', adjEp.devId)[0]
            print ('Local device: {:5s} | Local port: {:8s} | Remote device: {:25s} | Remote port: {:17s}'.\
                    format(localNode, localPort, devId, adjEp.portId))

    if args.dn:
        try:
            dn = session.md.lookupByDn(args.dn)
            print (getJSON(dn, args.short, args.pretty))
        except Exception as e:
            sys.exit(e)

    if args.cls:
        try:
            filt = None
            cls = session.md.lookupByClass(args.cls, propFilter = filt)
            for c in cls:
                print (getJSON(c, args.short, args.pretty))
        except Exception as e:
            sys.exit(e)

    if args.mac:
        ep = args.mac
        EPs = endpointSearch(session, ep)
        for EP in EPs:
            print ('Node: {node} | Port: {port} | vPC: {vpc} | IP: {ip} | MAC: {mac} | Encap: {encap}'.format(**EP))

    if args.ip:
        ep = args.ip
        EPs = endpointSearch(session, ep)
        for EP in EPs:
            print ('Node: {node} | Port: {port} | vPC: {vpc} | IP: {ip} | MAC: {mac} | Encap: {encap}'.format(**EP))

    if isinstance(args.faults, list):
        if len(args.faults) == 0:
            getFaults(session, args)
        else:
            listFaults(session, args.faults[0])

    if args.test:
        pass

def listFaults(session, severity):
    '''
    Get faults from local database
    '''
    faults = faults_sql_get(session, severity)
    for f in faults:
        printFault(f, session.verbose_flag)

def getFaults(session, args):
    '''
    Get faults from APIC. Compare them do local database and update changes
    '''
    faults = session.md.lookupByClass('faultInfo', orderBy='faultInfo.lastTransition|desc')
    faults_filtered = []
    for fault in faults:
        fault_dict = {}
        try:
            fault_dict['hash'] = h1(str(fault.dn)+str(session.env))
            fault_dict['fabric'] = str(session.env)
            fault_dict['dn'] = str(fault.dn)
            fault_dict['domain'] = str(fault.domain)
            fault_dict['type'] = str(fault.type)
            fault_dict['cause'] = str(fault.cause)
            fault_dict['descr'] = str(fault.descr)
            fault_dict['lifeCycle'] = str(fault.lc)
            fault_dict['status'] = str(fault.status)
            fault_dict['created'] = str(fault.created)
            fault_dict['severity'] = str(fault.origSeverity)
            fault_dict['code'] = str(fault.code)
            faults_filtered.append(fault_dict)
        except:
            pass

    same, new_faults, old_faults, all_faults = faults_sql_check(session, faults_filtered)

    if len(new_faults) == 0 and len(old_faults) == 0:
        sys.exit('No new faults found')

    # Summary
    all_crit = [x for x in all_faults if x['severity'] == 'critical']
    all_major = [x for x in all_faults if x['severity'] == 'major']
    all_minor = [x for x in all_faults if x['severity'] == 'minor']
    all_warning = [x for x in all_faults if x['severity'] == 'warning']

    new_crit = [x for x in new_faults if x['severity'] == 'critical']
    new_major = [x for x in new_faults if x['severity'] == 'major']
    new_minor = [x for x in new_faults if x['severity'] == 'minor']
    new_warning = [x for x in new_faults if x['severity'] == 'warning']

    old_crit = [x for x in old_faults if x['severity'] == 'critical']
    old_major = [x for x in old_faults if x['severity'] == 'major']
    old_minor = [x for x in old_faults if x['severity'] == 'minor']
    old_warning = [x for x in old_faults if x['severity'] == 'warning']
    print ('Fabric: {}'.format(session.env))
    print ('{:<12s}     | New / Removed'.format('Severity:'))
    print ('{:<12s}{:<4} | (+{:<2}/-{:<2})'.format('Critical:', len(all_crit), len(new_crit), len(old_crit)))
    print ('{:<12s}{:<4} | (+{:<2}/-{:<2})'.format('Major:', len(all_major), len(new_major), len(old_major)))
    print ('{:<12s}{:<4} | (+{:<2}/-{:<2})'.format('Minor:', len(all_minor), len(new_minor), len(old_minor)))
    print ('{:<12s}{:<4} | (+{:<2}/-{:<2})'.format('Warning:', len(all_warning), len(new_warning), len(old_warning)))

    faults_sql_delete(session, old_faults)
    faults_sql_insert(session, new_faults)

    flag_newFaults = False
    if len(new_crit) > 0 or len(new_major) > 0:
        print ('-'*10)
        print ('New Critical/Major faults:')

        # Print only changes with Critical or Major faults
        for lst in [new_crit, new_major]:
        #for lst in [new_crit, new_major, new_minor, new_warning]:
            for f in lst:
                if f['code'] in fault_blacklist.keys():
                    pass
                else:
                    flag_newFaults = True
                    node, port, descr = getFaultPort(session, f['dn'])
                    printFault(f, session.verbose_flag, node, port, descr)
    else:
        sys.exit('Some faults... Nothing important')

    if not flag_newFaults:
        sys.exit('Some faults... Nothing important')


def getFaultPort(session, dn):
    try:
        node_1 = re.search('node-(\d+)', str(dn))
        name = node_1.group(1)
        node_1 = re.search('\[(eth\d+/\d+)\]', str(dn))
        port = node_1.group(1)

        verbose = session.verbose_flag
        session.verbose_flag=True
        nodes = cli_lib.getNodes(session, nodeFilter=name)
        node = nodes[0]
        c_node = cls_node()
        c_node.setup(node)
        c_node.get_ports(session, port)
        p = c_node.ports[0]
        session.verbose_flag = verbose
        return p.node, p.port, p.descr

    except Exception as e:
        return None,None,None

def printFault(f, verbose_flag=None, node=None, port=None, descr=None):
    if verbose_flag:
        print (json.dumps(f, indent=2))

    else:
        if node:
            print ('{} | {} | {} | HASH: {} | Description: {} | Code: {} | Node: {} | Port: {} | IntDescr: {}'.format(str(f['severity']).upper(), str(f['domain']).upper(), f['lifeCycle'], f['hash'], f['descr'], f['code'], node, port, descr))
        else:
            print ('{} | {} | {} | HASH: {} | Description: {} | Code: {}'.format(str(f['severity']).upper(), str(f['domain']).upper(), f['lifeCycle'], f['hash'], f['descr'], f['code']))

def endpointSearch(session, ep):
    if cli_lib.if_mac(ep):
        return searchMacEp(session, ep, None)
    else:
        return searchIpEp(session, ep)

def searchIpEp(session, ip):
    if cli_lib.if_ip(ip):
        EPs = []
        clsQuery = session.md.lookupByClass('fvCEp', subtree='full', subtreeInclude='required', subtreeClassFilter='fvIp', subtreePropFilter='eq(fvIp.addr, "{}")'.format(ip))
        for obj in clsQuery:
            EP = searchMacEp(session, obj.mac, ip)
            EPs = EPs + EP
        return EPs
    else:
        EPs = []
        print ('Wildcard search by IP: {}'.format(ip))
        clsQuery = session.md.lookupByClass('fvIp', propFilter='and(wcard(fvIp.rn, "{}"))'.format(ip), )
        for obj in clsQuery:
            EP = {}
            try:
                dnQuery = session.md.lookupByDn(obj.parentDn)
                nodeInfo = session.md.lookupByClass('fvRsCEpToPathEp', parentDn=obj.parentDn)
            except ValueError as e:
                continue

            for node in nodeInfo:
                if session.debug_flag:
                    printJSON(obj, pretty=True)
                    printJSON(dnQuery, pretty=True)
                    printJSON(node, pretty=True)
                EP = {}
                EP['ip'] = dnQuery.ip
                EP['mac'] = dnQuery.mac
                EP['encap'] = dnQuery.encap
                node, port, vpc = cli_lib.getNodePort(str(node.tDn))
                EP['node'] = node
                EP['port'] = port
                EP['vpc'] = vpc
                EPs.append(EP)
        return EPs

def searchMacEp(session, mac, ip):
    EPs = []
    MAC = mac.translate(None, ',.-:').lower()
    if ip:
        try:
            clsQuery = session.md.lookupByClass('fvCEp', subtree='full', subtreeClassFilter='fvCEp,fvRsCEpToPathEp,fvIp,fvRsHyper,fvRsToNic,fvRsToVm', propFilter='and(eq(fvCEp.mac, "{}")eq(fvCEp.ip, "{}"))'.format(MAC, ip))
        except ValueError as e:
            sys.exit()
    else:
        try:
            clsQuery = session.md.lookupByClass('fvCEp', subtree='full', subtreeClassFilter='fvCEp,fvRsCEpToPathEp,fvIp,fvRsHyper,fvRsToNic,fvRsToVm', propFilter='eq(fvCEp.mac, "{}")'.format(MAC))
        except ValueError as e:
            sys.exit()

    for obj in clsQuery:
        EP = {}
        EP['mac'] = obj.mac
        EP['ip'] = obj.ip
        EP['encap'] = obj.encap
        if session.debug_flag:
            printJSON(obj, pretty=True)
        for child in obj.children:
            if child.__class__.__name__ == 'RsCEpToPathEp':
                node, port, vpc = cli_lib.getNodePort(str(child.tDn))
                EP['node'] = node
                EP['port'] = port
                EP['vpc'] = vpc
                EPs.append(EP)
    return EPs

def localNodePort(dn):
    node = re.search('node-(\d+)', dn)
    name = node.group(1)
    node = re.search('\[(eth\d+/\d+)\]', dn)
    port = node.group(1)
    port = port.replace('/', '-')
    return (name, port)

def getIfName(session, intf):
    # phy interface name looks like phys-[eth1/98]
    name = None
    idx = None

    match = re.search('\[(eth\d+/\d+)\]', str(intf.dn))
    profile = session.md.lookupByClass('infraAccPortGrp', parentDn=intf.dn)
    if match:
        name = match.group(1)
        match = re.search('(\d+)/(\d+)', name)
        # multiplied by 200 for sorting purposes. Module 01=201, interface 13=213
        if match:
            idx = 200*int(match.group(1)) + int(match.group(2))
    return name, idx

def dnQuery(session, dnObject, classFilter=None):
    dnQuery = cobra.mit.request.DnQuery(dnObject)
    dnQuery.queryTarget = 'children'
    dnQuery.classFilter = classFilter
    childMos = session.md.query(dnQuery)
    return childMos

def arrayPrintJSON(arr, allprops=True, pretty=False):
    jsonArray = []
    for i in arr:
        d = json.loads(getJSON(i, allprops=True, pretty=False))
        jsonArray.append(d)

    pretty_indent = None
    if pretty:
        pretty_indent = 2
    print (json.dumps(jsonArray, indent=pretty_indent))


def h1(w):
    '''
    Hashing function to get short unique string for Fault identificaiton
    '''
    return hashlib.md5(w).hexdigest()[:9] # After some tests, seems that 9 characters are enough to have unique hash

def faults_sql_get(session, severity):
    '''
    Get faults from local database by severity or hash string
    '''
    sqlSession = sql.LocalSqlSession()
    if str(severity).upper() in ['CRITICAL', 'MAJOR', 'MINOR', 'WARNING']:
        # Search by severity of the fault
        result = sqlSession.getFaults(env=session.env, severity=severity)

    else:
        # Search by hash
        result = sqlSession.getFaults(env=session.env, fault_hash=severity)

    return result

def faults_sql_check(session, faults):
    '''
    Run comparison of previous faults and new

    :param faults: list of faults received from apic
    :return: returns 4 lists of faults - same, new faults, old_faults, all_faults
    '''
    sqlSession = sql.LocalSqlSession()
    result = sqlSession.getFaults(env=session.env)
    new_faults = []
    gone_faults = []

    if len(result) == 0:
        # Return 4 lists
        # same, new_faults, old_faults, all_faults
        return result, faults, result, result

    else:
        sql_hashes = [i['hash'] for i in result]
        scan_hashes = [i['hash'] for i in faults]

        sql_set = set(sql_hashes)
        scan_set = set(scan_hashes)

        same = list(set(sql_set) & set(scan_set))
        new = list(set(scan_set) - set(sql_set))
        gone = list(set(sql_set) - set(scan_set))

        for fault in faults:
            new_faults.append(fault) if fault['hash'] in new else 0

        for fault in result:
            gone_faults.append(fault) if fault['hash'] in gone else 0

        return same, new_faults, gone_faults, result

def faults_sql_insert(session, faults):
    '''
    Populate database with faults from APIC
    :param faults: dictionary of faults to insert into database
    '''
    ts = time.localtime()
    dbTimeStamp = time.strftime('%Y-%m-%d-%H:%M', ts)

    sqlSession = sql.LocalSqlSession()
    for fault in faults:
        fault['timeStamp'] = dbTimeStamp
        sqlSession.insert(fault)

def faults_sql_delete(session, faults):
    '''
    Delete faults that are are not seen on the APIC anymore
    :param faults: dictionary of faults to delete from database
    '''
    sqlSession = sql.LocalSqlSession()
    for fault in faults:
        sqlSession.deleteFault(fault['hash'])

if __name__ == '__main__':
    main()
