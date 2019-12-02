from __future__ import print_function
import sys, json, re
sys.dont_write_bytecode = True
from libraries import cli_lib
from libraries.generic import switchportCmp, typeCmp, printDict, switchportCsv, getDict, printClass, parseHports, toJSONStr, printNode, printInterface, eprint, printJSON, getJSON

# Classes for ACI object collection and mapping
class cls_ppg():
    '''
    Leaf Port Policy Group class

    '''
    def __init__(self, name=None, label=None, poltype=None, aep=None, obj=None):
        self.obj = obj
        self.name = name
        self.label = label
        self.poltype = poltype
        self.aep = None
        self.ports = []

    def add_aep(self, aep):
        self.aep = aep

    def add_port(self, port):
        self.ports.append(port)

    def add_poltype(self, obj):
        types = {'infraAccBndlGrp': 'vpc', 'infraAccPortGrp': 'access'}
        self.poltype = types.get(obj.meta.moClassName)

    def print_json(self, verbose_flag=None, pretty=False):
        printJSON(self.obj, pretty=pretty)

    def setup(self, obj):
        self.obj = obj
        self.name = obj.name
        self.label = obj.meta.label
        self.add_poltype(obj)

    def get_ports(self, session):
        if self.obj:
            for c in self.obj.children:
                if c.meta.moClassName == 'infraRtAccBaseGrp':
                    node, interface = parseHports(c.tDn)
                    port = cls_port(node, interface)
                    port.get_physical(session)
                    self.add_port(port)

    def get_aeps(self, session):
        if self.obj:
            for c in self.obj.children:
                if c.meta.moClassName == 'infraRsAttEntP':
                    aep = cls_aep()
                    aep.by_dn(session, c.tDn)
                    self.add_aep(aep)
            if session.verbose_flag and self.aep:
                self.aep.get_epgs(session)

    def get_all(self, session):
        self.get_aeps(session)
        self.get_ports(session)

    def pp(self, verbose_flag=None, debug_flag=None, remote=False, json_flag=False, pretty=False):
        if json_flag:
            self.print_json(verbose_flag=verbose_flag, pretty=pretty)
        else:
            if len(self.ports) > 0:
                for port in self.ports:
                    port.pp(verbose_flag, debug_flag, remote=True)
                    print (' | {:30s}: {:15s}'.format(self.label, self.name), end ='')
                    if self.aep:
                        print (' | AEP: {}'.format(self.aep.name))
                    else:
                        print ()
                        if not remote:
                            print ()
            else:
                print ('{:30s}: {:15s}'.format(self.label, self.name), end ='')
                if self.aep:
                    print (' | AEP: {}'.format(self.aep.name), end='')

                if not remote:
                    print ()

class cls_aep():
    '''
    Access Entity Profile class

    '''
    def __init__(self, obj=None, name=None):
        self.obj = obj
        self.name = name
        self.epgs = []
        self.ppgs = []

    def add_epg(self, epg):
        self.epgs.append(epg)

    def add_ppg(self, ppg):
        self.ppgs.append(ppg)

    def by_dn(self, session, dn):
        self.obj = cli_lib.getAEP_by_dn(session, dn)
        if self.obj:
            self.name = self.obj.name

    def setup(self, obj):
        self.obj = obj
        self.name = obj.name

    def print_json(self, verbose_flag=None, pretty=False):
        printJSON(self.obj, pretty=pretty)
        if verbose_flag and len(self.epgs) > 0:
            for epg in self.epgs:
                printJSON(epg.obj, pretty=True)

        if verbose_flag and len(self.ppgs) > 0:
            for ppg in self.ppgs:
                printJSON(ppg.obj, pretty=True)

    def get_epgs(self, session):
        if self.obj:
            for c in self.obj.children:
                if c.meta.moClassName == 'infraGeneric':
                    for cc in c.children:
                        if cc.meta.moClassName == 'infraRsFuncToEpg':
                            epg = cls_epg_func(obj=cc)
                            epg.setup()
                            self.add_epg(epg)

    def get_ppgs(self, session):
        if self.obj:
            for c in self.obj.children:
                if c.meta.moClassName == 'infraRtAttEntP':
                    ppgObj = cli_lib.getPPG_byDn(session, c.tDn)
                    ppg = cls_ppg()
                    ppg.setup(ppgObj)
                    ppg.get_ports(session)
                    ppg.add_aep(self)
                    self.add_ppg(ppg)

    def get_all(self, session):
        self.get_epgs(session)
        self.get_ppgs(session)

    def pp(self, verbose_flag=None, debug_flag=None, remote=False, json_flag=False, pretty=False):
        if json_flag:
            self.print_json(verbose_flag=verbose_flag, pretty=pretty)
        else:
            if not verbose_flag and len(self.epgs) > 0:
                print ('AEP: {:16s}'.format(self.name), end='')
                for epg in self.epgs:
                    print ()
                    epg.pp(verbose_flag, debug_flag, remote=True)
                print ()

            elif verbose_flag and len(self.ppgs) > 0:
                for ppg in self.ppgs:
                    if len(ppg.ports) != 0:
                        #print ()
                        ppg.pp(verbose_flag, debug_flag, remote=True)

class cls_epg_func():
    '''
    Endpoint Group relation class

    '''
    def __init__(self, obj=None):
        self.obj = obj
        self.name = None
        self.encap = None
        self.mode = None

    def setup(self, obj=None):
        if not obj and not self.obj:
            return None
        elif obj:
            self.obj = obj

        try:
            self.name = re.search('epg-(.*)', str(self.obj.tDn)).group(1)
        except Exception as e:
            print ('! ERROR: {}'.format(e))
            return None

        self.encap = self.obj.encap
        self.set_mode(self.obj.mode)

    def print_json(self, verbose_flag=None):
        printJSON(self.obj, pretty=True)

    def set_mode(self, mode):
        modes = {'native': 'access', 'regular': 'trunk'}
        try:
            self.mode = modes[mode]
        except Exception as e:
            self.mode = mode
            print ('! ERROR: {}'.format(e))

    def __str__(self):
        return ('\t- EPG: {:23s} | Switchport: {:7s} | Encap: {:9s}'.format(self.name, self.mode, self.encap))

    def pp(self, verbose_flag=None, debug_flag=None, remote=False, json_flag=False, pretty=False):
        if json_flag:
            self.print_json(verbose_flag=verbose_flag)
        else:
            print ('\t- EPG: {:23s} | Switchport: {:7s} | Encap: {:9s}'.format(self.name, self.mode, self.encap), end ='')

            if not remote:
                print ()

class cls_ep():
    '''
    Endpoint class

    '''
    def __init__(self, obj=None):
        self.obj = obj
        self.name = None
        self.ip = None
        self.mac = None
        self.encap = None
        self.node = None
        self.port = None
        self.vpc = None

    def setup(self, obj):
        self.obj = obj
        self.name = self.obj.name
        self.ip = self.obj.ip
        self.mac = self.obj.mac
        self.encap = self.obj.encap
        self.get_node()

    def get_node(self):
        for c in self.obj.children:
            if c.meta.moClassName == 'fvRsCEpToPathEp':
                node, port, vpc = cli_lib.getNodePort(c.tDn)
                self.node = node
                self.port = port
                self.vpc = vpc

    def print_json(self, verbose_flag=None, pretty=False):
        printJSON(self.obj, pretty=pretty)

    def pp(self, verbose_flag=None, debug_flag=None, remote=False, json_flag=False, pretty=False):
        if json_flag:
            self.print_json(verbose_flag=verbose_flag, pretty=pretty)
        else:
            if remote:
                print ('\t- EP Name: {:20s} | IP: {:16s} | MAC: {:20s} | ENCAP: {:10s} | Node: {:10s} | Port: {:6s} | vPC: {}'.format(self.name, self.ip, self.mac, self.encap, self.node, self.port, self.vpc), end='')
            else:
                print ('EP Name: {:20s} | IP: {:16s} | MAC: {:20s} | ENCAP: {:10s} | Node: {:10s} | Port: {:6s} | vPC: {}'.format(self.name, self.ip, self.mac, self.encap, self.node, self.port, self.vpc))


class cls_epg():
    '''
    Endpoint group class

    '''
    def __init__(self, obj=None):
        self.obj = obj
        self.name = None
        self.alias = None
        self.eps = []
        self.aeps = []
        self.enforcement = None


    def setup(self, obj):
        self.obj = obj

        self.name = self.obj.name
        self.alias = self.obj.nameAlias
        self.enforcement = self.obj.pcEnfPref

    def get_ep(self, session):
        ep = session.md.lookupByDn(self.obj.dn, subtree='full', subtreeClassFilter='fvCEp', parentDn=self.obj.dn)
        if ep.children:
            for c in ep.children:
                endpoint = cls_ep()
                endpoint.setup(c)
                self.eps.append(endpoint)

    def get_aep(self, session):
        aep_rt = session.md.lookupByDn(self.obj.dn, subtree='full', subtreeClassFilter='fvRtFuncToEpg', parentDn=self.obj.dn)
        if aep_rt.children:
            for c in aep_rt.children:
                dn = str(c.tDn).replace('/gen-default','')
                aep_obj = session.md.lookupByDn(dn)
                aep = cls_aep()
                aep.setup(aep_obj)
                self.aeps.append(aep)

    def print_json(self, verbose_flag=None, pretty=False):
        printJSON(self.obj, pretty=pretty)
        if verbose_flag:
            for ep in self.eps:
                ep.pp(verbose_flag=verbose_flag, json_flag=True, pretty=pretty)

    def set_mode(self, mode):
        modes = {'native': 'access', 'regular': 'trunk'}
        try:
            self.mode = modes[mode]
        except Exception as e:
            self.mode = mode
            print ('! ERROR: {}'.format(e))

    def __str__(self):
        return ('\t- EPG: {:23s} | Alias: {:9s}'.format(self.name, self.alias))

    def pp(self, verbose_flag=None, debug_flag=None, remote=False, json_flag=False, pretty=False):
        if json_flag:
            self.print_json(verbose_flag=verbose_flag, pretty=pretty)
        else:
            if remote:
                print ('\t- ', end='')
                print ('EPG: {:23s} | Alias: {:7s} | Enforcement: {}'.format(self.name, self.alias, self.enforcement), end ='')
            else:
                print ('EPG: {:23s} | Alias: {:7s} | Enforcement: {}'.format(self.name, self.alias, self.enforcement), end ='')
                if len(self.aeps) > 0:
                    print()
                    for aep in self.aeps:
                        print('\t- Used in AAEP: {}'.format(aep.name))
                print ()

            if verbose_flag:
                for ep in self.eps:
                    ep.pp(verbose_flag=verbose_flag, debug_flag=debug_flag, remote=True)
                    print ()

class cls_port():
    '''
    Switch port class

    '''
    def __init__(self, node=None, port=None, physObj = None, logicalObj = None):
        self.physObj = physObj
        self.logicalObj = logicalObj
        self.node = node
        self.port = port
        self.descr = None
        self.adminSt = None
        self.operSt = None
        self.operQual = None
        self.operSpeed = None
        self.switchingSt = None
        self.ppg = None

        # Errors:
        self.errIn = None
        self.errOut = None
        self.discardIn = None
        self.discardOut = None
        self.crc = None
        self.collisions = None
        self.inDrops = None
        self.outDrops = None

    def __str__(self):
        return ('Node: {} | Port: {}'.format(self.node, self.port))

    def setup(self, physObj = None, logicalObj = None):
        if physObj:
            self.physObj = physObj
            self.parse_phys()
            self.parse_errors()

        if logicalObj:
            self.logicalObj = logicalObj
            self.parse_logical()

    def print_json(self, verbose_flag=None, pretty=False):
        if self.physObj:
            printJSON(self.physObj, pretty=pretty)
        if self.logicalObj:
            printJSON(self.logicalObj, pretty=pretty)

    def parse_phys(self):
        self.port = self.physObj.id
        self.adminSt = self.physObj.adminSt
        self.descr = self.physObj.descr
        self.switchingSt = self.physObj.switchingSt
        for c in self.physObj.children:
            if c.meta.moClassName == 'ethpmPhysIf':
                self.operSt = c.operSt
                self.operQual = c.operStQual
                self.operSpeed = c.operSpeed

    def parse_errors(self):
        for c in self.physObj.children:
            if c.meta.moClassName == 'rmonIfOut':
                self.errOut = c.errors
                self.discardOut = c.discards

            if c.meta.moClassName == 'rmonIfIn':
                self.errIn = c.errors
                self.discardIn = c.discards

            if c.meta.moClassName == 'rmonEtherStats':
                self.crc = c.cRCAlignErrors
                self.collisions = c.collisions

            if c.meta.moClassName == 'rmonIngrCounters':
                self.inDrops = c.totaldroppkts

            if c.meta.moClassName == 'rmonEgrCounters':
                self.outDrops = c.totaldroppkts


    def parse_logical(self):
        pass

    def get_physical(self, session):
        if not self.node or not self.port:
            sys.exit('! ERROR: Node and Port should be initiated before calling port.get_physical method')

        node = cli_lib.getNodes(session, nodeFilter=self.node)
        if len(node) == 1:
            node = node[0]
        else:
            return None

        interface = cli_lib.getInterfaces(session, node.dn, self.port)
        self.physObj = interface[0]
        self.parse_phys()

    def get_logical(self, session):
        if not self.node or not self.port:
            return None
        try:
            leafProfile = cli_lib.getLeafPortProfile(session, self.node, self.port)
            if leafProfile:
                leafProfile = leafProfile[0]
            else:
                return None
        except Exception as e:
            print ('! ERROR: {}'.format(e))
            return None

        for c in leafProfile.children:
            if c.meta.moClassName == 'infraHPortS':
                for cc in c.children:
                    if cc.meta.moClassName == 'infraRsAccBaseGrp':
                        try:
                            ppg = cli_lib.getPPG_byDn(session, cc.tDn)
                        except Exception as e:
                            if session.debug_flag:
                                print (cc.dn)
                                print('! ERROR: {}'.format(e))
                            continue
                        c_ppg = cls_ppg()
                        c_ppg.setup(ppg)
                        c_ppg.get_aeps(session)
                        self.ppg = c_ppg

    def pp(self, verbose_flag=None, debug_flag=None, remote=False, json_flag=False, pretty=False, error_flag=False):
        if json_flag:
            self.print_json(verbose_flag=verbose_flag)
        else:
            print('Switch: {:8s} | Port: {:7s} | descr: {:34s} | adminSt: {:5s} | operSt: {:5s} | operSpeed: {:7s} | switchingSt: {:8s} '.format(self.node, self.port, self.descr, self.adminSt, self.operSt, self.operSpeed, self.switchingSt), end='')
            if error_flag:
                print('| errIn: {:3} | errOut: {:3} | discardIn {:3} | discardOut: {:3} | crc: {:3} | collision: {:3} | inDrops: {:3} | outDrops: {:3} '.format(self.errIn, self.errOut, self.discardIn, self.discardOut, self.crc, self.collisions, self.inDrops, self.outDrops), end='')
            else:
                print('| operQual: {:14s} '.format(self.operQual), end='')

            if self.ppg:
                print ('| ', end='')
                self.ppg.pp(verbose_flag, debug_flag, remote=True)

            if not remote:
                print ()

class cls_routes():
    '''
    Routes in ACI Fabric class

    '''
    def __init__(self, prefix=None):
        self.prefix = prefix
        self.routes = []

    def get_route(self, session, vrf=None):
        rt = session.md.lookupByClass('uribv4Route', propFilter='eq(uribv4Route.prefix, "{}")'.format(self.prefix), subtree='full', subtreeClassFilter='uribv4Nexthop')
        for r in rt:
            for child in r.children:
                if child.meta.moClassName == 'uribv4Nexthop':
                    route = cls_route(prefix=self.prefix, obj=child)
                    podId, nodeId, vrfName = route.parseDn(str(child.dn))
                    route.node = nodeId
                    route.podId = podId
                    route.vrfName = vrfName
                    route.nextHop = child.addr
                    route.routeTypes(child.type)
                    route.tag = child.tag
                    route.routeType = child.routeType
                    route.pref = child.pref

                    self.routes.append(route)

    def print_routes(self):
        for route in self.routes:
            print(self.prefix, end='')
            print (' via {} | VRF: {} | attached: {} | routeType: {} | tag: {} | pref: {} | Node: {} '.format(route.nextHop, route.vrfName, route.attached, route.routeType, route.tag, route.pref, route.node))

        pass


class cls_route():
    '''
    Single route class

    '''
    def __init__(self, prefix=None, obj=None):
        self.prefix = prefix
        self.obj = None
        self.node = None
        self.nextHop = None
        self.attached = False
        self.direct = False
        self.pervasive = False
        self.recursive = False
        self.tag = None
        self.routeType = None
        self.pref = None

    def parseDn(self, dn):
        #    DN: topology/pod-1/node-1102/sys/uribv4/dom-common:vrf112/db-rt/rt-[10.32.58.0/27]/nh-[static]-[100.101.104.66/32]-[unspecified]-[overlay-1]
        try:
            podId = re.search('topology/pod-(\d+)/', dn).group(1)
        except:
            podId = None

        try:
            nodeId = re.search('node-(\d+)/', dn).group(1)
        except:
            nodeId = None

        try:
            vrfName = re.search('dom-common:(vrf\d+)', dn).group(1)
        except:
            vrfName = re.search('dom-([a-zA-Z]*)\/', dn).group(1)

        return podId, nodeId, vrfName

    def routeTypes(self, types):
        # 10.32.58.0/27 via 100.101.104.66/32 | VRF: vrf112 | type: attached,direct,pervasive,recursive | routeType: static | tag: 0 | pref: 1 | Node: 1403
        # recursive - pointing to overlay. Or pointing to a network not a next hop IP
        # pervasive - a distributed gw (anycast)
        for t in types.split(','):
            if str(t) == 'attached':
                self.attached = True
            if str(t) == 'direct':
                self.direct = True
            if str(t) == 'recursive':
                self.recursive = True
            if str(t) == 'pervasive':
                self.pervasive = True

class cls_node():
    '''
    Fabric Node class

    '''
    def __init__(self, node=None, obj=None):
        self.name = node
        self.ports = []
        self.mgmtIp = None
        self.serial = None
        self.model = None
        self.role = None
        self.id = None
        self.status = None
        self.addr = None
        self.ppg = None
        self.runningVer = None
        self.fwVer = None

    def setup(self, obj):
        self.obj = obj
        self.name = obj.name
        self.serial = obj.serial
        self.model = obj.model
        self.role = obj.role
        self.id = obj.id
        self.fabricSt = obj.fabricSt

    def print_json(self, verbose_flag=None, pretty=False):
        printJSON(self.obj, pretty=pretty)
        if verbose_flag and len(self.ports) > 0:
            for port in self.ports:
                port.print_json()

    def get_sys(self, session):
        try:
            nodeSys = cli_lib.getSys(session, nodeDn = self.obj.dn)
            self.mgmtIp = nodeSys.oobMgmtAddr
            self.addr = nodeSys.address
        except:
            pass

    def get_ports(self, session, port=None):
        interfaces = cli_lib.getInterfaces(session, nodeDn = self.obj.dn, portId = port)
        for i in interfaces:
            c_port = cls_port(node=self.name)
            c_port.setup(physObj = i)
            if session.verbose_flag:
                c_port.get_logical(session)
            self.add_port(c_port)

    def get_version(self, session):
        dhcpClient = cli_lib.getDhcpClient(session, self.serial)
        try:
            self.runningVer = dhcpClient.runningVer
            self.fwVer = dhcpClient.fwVer
        except:
            pass


    def add_port(self, port):
        self.ports.append(port)

    def port_pp(self, verbose_flag=None, debug_flag=None, remote=False, json_flag=False, pretty=False, error_flag=False):
        if json_flag:
            port_list = []
            for port in self.ports:
                port_list.append(json.loads(getJSON(port.physObj)))

            if pretty:
                print (json.dumps(port_list, indent=2))
            else:
                print (json.dumps(port_list))
        else:
            ports = sorted(self.ports, key=lambda k: k.port, cmp=switchportCmp)
            for port in ports:
                port.pp(verbose_flag=verbose_flag, debug_flag=debug_flag, remote=False, json_flag=json_flag, error_flag=error_flag)

    def pp(self, verbose_flag=None, debug_flag=None, remote=False, json_flag=False, pretty=False, error_flag=False):
        if json_flag:
            self.print_json(verbose_flag=verbose_flag, pretty=pretty)
        else:
            print('ID: {:5s} | Name: {:9s} | Role: {:12s} | Status: {:10s} | Model: {:17s} | Serial: {:12s} | Mgmt: {:16s} | runVer: {:15s} | fwVer: {:15s}'.\
                    format(str(self.id), str(self.name), str(self.role), str(self.fabricSt), str(self.model), str(self.serial), str(self.mgmtIp), str(self.runningVer), str(self.fwVer)))
            # Sort ports
            ports = sorted(self.ports, key=lambda k: k.port, cmp=switchportCmp)
            for port in ports:
                port.pp(verbose_flag=verbose_flag, debug_flag=debug_flag, remote=True, json_flag=json_flag, error_flag=error_flag)
                if not remote:
                    print ()

class cls_bd():
    '''
    Bridge domain class

    '''
    def __init__(self, obj=None, name=None, alias=None, epg=None):
        self.obj = obj
        self.name = name
        self.alias = alias
        self.epg = epg
        self.vrf = None
        self.vrfAlias = None
        self.L3out = None
        self.gw = None

    def setup(self, obj):
        self.obj = obj
        self.name = obj.name
        self.alias = obj.nameAlias
        self.ipLearning = obj.ipLearning
        self.arpFlood = obj.arpFlood
        self.multiDstPktAct = obj.multiDstPktAct # Multi destination packet flooding
        self.unkMacUcastAct = obj.unkMacUcastAct
        self.unkMcastAct = obj.unkMcastAct
        self.unicastRoute = obj.unicastRoute

    def get_vrf(self):
        for c in self.obj.children:
            if c.meta.moClassName == 'fvRsCtx':
                self.vrf = c.tnFvCtxName

    def get_out(self):
        for c in self.obj.children:
            if c.meta.moClassName == 'fvRsBDToOut':
                self.L3out = c.tnL3extOutName

    def get_subnet(self):
        for c in self.obj.children:
            if c.meta.moClassName == 'fvSubnet':
                self.gw = c.ip

    def print_json(self, verbose_flag=None, pretty=False):
        printJSON(self.obj, pretty=pretty)

    def get_all(self):
        self.get_vrf()
        self.get_out()
        self.get_subnet()

    def pp(self, verbose_flag=None, debug_flag=None, remote=False, json_flag=False, pretty=False):
        if json_flag:
            self.print_json(verbose_flag=verbose_flag, pretty=pretty)
        else:
            print ('Name: {:22s} | Alias: {:10s}'.format(self.name, self.alias), end='')
            print ('| ipLearning: {:3s} | arpFlood: {:3s} | MultiDstFlood: {:10s} | unkMcastFlood: {:10s} | unkMcastAct: {:10s} | ucastRouting: {:6s}'.format(self.ipLearning, self.arpFlood, self.multiDstPktAct, self.unkMacUcastAct, self.unkMcastAct, self.unicastRoute), end='')
            print ('| VRF: {:6s}'.format(self.vrf), end='')
            print ('| L3 out: {:15s}'.format(self.L3out), end='')
            print ('| GW IP: {:15s}'.format(self.gw), end='')

        if not remote:
            print()


class cls_vrf():
    '''
    VRF class

    '''
    def __init__(self, obj=None):
        self.obj = obj
        self.name = None
        self.alias = None

    def setup(self, obj):
        self.obj = obj
        self.name = self.obj.name
        self.alias = self.obj.nameAlias

    def print_json(self, verbose_flag=None, pretty=False):
        printJSON(self.obj, pretty=pretty)

    def __str__(self):
        return ('VRF: {:7s} | Alias: {:20s}'.format(self.name, self.alias))

    def pp(self, verbose_flag=None, debug_flag=None, remote=False, json_flag=False, pretty=False):
        if json_flag:
            self.print_json(verbose_flag=verbose_flag, pretty=pretty)
        else:
            print(str(self))
