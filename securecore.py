from pox.core import core
from pox.lib.revent import revent
import pox.openflow.libopenflow_01 as of
import pox.openflow.nicira as nx
from pox.openflow.discovery import Discovery
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
from pox.lib.addresses import IPAddr
from pox.lib.addresses import EthAddr
import pox.lib.packet as pkt
import pox.openflow.spanning_tree
import asyncore
import asynchat
import socket
import thread
import os
import RouteApp
import threading
import time
import pyinotify
import random

log = core.getLogger()
snort_addr=()
ip2serv_name = {}
serv_name2ip = {}
gateway_mac=EthAddr("08:00:27:47:7b:44")
MAXCMD = 100

def start_server(socket_map):
    asyncore.loop(map = socket_map)

def start_watch(wm, eh):
    notifier = pyinotify.Notifier(wm, eh)
    notifier.loop()

class MyEventHandler(pyinotify.ProcessEvent):
    log.info("Starting monitor...")

    def gen_cmd(self, pathname):
        try:
            fd = open(pathname, 'r')
            commands = fd.readlines(MAXCMD)
            fd.close()
            return commands
        except IOError as e:
            log.error("I/O error ({0}): {1}".format(e.errno, e.strerror))
        return -1
    def func_gen(self, event):
        commands = self.gen_cmd(event.name)
        if not commands == -1:
            core.secure.func_gen(event.name, commands)
        
    def func_del(self, event):
        func_name = "func_" + event.name
        try:
            core.secure.funclist.remove(func_name)
            func_name = func_name.replace(" ", "_")
            delattr(core.secure.handlers, func_name)
        except ValueError as e:
            log.error('%s is not in the funclist'%func_name)

    def process_IN_MOVED_TO(self, event):
        log.info('MOVED_TO event: %s'%event.name)
        self.func_gen(event)
        
    def process_IN_MODIFY(self, event):
        log.info('MODIFY event: %s'%event.name)
        self.func_gen(event)

    def process_IN_DELETE(self, event):
        log.info('DELETE event: %s'%event.name)
        self.func_del(event)

    def process_IN_MOVED_FROM(self, event):
        log.info('MOVED_FROM event: %s', event.name)
        self.func_del(event)

class AlertIn(revent.Event):

    def __init__(self, alertmsg):
        revent.Event.__init__(self)
        self.name = alertmsg[0]
        self.priority = alertmsg[1]
        self.src = alertmsg[2]
        self.dst = alertmsg[3]
        self.occation  = alertmsg[4]

class Reminder(revent.EventMixin):

    _eventMixin_events = set([
        AlertIn,
        ])
    def __init__(self):
        self.msg = None

    def set_msg(self, msg):
        self.msg = msg

    def alert(self):
        self.raiseEvent(AlertIn, self.msg)

class secure_connect(asynchat.async_chat):

    def __init__(self, connection, socket_map):
        asynchat.async_chat.__init__(self, connection, map = socket_map)
        self.buf = []
        self.ac_in_buffer_size = 1024
        self.set_terminator("@")

    def collect_incoming_data(self, data):
        self.buf.append(data)

    def found_terminator(self):
        temp = ("".join(self.buf)).split("\n")
        core.Reminder.set_msg(temp)
        core.Reminder.alert()
        self.buf=[]
        self.set_terminator("@")

class secure_server(asyncore.dispatcher):
    def __init__(self, socket_map):
        self.socket_map = socket_map
        asyncore.dispatcher.__init__(self, map = self.socket_map)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind(("0.0.0.0",20000))
        self.listen(5)
        
    def handle_accept(self):
        connection, addr = self.accept()
        snort_addr = addr
        server_connect = secure_connect(connection, self.socket_map)

class handlers(object):
    def __init__(self):
        pass

class secure(object):
    def start(self):
        core.openflow.addListeners(self)
        core.openflow_discovery.addListeners(self)
    
    def __init__(self, path):
        self.path = path
        self.filelist=None
        self.counter=0
        self.filenum=0
        self.cmdlist = ["disconnect", "wait", "reconnect", "pass", "monitor", "reset"]
	self.handlers = handlers()
        self.funclist = None
        self.sig_table= {"BAD-TRAFFIC same SRC/DST":"1",
                "ICMP Time-To-Live Exceeded in Transit":"2",
                "ICMP Echo Reply":"3",
                "ICMP PING BSDtype":"4",
                "ICMP PING *NIX":"5",
                "ICMP PING":"6",
                "SNMP AgentX/tcp request":"7",
                "SNMP request tcp":"8"}
        self.func_table={}
        self.alys_cmd()
        
        self.name_process()

        self.mactable = {}
        self.iptable = {}
        self.droplist = {}
        self.monitorlist = {}
        self.redirectlist = {}
        
        self.ignorelist = []
        
        self.socket_map = {}
        self.server = secure_server(self.socket_map)
        core.Reminder.addListeners(self)
        core.addListener(pox.core.GoingUpEvent, self.start_server)
        core.call_when_ready(self.start, ["openflow_discovery", "NX"])
        core.callDelayed(1, self.start_watch)

    def start_server(self, event):
        thread.start_new_thread(start_server, (self.socket_map,))

    def start_watch(self):
        wm = pyinotify.WatchManager()
        wm.add_watch(self.path, pyinotify.ALL_EVENTS, rec = True)
        eh = MyEventHandler()
        thread.start_new_thread(start_watch, (wm, eh))

    def func_gen(self, File, cmds):
        func_name = "func_" + File
        self.funclist.append(func_name)
        func_name = func_name.replace(" ", "_")
        cmdgenlist = []
        for each in cmds:
            item = each.split('\n')
            action=item[0].split(',')
            if action[0]=="time":
                action[1]=float(action[1])
                func_action = "self."+action[0]+"("+action[1]+")"
            elif action[0] in self.cmdlist:
                if(len(action) == 1):
                    func_action = "self."+action[0]+"()"
                else:
                    func_action = "self."+action[0]+"("+action[1]+")"
            cmdgenlist.append(func_action)
            func_action = ''

        function = "def "+func_name+"(self, src, dst):\n"
        for command in cmdgenlist:
            function = function+"    "+command+"\n"
        exec function        
        setattr(self.handlers, func_name, eval(func_name))
        log.info("%s registered"%func_name)


    def alys_file(self):
        for File in self.filelist:
            fd = open(self.path + File,'r')
            commands = fd.readlines(MAXCMD)
            fd.close()
            yield File, commands

    def alys_cmd(self):
        self.filelist = os.listdir(self.path)
        self.funclist = []
        self.filenum = len(self.filelist)
        filegen = self.alys_file()
        while self.counter < self.filenum:
            File,commands = filegen.next()
            self.func_gen(File, commands)
            self.counter += 1
   
    def disconnect(self,addr):
        if self.droplist.has_key(addr):
            self.droplist[addr] += 1
            return
        else:
            self.droplist[addr] = 1
        ipaddr = IPAddr(addr)
        if self.iptable.has_key(ipaddr):
            #Forbid inside machine from sending packets
            host_mac = self.iptable[ipaddr]
            switchid = self.mactable[host_mac][0]
            msg = of.ofp_flow_mod()
            msg.match.dl_src = host_mac
            msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
        else:
            global gateway_mac
            switchid = self.mactable[gateway_mac][0]
            msg = of.ofp_flow_mod()
            msg.match.nw_src = addr
            msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
        switch = core.openflow.getConnection(switchid)
        switch.send(msg)
        log.info("%s being disconncted"%addr)
    
    def redirect(self,addr):
        ipaddr = IPAddr(addr)
        if not self.iptable.has_key(ipaddr):
            return
        if self.redirectlist.has_key(addr):
            self.redirectlist[addr] += 1
        else:
            self.redirectlist[addr] = 1
        if self.redirectlist[addr] == 1:
            if addr in self.droplist:
                if ip2serv_name.has_key(addr):
                    serv_name = ip2serv_name[addr]
                    if serv_name2ip.has_key(serv_name):
                    	Masterip = serv_name2ip[serv_name][0]
                    	Masteraddr = IPAddr(Masterip)
                        livelist = [ item for item in serv_name2ip[serv_name] if item not in self.droplist ]
                        if len(livelist) > 0:
                            new_ip = random.choice(livelist)
                            log.info("redirectint for %s to %s \nin the service of %s"%(addr, str(new_ip), serv_name))
                            new_mac = self.iptable[IPAddr(new_ip)]
                            msg = of.ofp_flow_mod()
                            msg.match.dl_dst = self.iptable[Masteraddr]
                            msg.actions.append(of.ofp_action_dl_addr.set_dst(new_mac))
                            msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(newip)))
                            routelist = RouteApp.get_shortest_route(pox.openflow.spanning_tree._calc_spanning_tree(), \
                                self.mactable[gateway_mac][0], \
                                self.mactable[new_mac][0])
                            routelist[-1] = self.mactable[new_mac]
                            msg.actions.append(of.ofp_action_output(port = routelist[0][1]))
                            switchid = self.mactable[gateway_mac][0]
                            switch = core.openflow.getConnection(switchid)
                            switch.send(msg)
                            msg = of.ofp_flow_mod()
                            msg.match.dl_dst = gateway_mac
                            #msg.match.nw_proto = pkt.ipv4.TCP_PROTOCO
                            msg.actions.append(of.ofp_action_dl_addr.set_src(self.iptable[ipaddr]))
                            msg.actions.append(of.ofp_action_nw_addr.set_src(ipaddr))
                            msg.actions.append(of.ofp_action_output(port = self.mactable[gateway_mac][1])
                            switchid = self.mactable[gateway_mac][0]
                            switch = core.openflow.getConnection(switchid)
                            switch.send(msg)
                        else:
                            log.error("no more same service ip to redirect")
                    else:
                        log.error("check the service to ip dictionary %s"%serv_name)
                else:
                    log.error("check the ip to service dictionary %s"%addr)
            else:
                log.error("%s is not in droplist"%addr)

    def wait(self,arg):
        log.info("waiting for %d seconds"%arg)
        time.sleep(arg)

    def reconnect(self,addr):
        self.droplist[addr] -= 1
        if self.droplist[addr] <= 0:
            ipaddr = IPAddr(addr)
            self.droplist[addr] = 0
            log.info("%s being reconnected"%addr)
            msg = of.ofp_flow_mod()
            msg.command = of.OFPFC_DELETE_STRICT
            msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
            if self.iptable.has_key(ipaddr):
                host_mac = self.iptable[ipaddr]
                switchid = self.mactable[host_mac][0]
                msg.match.dl_src = host_mac
            else:
                global gateway_mac
                switchid = self.mactable[gateway_mac][0]
                msg.match.nw_src = addr
            msg.priority = of.OFP_DEFAULT_PRIORITY
            switch = core.openflow.getConnection(switchid)
            switch.send(msg)
    
    def monitor(self, addr):
        ipaddr = IPAddr(addr)
        if not self.iptable.has_key(ipaddr):
            return
        if self.monitorlist.has_key(addr):
            self.monitorlist[addr] += 1
        else:
            self.monitorlist[addr] = 1
        if self.monitorlist[addr] == 1:
            log.info("packet from/to %s mirrored for monitoring"%addr)
            msg = nx.nx_flow_mod()
            msg.table_id = 1
            msg.match.eth_src = self.iptable[ipaddr]
            msg.actions.append(of.ofp_action_dl_addr.set_dst(gateway_mac))
            routelist = RouteApp.get_shortest_route(pox.openflow.spanning_tree._calc_spanning_tree(), self.mactable[self.iptable[ipaddr]][0], self.mactable[gateway_mac][0])
            routelist[-1] = self.mactable[gateway_mac]
            msg.actions.append(of.ofp_action_output(port = routelist[0][1]))
            switchid = self.mactable[self.iptable[ipaddr]][0]
            switch = core.openflow.getConnection(switchid)
            switch.send(msg)

    #delete all flow entries in flowtable 1
    def reset(self, addr):

        self.monitorlist[addr] -= 1
        if self.monitorlist[addr] > 0:
            return
        self.monitorlist[addr] = 0
        log.info("resetting %s"%addr)
        msg = nx.nx_flow_mod()
        msg.command = of.OFPFC_DELETE_STRICT
        msg.table_id = 1
        ipaddr = IPAddr(addr)
        host_mac = self.iptable[ipaddr]
        msg.match.eth_src = host_mac
        switchid = self.mactable[host_mac][0]
        switch = core.openflow.getConnection(switchid)
        switch.send(msg)

    def unredirect(self, addr):
        self.redirectlist[addr] -= 1
        if self.redirectlist[addr] > 0:
            return
        self.redirectlist[addr] = 0
        log.info("unredirecting %s"%addr)
        msg = nx.nx_flow_mod()
        msg.command = of.OFPFC_DELETE_STRICT
        msg.table_id = 1
        serv_name = ip2serv_name[addr]
        Masterip = serv_name2ip[serv_name]
        Masteraddr = IPAddr(Masterip)
        host_mac = self.iptable[Masteraddr]
        msg.match.eth_dst = host_mac
        msg.match.of_ip_src = Masterip
        switchid = self.mactable[gateway_mac][0]
        switch = core.openflow.getConnection(switchid)
        switch.send(msg)


    def name_process(self):
        for func_name in self.funclist:
            value = func_name.split('_')
            del value[0]
            if not self.func_table.has_key(value[0]):
                self.func_table[value[0]]={}
            if not self.func_table[value[0]].has_key(value[1]):
		self.func_table[value[0]][value[1]] = {}
            if (len(value) == 4):
		self.func_table[value[0]][value[1]][(value[2],value[3])] = func_name
            else:
                self.func_table[value[0]][value[1]]["any"] = func_name
        
#{priority:{signatrue:{(interval, times):funcname}}}

    def occa_process(self, occation, during):
        timeArray = time.strptime(occation, "%Y-%m-%d %H:%M:%S")
        timeStamp = time.mktime(timeArray)
        timeStamp -= float(during)
        timeArray = time.localtime(timeStamp)
        before = time.strftime("%Y-%m-%d %H:%M:%S", timeArray)
        return before
      
    def _handle_AlertIn(self, event):
        log.info("Alert In.")
        sig = event.name
        occation = event.occation
        priority = event.priority
        sip  = event.src
        dip  = event.dst

        if self.monitorlist.has_key(sip) and self.monitorlist[sip] > 0 and not sig in self.ignorelist:
            log.info("%s is under attack and may have been captured, so disconncet it.")
            self.disconnect(sip)
        
        func_name = "func_"
        if self.func_table.has_key(priority):
            func_name += priority

            if self.func_table[priority].has_key(sig):
                func_name += "_" + sig
                
                if (len(self.func_table[priority][sig]) == 1) and (self.func_table[priority][sig].keys()[0] == "any"):
                    func_name += "_any"
                else:
                    timelist = [item for item in self.func_table[priority][sig].keys()]
                    flag = False
                    for time in timelist:
                        before = self.occa_process(occation, time[0])
                        times = self.sql(before, occation, sip, dip)
                        if times == time[1]:
                            func_name += "_" + time[0] + "_" + time[1]
                            flag = True
                            break
                    if not flag:
                        if (self.func_table[priority][sig].has_key("any")):
                            func_name += "_any"
                        else:
                            log.error("No Strategy for function %s"%func_name)
                            return

            elif (self.func_table[priority].has_key("any")):
                func_name += "_any"
                
                if (len(self.func_table[priority]["any"]) == 1) and (self.func_table[priority][sig][self.func_table[priority]["any"].keys()[0]] == "any"):
                    func_name += "_any"
                else:
                    timelist = [item for item in self.func_table[priority]["any"].keys()]
                    flag = False
                    for time in timelist:
                        before = self.occa_process(occation, time[0])
                        times = self.sql(before, occation, sip, dip)
                        if times == time[1]:
                            func_name += "_" + time[0] + "_" + time[1]
                            flag = True
                            break
                    if not flag:
                        if (self.func_table[priority]["any"].has_key("any")):
                            func_name += "_any"
                        else:
                            log.error("No Strategy for function %s"%func_name)
                            return
            else:
                log.error("No Strategy for function %s"%func_name)
                return

        else:
            log.error("No Strategy for priority %s"%func_name)
            return
        
        func_name = func_name.replace(" ", "_")
        new_th = threading.Thread(target = getattr(self.handlers, func_name), args=(self, sip, dip))
        new_th.start()

    def sql(self, before, occation, src, dst):
        try:
            conn = mysql.connector.connect(host=snort_addr[0], user='root',passwd='xiaobai',db='snort')
        except Exception, e:
           log.error(e)
           sys.exit(-1)
        cursor = conn.cursor
        cursor.excute("select count(*) as times from iphdr,event where (event.timestamp between %s and %s) and (iphdr.ip_src=%d and iphdr.ip_dst=%d) and iphdr.cid=event.cid;"%(before, occation, socket.ntohl(struct.unpack("I", socket.inet_aton(src))[0]), socket.ntohl(struct.unpack("I", socket.inet_aton(dst))[0])))
        rows = cursor.fetchone()
        cursor.close()
        conn.close()
        return str(row.times)
	
    def _handle_ConnectionUp(self, event):
        msg = nx.nx_packet_in_format()
        event.connection.send(msg)
        msg = nx.nx_flow_mod_table_id()
        event.connection.send(msg)
        msg = nx.nx_flow_mod(command = of.OFPFC_DELETE)
        msg.table_id = 1
        event.connection.send(msg)

    def _handle_PacketIn(self, event):
    
        packet = event.parsed
        #the flood method
        def flood(switch):      
            msg = of.ofp_packet_out()
      
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      
            msg.data = event.ofp
            msg.in_port = event.port
            switch.send(msg)
    
    #the drop method
        def drop(switch):
            msg = of.ofp_packet_out()
            msg.buffer_id = event.ofp.buffer_id
            msg.in_port = event.port
            switch.send(msg)
        
        ip = packet.find("ipv4")
        if ip == None:
            ip = packet.find("icmp")

        if ip:
            if not self.iptable.has_key(ip.srcip):
                self.iptable[ip.srcip] = packet.src

        if not self.mactable.has_key(packet.src):
             self.mactable[packet.src] = (event.dpid, event.port)
    
        if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
            drop(event.connection)
            return
        if packet.dst.is_multicast:
            flood(event.connection)
        else:
            if not self.mactable.has_key(packet.dst):
	        flood(event.connection)
            else:
	        routelist = RouteApp.get_shortest_route(pox.openflow.spanning_tree._calc_spanning_tree(), event.dpid, self.mactable[packet.dst][0])
	        routelist[-1] = self.mactable[packet.dst]
	        msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.actions.append(of.ofp_action_output(port = routelist[0][1]))
                event.connection.send(msg) 
	        for switchid,out_port in routelist:
	            msg = nx.nx_flow_mod()
                    msg.table_id = 0
	            msg.match.eth_dst = packet.dst
	            msg.actions.append(of.ofp_action_output(port = out_port))
                    msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 1))
                    msg.idle_timeout = 10
                    msg.hard_timeout = 30
	            switch = core.openflow.getConnection(switchid)
	            switch.send(msg)


def launch():
    path = "./rules/"
    core.registerNew(Reminder)
    core.registerNew(secure, path)
    log.info("Secure module launched.")
