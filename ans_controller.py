"""
 Copyright (c) 2026 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ether_types
import ipaddress


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller

        # Initializing a MAC table for the Layer 2 switches
        self.mac_to_port = {}

        # Router interface MAC addresses assumed by the controller
        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03"
        }

        # Router interface IP addresses (the gateways) assumed by the controller
        self.port_to_own_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }
        
        # This is the list of packets waiting for the ARP resolution, indexed by destination IP address.
        self.Pending_Packets = {}

        # The router's ARP table where it learns the IP-to-MAC mappings
        self.Arp_Table = {}

        # This dictionary used to allow a host to only ping his own gateway
        self.Allowed_Gateways = {
        '10.0.1.2': '10.0.1.1',
        '10.0.1.3': '10.0.1.1',
        '10.0.2.2': '10.0.2.1',
        '192.168.1.123': '192.168.1.1'
        }

        # This routing table maps the destination subnets to their corresponding router ports 
        self.Routing_Table = [
            {'network': ipaddress.IPv4Network('10.0.1.0/24'), 'port': 1},
            {'network': ipaddress.IPv4Network('10.0.2.0/24'), 'port': 2},
            {'network': ipaddress.IPv4Network('192.168.1.0/24'), 'port': 3},
        ]



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # Installing the table-miss rule so unmatched packets are sent to the controller
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):

        # Get OpenFlow protocol constants for the switch (datapath)
        ofproto = datapath.ofproto
         # Get OpenFlow parser to build messages and actions for the switch
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        #the buffer ID will be included if the packet is buffered on the switch
        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, buffer_id=buffer_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    # Handling the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        msg = ev.msg
        datapath = msg.datapath
        
        # Your controller implementation should start here
        in_port = msg.match['in_port'] 

        pkt = packet.Packet(msg.data) 
        eth = pkt.get_protocol(ethernet.ethernet)
        
        dpid = datapath.id

        # The Router Handling, ARP and IPv4 are processed separately
        if dpid==3:
            # Handle ARP packets
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                self.ARP_Packet_Handler(datapath,pkt, in_port, eth)
            # Handle IPV4 packets
            elif eth.ethertype == ether_types.ETH_TYPE_IP:
                self.IPV4_Packet_Handler(datapath, pkt,in_port, eth)
            return
        else:
            # The Switch handling for s1 and s2.
            self.Switch_Packet_Handler(msg, datapath, in_port, eth, msg.buffer_id)
            
    def Switch_Packet_Handler(self, msg, datapath, in_port, eth, buffer_id=None):

        # The Learning switch logic
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dst = eth.dst # MAC address of the destination host
        src = eth.src # MAC address of the source host
        dpid = datapath.id # The switch's ID that received the packet

        # Create an empty MAC-to-port mapping if it doesn't already exist for the switch
        self.mac_to_port.setdefault(dpid, {})

        # Learn the mac address to avoid flooding next time
        self.mac_to_port[dpid][src] = in_port

        # Check whether the destination is known or whether flooding is needed
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # Install a flow to avoid packet_in next time
        if out_port == ofproto.OFPP_FLOOD:
            match = datapath.ofproto_parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, ofproto.OFP_DEFAULT_PRIORITY, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, ofproto.OFP_DEFAULT_PRIORITY, match, actions)

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        else:
            data = None

        self.send_packet_out(datapath, bufferid=msg.buffer_id, actions=actions, port=in_port, data=data)


    def ARP_Packet_Handler(self, datapath, pkt, in_port, eth):
        
        arp_pkt = pkt.get_protocol(arp.arp)
                
        self.logger.info("ARP packet received : src_ip = %s dst_ip = %s in_port = %s src_mac = %s dst_mac = %s",arp_pkt.src_ip,arp_pkt.dst_ip, in_port, eth.src, eth.dst)

        # If it's an ARP request targeting the router's gateway IP, send a reply ; otherwise forward an ARP request to the destination or handle the ARP reply
        if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == self.port_to_own_ip[in_port]:
            self.ARP_Sending_Reply(datapath, pkt, in_port, eth, arp_pkt)
        elif arp_pkt.opcode == arp.ARP_REQUEST: 
            self.ARP_Sending_Request(datapath, pkt, in_port, eth, arp_pkt)
        else:
            self.ARP_Handling_Reply(datapath, pkt, in_port, eth, arp_pkt)


    def ARP_Sending_Reply(self, datapath, pkt, in_port, eth, arp_pkt):

        self.logger.info("The ARP request is for the router interface on port %s ; generating a reply.", in_port)

        # saved the H1 source mac and source ip in the arp table with the port number as well, so that we can use it later to send the ARP reply and also to forward the IP packets
        self.Arp_Table[arp_pkt.src_ip] = {'mac': eth.src, 'port': in_port} 
        
        # The router's MAC and IP will be the source, while host's MAC and IP who sent the ARP request will be the destination for the ARP reply
        src_mac = self.port_to_own_mac[in_port] 
        src_ip = self.port_to_own_ip[in_port]
        dst_ip = arp_pkt.src_ip 
        dst_mac = eth.src 
        dst = eth.src
        src = src_mac

        self.logger.info("The ARP Reply info | src_mac : %s, src_ip = %s, dst_ip = %s, dst_mac : %s, src = %s, dst = %s",src_mac, src_ip, dst_ip, dst_mac, src, dst)          
        
        # Construct the ARP reply packet
        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(
            ethertype = eth.ethertype,
            dst = dst_mac,
            src = src_mac
        ))
        arp_reply.add_protocol(arp.arp(
            opcode = arp.ARP_REPLY,
            src_mac = src_mac,
            src_ip = src_ip,
            dst_mac = dst_mac,
            dst_ip = dst_ip
        ))
        arp_reply.serialize()

        parser = datapath.ofproto_parser 
        ofproto = datapath.ofproto
        actions = [parser.OFPActionOutput(in_port)]

        self.send_packet_out(datapath, bufferid=ofproto.OFP_NO_BUFFER, actions=actions, port=ofproto.OFPP_CONTROLLER, data=arp_reply.data) 
        
    def ARP_Sending_Request(self, datapath, pkt, in_port, eth, arp_pkt):

        self.logger.info( "Destination MAC unknown for dst_ip = %s. Broadcast the ARP request In Port = %s, src_ip = %s", arp_pkt.dst_ip, in_port, arp_pkt.src_ip)

        # Determine the output port based on the destination IP address 
        out_port = self.get_out_port(arp_pkt.dst_ip)

        # The router interface MAC/IP will be the source; the destination MAC is unknown, so the ARP request is broadcast
        src_mac = self.port_to_own_mac[out_port]
        src_ip = self.port_to_own_ip[out_port]
        dst_ip = arp_pkt.dst_ip
        dst_mac='00:00:00:00:00:00'
        dst='ff:ff:ff:ff:ff:ff' 

        # Construct the ARP request packet
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=dst,
            src=src_mac
        ))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac='00:00:00:00:00:00',
            dst_ip=dst_ip
        ))
        pkt.serialize()

        # Store the packet info until the ARP reply is received
        self.Pending_Packets.setdefault(dst_ip, []).append((in_port, eth.src, arp_pkt.src_ip)) 

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        actions = [parser.OFPActionOutput(out_port)]
        Packet_Out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions, data=pkt.data,
                                  buffer_id=ofproto.OFP_NO_BUFFER)
        datapath.send_msg(Packet_Out) 

    def ARP_Handling_Reply(self, datapath, pkt, in_port, eth, arp_pkt):

        # Here we Learn the sender's MAC address from an ARP reply and release the waiting packets

        self.logger.info("an ARP reply received: src_ip = %s, dst_ip = %s, in_port = %s, src_mac = %s, dst_mac = %s",arp_pkt.src_ip,arp_pkt.dst_ip, in_port, eth.src, eth.dst)
        
        # Get the source IP address from the ARP reply
        src_ip = arp_pkt.src_ip
        
        # Store the sender's IP and MAC address in the ARP table. It will be used later for IP packets forwarding and also to send ARP replies if needed
        self.Arp_Table[src_ip] = {'mac': eth.src, 'port': in_port} 

        # Check If a pending packet exists for this IP, if yes, generate and send ARP replies to resolve it
        if src_ip in self.Pending_Packets:
            self.logger.info("Found a packet with source ip : %s",src_ip)
            for out_port, dst, dst_ip in self.Pending_Packets[src_ip]:
                self.logger.info("Generating an ARP Reply for the request from : Port : %s, IP : %s, MAC : %s",out_port, dst_ip, dst)
                arp_reply = packet.Packet()
                arp_reply.add_protocol(ethernet.ethernet(
                    ethertype = eth.ethertype,
                    dst = dst,
                    src = eth.src
                ))
                arp_reply.add_protocol(arp.arp(
                    opcode = arp.ARP_REPLY,
                    src_mac = eth.src,
                    src_ip = src_ip,
                    dst_mac = dst,
                    dst_ip = dst_ip
                ))
                arp_reply.serialize()

                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto
                actions = [parser.OFPActionOutput(out_port)]
                Packet_Out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_CONTROLLER,
                                          actions=actions, data=arp_reply.data,
                                          buffer_id=ofproto.OFP_NO_BUFFER)
                datapath.send_msg(Packet_Out)

    def IPV4_Packet_Handler(self, datapath, pkt, in_port, eth):

        # Handling IPv4 packets using the learned ARP table and static subnet mapping

        ip_pkt = pkt.get_protocol(ipv4.ipv4)        
    
        self.logger.info("IPv4 packet received: src_ip = %s, dst_ip = %s, in_port = %s, proto = %s",ip_pkt.src,ip_pkt.dst, in_port, ip_pkt.proto)

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        # Learn the source IP and MAC address in the ARP table, so that we can use it later to forward the IP packets and also to send ARP replies if needed
        self.Arp_Table[src_ip] = {'mac': eth.src, 'port': in_port} 
        
        # Retrieve the destination host information from the ARP table
        Dst_Entry = self.Arp_Table.get(dst_ip)
        
        # If the destination is unknown, either reply to gateway ICMP requests or send an ARP request to discover the host
        if not Dst_Entry:
            self.logger.info("No ARP entry for %s, sending ARP request on port %d", dst_ip, in_port)

            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                if src_ip in self.Allowed_Gateways and self.Allowed_Gateways[src_ip] == dst_ip:
                    self.logger.info("ICMP Echo Request Received. Sending an ICMP Reply")
                    self.send_icmp_reply(datapath, pkt, ip_pkt, icmp_pkt, in_port)
                    return

            # Construct the ARP request packet to discover the destination host's MAC address
            arp_pkt = packet.Packet()
            arp_pkt.add_protocol(ethernet.ethernet(
                ethertype=ether_types.ETH_TYPE_ARP,
                dst='ff:ff:ff:ff:ff:ff',
                src=eth.src
            ))
            arp_pkt.add_protocol(arp.arp(
                opcode=arp.ARP_REQUEST,
                src_mac=eth.src,
                src_ip=src_ip,
                dst_mac='00:00:00:00:00:00',
                dst_ip=dst_ip
            ))
            arp_pkt.serialize()

            self.ARP_Sending_Request(datapath, pkt, in_port, eth, arp_pkt.get_protocol(arp.arp))
            return

        self.logger.info( "The Destination is Resolved | dst_ip = %s, dst_mac = %s, output_port = %s", dst_ip, Dst_Entry['mac'], Dst_Entry['port'])
        
        # Traffic filtering policies

        self.logger.info("IPv4 packet Info | src_ip : %s, dst_ip : %s, Ip Proto : %s",src_ip, dst_ip, ip_pkt.proto)

        # Blocking all ICMP traffic involving the external host
        if (src_ip =='192.168.1.123' or dst_ip =='192.168.1.123') and ip_pkt.proto == 1: 
            self.logger.info("Dropping ICMP Packets For External Host")
            return
            
        # Blocking the TCP/UDP communication between external host and server
        elif (ip_pkt.proto == 6 or ip_pkt.proto == 17) and ((src_ip == '192.168.1.123' and dst_ip == '10.0.2.2') or (dst_ip == '192.168.1.123' and src_ip == '10.0.2.2')):
            self.logger.info("Dropping TCP and UDP Packets Between External Host and Server")
            return 

        # Creating a new Ethernet header using the destination MAC and the router outgoing interface MAC
        eth_packet = ethernet.ethernet(dst=Dst_Entry['mac'], src=self.port_to_own_mac[Dst_Entry['port']], ethertype=eth.ethertype)

        # Creating a new IPv4 header while keeping the original source IP, destination IP, and protocol type
        ipv4_pkt = ipv4.ipv4(dst=ip_pkt.dst, src=ip_pkt.src, proto=ip_pkt.proto)

        self.logger.info("The IPv4 Packet : %s",ipv4_pkt)
        
        # Building and serializing the complete Ethernet frame for transmission
        pkt.add_protocol(eth_packet)
        pkt.add_protocol(ipv4_pkt) 
        pkt.serialize()
        
        # Defining the actions that include rewriting both source and destination MACs, and forwarding packet to the destination port
        actions = [parser.OFPActionSetField(eth_src=self.port_to_own_mac[Dst_Entry['port']]),
                                parser.OFPActionSetField(eth_dst=Dst_Entry['mac']),
                                parser.OFPActionOutput(Dst_Entry['port'])]

        # Defining a match rule, matching IPv4 packets based on source and destination IP addresses              
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=ip_pkt.src,
            ipv4_dst=ip_pkt.dst
        )
        
        # Install the flow rule
        self.add_flow(datapath, ofproto.OFP_DEFAULT_PRIORITY, match, actions)

        Packet_Out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
            actions=actions, data=pkt.data)
        datapath.send_msg(Packet_Out)


    def send_icmp_reply(self, datapath, pkt, ip_pkt, icmp_pkt, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Extracting the Ethernet header from the received packet
        eth_packet = pkt.get_protocol(ethernet.ethernet)

        # Constructing the Ethernet and IPv4 headers for the ICMP reply
        eth = ethernet.ethernet(dst=eth_packet.src,
                            src=self.port_to_own_mac[in_port],
                            ethertype=ether_types.ETH_TYPE_IP)
        ip = ipv4.ipv4(dst=ip_pkt.src,
                   src=ip_pkt.dst,
                   proto=ip_pkt.proto)

        # Creating an ICMP Echo Reply message using data from the original ICMP request
        icmp_reply = icmp.icmp(
            type_=icmp.ICMP_ECHO_REPLY,
            code=0,
            csum=0,
            data=icmp_pkt.data
        )

        # Constructing a new packet object for the ICMP reply
        reply_packet = packet.Packet()
        reply_packet.add_protocol(eth)
        reply_packet.add_protocol(ip)
        reply_packet.add_protocol(icmp_reply)
        reply_packet.serialize()

        # The action is to send the packet back out through the incoming port
        actions = [parser.OFPActionOutput(in_port)]

        Packet_Out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=reply_packet.data
        )

        datapath.send_msg(Packet_Out)

    # This is a helper function to send packet_out messages to the switch
    def send_packet_out(self, datapath, bufferid, actions, port, data):
        parser = datapath.ofproto_parser

        Packet_Out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=bufferid, in_port=port,
            actions=actions, data=data)

        datapath.send_msg(Packet_Out)

    # Determine the output port based on the destination IP address using the routing table and longest prefix matching
    def get_out_port(self, dst_ip_str):
        dst_ip = ipaddress.IPv4Address(dst_ip_str)
        Longest_Prefix = None
        Selected_Port = None

        for entry in self.Routing_Table:
            if dst_ip in entry['network']:
                if Longest_Prefix is None or entry['network'].prefixlen > Longest_Prefix.prefixlen:
                    Longest_Prefix = entry['network']
                    Selected_Port = entry['port']

        return Selected_Port