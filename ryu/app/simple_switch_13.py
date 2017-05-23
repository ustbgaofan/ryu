# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        //新增一个存储Host MAC的数据结构，类别为dict字典
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        //一开始Switch连上Controller时的初始设定Function
        datapath = ev.msg.datapath  //接受OpenFlow交换机实例
        ofproto = datapath.ofproto  //OpenFLow交换机使用的OF协议版本
        parser = datapath.ofproto_parser //处理OF协议的parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        //以下片段用于设定Table-Miss FlowEntry
        //首先新增一个空的match，也就是能够match任何封包的match rule
        match = parser.OFPMatch()
        //指定这一条Table-Miss FlowEntry的对应行为
        //把所有不知道如何处理的封包都送到Controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        //把Table-Miss FlowEntry设定至Switch，并指定优先权为0（最低）
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        //取得与Switch 使用的OF 版本， 对应的OF协议及parser
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        //Instruction 是定义当封包满足match时，所要执行的动作
        //因此把action以 OFPInstructionActions 包装起来
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        
        // FlowMod Function 可以让我们对Switch写入由我们所定义的Flow Entry        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
         // 把定义好的FlowEntry送给Switch
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        //收到来自Switch 不知如何处理的封包（Match 到 Table-Miss FlowEntry）
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        //in_port 相当于分包从Switch 的哪个port 进到Switch 中
        //同事也代表 source Host MAC 要往 in_port 送，才能送达
        
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        
        dst = eth.dst  //得到封包目的端MAC address
        src = eth.src  //得到封包来源端MAC address 

        dpid = datapath.id    //Switch 的 datapath id （独一无二的ID）
        
        //如果 MAC表内不曾存储过这个Switch的MAC， 则帮他新增一个预设值
        // ex. mac_to_port = {'1': {'AA:BB:CC:DD:EE:FF': 2}}
        //    但是目前 dpid 为 2 不存在，执行 mac_to_port 会变成
        //    mac_to_port = {'1': {'AA:BB:CC:DD:EE:FF':2}, '2': {}}
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        
        //我们拥有来源端MAC 与in_port 了，因此可以学习到src MAC要往 in_port 送
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        //如果 目的端MAC 在 mac_to_port 表中的话，就直接告诉Switch送到 out_port
        //否则就请 Switch 用Flooding送出去
        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        //把刚刚的out_port 做成这次风暴的的处理动作
        actions = [parser.OFPActionOutput(out_port)]
        
        //如果没有让switch flooding，表示目的端mac 有学习过
        //因此使用 add_flow 让Switch 新增 FlowEntry 学习此条规则
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            
        //把要Switch执行的动作包装成Packet_out， 并让Switch执行动作
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
