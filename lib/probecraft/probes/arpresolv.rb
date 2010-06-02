#
# This file is part of Probecraft.
# 
# Probecraft is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# Probecraft is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public License
# along with Probecraft.  If not, see <http://www.gnu.org/licenses/>.
# 
# Copyright (c) 2009, Di Cioccio Lucas
#

require 'probecraft/probes/probe'
require 'probecraft/protocols/ethernet'
require 'probecraft/protocols/arp'
require 'probecraft/matcher'

module Probecraft
  class ARPResolution < Probe
    attr_reader :target_addr

    private

    def ip2ip(str)
      str.split('.').map{|i| i.to_i}.pack('c4').unpack('H*') 
    end

    def mac2mac(str)
      str.split(':').join
    end

    public

    def initialize(tgt, params={})
      @target_addr = ip2ip tgt
      @timeout = params[:timeout] || 1
    end

    def prepare
      @packet = @probecraft.link_layer_pkt do |eth|
        eth.dst = "ff:ff:ff:ff:ff:ff"
        eth.payload = ARP.new do |arp|
          arp.hw_type = "0001"
          arp.proto_type = "0800"
          arp.hw_size = 6
          arp.proto_size = 4
          arp.opcode = "0001"
          arp.src_hw = mac2mac @probecraft.iface_hw_addr
          arp.src_proto = ip2ip(@probecraft.iface_addr).first
          arp.tgt_hw = "000000000000"
          arp.tgt_proto = @target_addr.first
        end
      end
      @matcher = Matcher.new do |m|
        m.layers(Ethernet, ARP) do |arp|
          (arp.opcode == "0002") and
          (arp.src_proto.join == @target_addr.join) and
          (arp.tgt_proto.join == "84e36423" )
        end
      end
    end

    def perform!
      @packet.encode!
      @probecraft.send @packet.to_s
      @result = @probecraft.dispatch(1, @timeout, [@matcher])
      @result
    end

    def report
      item = @result[@matcher]
      p @result
      if item.size == 1
        item.first.payload.src_hw
      end
    end

  end
end
