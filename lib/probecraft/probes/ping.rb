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

require 'probecraft/protocols/ip'
require 'probecraft/protocols/icmp'
require 'probecraft/protocols/tcp'
require 'probecraft/protocols/udp'
require 'probecraft/probes/probe'
require 'probecraft/matcher'

module  Probecraft
  class Ping < Probe
    attr_accessor :target, :packet, :timeout, :matched, :size

    def initialize(tgt, params={})
      @target = tgt
      @timeout = params[:timeout] || 1
      @size = params[:size] || 56
      @matched = []
    end

    def [](layer)
      #TODO: return the @packet at the layer lvl
    end

    def perform!
      @packet.encode!
      @probecraft.send @packet.to_s
      @result = @probecraft.dispatch(@expected, @timeout, [@matcher])
      @result
    end
  end

  class ICMPPing < Ping
    attr_accessor :seqnum, :seq, :ipid

    def initialize(tgt, params={})
      super
      @expected = 2
      @ipid = params[:ipid] || rand(2**16)
      @identifier = params[:id] || rand(2**16)
      @seq = params[:seq] || rand(2**16)
      @data = params[:data] || (1 .. (@size-28)).map{|i| rand(2**8)}.pack('C*')
    end

    def prepare
      @packet = @probecraft.link_layer_pkt do |ll|
        ll.payload = IP.new do |ip|
          ip.src = @probecraft.iface_addr
          ip.dst = @target
          ip.ttl = 32
          ip.dont_fragment!
          ip.ipid = @ipid
          ip.payload = ICMP.new do |icmp|
            icmp.kind = :echo_request
            icmp.seqnum = @seq
            icmp.identifier = @identifier
            icmp.data = @data
          end
        end
      end
      @matcher = Matcher.new do |m|
        m.layers(Ethernet, IP, ICMP) do |icmp|
          (icmp[:echo_reply] or icmp[:echo_request]) and 
          icmp.identifier == @identifier
        end
      end
    end

    def report
      pair = @result[@matcher]
      if pair.size == 2
        pair[1].pkt_timestamp - pair[0].pkt_timestamp
      end
    end
  end

  class IPPing < Ping

    def initialize(tgt, params={})
      super
      @expected = 2
      @ipid = params[:ipid] || rand(2**16)
      @data = params[:data] || (1 .. (@size-20)).map{|i| rand(2**8)}.pack('C*')
    end

    def prepare
      @packet = @probecraft.link_layer_pkt do |ll|
        ll.payload = IP.new do |ip|
          ip.src = @probecraft.iface_addr
          ip.dst = @target
          ip.ttl = 32
          ip.dont_fragment!
          ip.ipid = @ipid
          ip.payload = @data
        end
      end
      @matcher = Matcher.new do |m|
        m.layers(Ethernet, IP) do |ip|
          false  #TODO
        end
      end
    end

    def report
      pair = @result[@matcher]
      if pair.size == 2
        pair[1].pkt_timestamp - pair[0].pkt_timestamp
      end
    end
  end

  class TCPPing < Ping

    attr_accessor :dstport

    def initialize(tgt, params={})
      super
      @expected = 2
      @ipid = params[:ipid] || rand(2**16)
      @srcport = params[:srcport] || rand(2**16)
      @dstport = params[:dstport] || 7
      @seq  = params[:seq] || 0
      @ack  = params[:ack] || 0
      @data = params[:data] || (1 .. (@size-40)).map{|i| rand(2**8)}.pack('C*')
      #TODO: allow to put some flags
    end

    def prepare
      @packet = @probecraft.link_layer_pkt do |ll|
        ll.payload = IP.new do |ip|
          ip.src = @probecraft.iface_addr
          ip.dst = @target
          ip.ttl = 32
          ip.dont_fragment!
          ip.ipid = @ipid
          ip.payload = TCP.new(ip) do |tcp|
            tcp.srcport = @srcport
            tcp.dstport = @dstport
            tcp.flags[:SYN] = true
            tcp.flags[:ACK] = true
            tcp.seq = @seq
            tcp.ack = @ack
            tcp.payload = @data
          end
        end
      end
      @matcher = Matcher.new do |m|
        m.layers(Ethernet, IP, TCP) do |tcp|
          ((tcp.dstport == @srcport) and 
           (tcp.srcport == @dstport)) or
           ((tcp.dstport == @dstport) and
            (tcp.srcport == @srcport))
        end
      end
    end

    def report
      pair = @result[@matcher]
      if pair.size == 2
        pair[1].pkt_timestamp - pair[0].pkt_timestamp
      end
    end
  end

  class UDPPing < Ping
    def initialize(tgt, params={})
      super
      @expected = 2
      @ipid = params[:ipid] || rand(2**16)
      @data = params[:data] || (1 .. (@size-28)).map{|i| rand(2**8)}.pack('C*')
      @srcport = params[:srcport] || rand(2**16)
      @dstport = params[:dstport] || 7
    end

    def prepare
      @packet = @probecraft.link_layer_pkt do |ll|
        ll.payload = IP.new do |ip|
          ip.src = @probecraft.iface_addr
          ip.dst = @target
          ip.ttl = 32
          ip.dont_fragment!
          ip.ipid = @ipid
          ip.payload = UDP.new(ip) do |udp|
            udp.srcport = @srcport
            udp.dstport = @dstport
            udp.payload = @data
          end
        end
      end
      @matcher = Matcher.new do |m|
        m.layers(Ethernet, IP, UDP) do |udp|
          ((udp.dstport == @srcport) and 
           (udp.srcport == @dstport)) or
           ((udp.dstport == @dstport) and
            (udp.srcport == @srcport))
        end
      end
    end

    def report
      pair = @result[@matcher]
      if pair.size == 2
        pair[1].pkt_timestamp - pair[0].pkt_timestamp
      end
    end
  end
end

