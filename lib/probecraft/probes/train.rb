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

require 'capby'
require 'probecraft/protocols/ethernet'
require 'probecraft/protocols/ip'
require 'probecraft/protocols/ipoptions'
require 'probecraft/protocols/icmp'
require 'probecraft/protocols/tcp'
require 'probecraft/protocols/udp'
require 'probecraft/matcher'

module Probecraft
  class Train

    attr_accessor :probecraft, :packets

    def initialize(probecraft, params={})
      @packets = []
      @probecraft = probecraft
      @timeout = params[:timeout] || 1
    end 

    def perform
      @probecraft.send @packets.map{|p| p[0]}
      @probecraft.dispatch(2*@packets.size, 5, @packets.map{|p| p[1]}) 
      #TODO: not always expect a response for one way tools
    end

    def add_probe_and_matcher(raw, matcher)
      @packets << [raw, matcher]
    end

    def raw_pkt_for(pkt, params)
      pkt.encode!
      raw = Capby::Packet.new pkt.to_s
      raw.after_delay = params[:idle] * 1000
      raw
    end

    def ip_layer_for(params)
      pkt = @probecraft.link_layer_pkt do |ll|
        ll.payload = IP.new do |ip|
          ip.src = @probecraft.iface_addr
          ip.dst = params[:target]
          ip.ttl = params[:ttl]
          ip.dont_fragment!
          ip.ipid = params[:ipid]
          if params[:use_ip_tst]
            ip.options << IPOption::TS.new do |opt|
              opt.ptr = 9
              opt.oflw_flgs = 0
              opt.timestamps << [params[:ot]]
              8.times do |t|
                opt.timestamps << [0]
              end
            end
          end
          if params[:record_route]
            ip.options << IPOption::RR.new do |opt|
              opt.route << [0,0,0,0]
            end
          end
        end
      end
      yield pkt.payload if block_given?
      pkt
    end

    def add_icmp_echo_probe(params)
      params = parse_params(params)
      pkt = ip_layer_for(params) do |ip|
        ip.payload = ICMP.new do |icmp|
          icmp.kind = :echo_request
          icmp.seqnum = params[:seqnum]
          icmp.identifier = params[:identifier]
          icmp.data = params[:data]
        end
      end

      raw = raw_pkt_for(pkt, params)

      matcher = Matcher.new do |m|
        m.layers(Ethernet, IP, ICMP) do |icmp|
          (icmp[:echo_reply] or icmp[:echo_request]) and 
          (icmp.identifier == params[:identifier]) and
          (icmp.seqnum == params[:seqnum])
        end
      end

      add_probe_and_matcher(raw, matcher)
    end

    def add_icmp_tst_probe(params)
      pkt = ip_layer_for(params) do |ip|
        ip.payload = ICMP.new do |icmp|
          icmp.kind = :timestamp_request
          icmp.seqnum = params[:seqnum]
          icmp.identifier = params[:identifier]
          icmp.ot = params[:ot]
        end
      end

      raw = raw_pkt_for(pkt, params)

      matcher = Matcher.new do |m|
        m.layers(Ethernet, IP, ICMP) do |icmp|
          (icmp[:timestamp_reply] or icmp[:timestamp_request]) and 
          (icmp.identifier == params[:identifier]) and
          (icmp.seqnum == params[:seqnum])
        end
      end
      add_probe_and_matcher(raw, matcher)
    end

    def add_udp_echo_probe(params)
      pkt = ip_layer_for(params) do |ip|
        ip.payload = UDP.new(ip) do |udp|
          udp.dstport = 7 
          udp.srcport = params[:sport]
          udp.payload = params[:data]
        end
      end

      raw = raw_pkt_for(pkt, params)

      matcher = Matcher.new do |m|
        m.layers(Ethernet, IP, ICMP) do |udp|
          #XXX not implemented !!!
          raise
        end
      end
      add_probe_and_matcher(raw, matcher)
    end

    def add_tcp_oof_probe(params)
      pkt = ip_layer_for(params) do |ip|
        ip.payload = TCP.new(ip) do |tcp|
          tcp.dstport = params[:dport]
          tcp.srcport = params[:sport]
          tcp.payload = params[:data]
        end
      end

      raw = raw_pkt_for(pkt, params)
      sent_ip = pkt.payload
      sent_tcp = sent_ip.payload

      matcher = Matcher.new do |m|
        m.layers(Ethernet, IP, TCP) do |tcp|
          #TODO: seqnum, srcport dport
          tcp.srcport = sent_tcp.dstport
          #XXX not implemented!
          raise
        end
      end
      add_probe_and_matcher(raw, matcher)
    end

    def add_ttl_expired_probe(params)
      pkt = ip_layer_for(params) do |ip|
        ip.payload = UDP.new(ip) do |udp|
          udp.dstport = params[:dport]
          udp.srcport = params[:sport]
          udp.payload = params[:data]
          udp.use_chksum = true
        end
      end

      raw = raw_pkt_for(pkt, params)
      sent_ip = pkt.payload
      sent_udp = sent_ip.payload

      matcher = Matcher.new do |m|
        m.layers(Ethernet, IP) do |ip|
          test = false
          if ip.payload.is_a? UDP
            test = true if (ip.payload.chksum == sent_udp.chksum)
          elsif ip.payload.is_a? ICMP
            test = true if paris_matching?(sent_ip, ip.payload)
          end
          test
        end
      end
      add_probe_and_matcher(raw, matcher)
    end

    private

    # See paris-traceroute matching for udp
    def paris_matching?(sent_ip, icmp)
      #Match the beggining of the reported IP msg
      m1 = Matcher.new do |m|
        m.layers(IP) do |ip|
          ip.ipid == sent_ip.ipid
        end
        m.layers(IP, UDP) do |udp|
          udp.chksum == sent_ip.payload.chksum
        end
      end

      m2 = Matcher.new do |m|
        m.layers(ICMP) do |icmp|
          (icmp[:time_exceeded]) and (m1.match? icmp.req_start)
        end
      end

      m2.match? icmp
    end

    public

    def << (opts={})
      params = parse_params opts
      case opts[:type]
      when :icmp_echo
        add_icmp_echo_probe params 
      when :icmp_tst
        add_icmp_tst_probe params 
      when :ttl_expired
        add_ttl_expired_probe params 
      when :udp_echo
        add_udp_echo_probe params
      end
    end

    def parse_params(opts={})
      params = opts.dup
      params[:type] ||= :icmp_echo
      params[:target] ||= '255.255.255.255'
      params[:idle] ||= 0
      params[:ttl] ||= 64
      params[:ipid] ||= rand(2**16)
      raise ArgumentError.new(":idle params should be < 1000") unless params[:idle] < 1000
      params[:seqnum] ||= rand(2**16)
      params[:identifier] ||= rand(2**16)
      params[:ot] ||= rand(2**32)
      params[:size] ||= 56
      params[:data] ||= (1 .. params[:size]).map{|i| rand(2**8)}.pack('C*')
      params[:dport] ||= rand(2**16)
      params[:sport] ||= rand(2**16)
      params
    end

  end
end
