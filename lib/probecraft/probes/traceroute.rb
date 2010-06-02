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

module Probecraft
  class LostPacket < Probe
    def initialize(tgt, ttl, params={})
      @target = tgt
      @ttl = ttl
      @timeout = params[:timeout] || 1
      @matched = []
    end

    def prepare
      @packet = @probecraft.link_layer_pkt do |ll|
        ll.payload = IP.new do |ip|
          ip.src = @probecraft.iface_addr
          ip.dst = @target
          ip.ttl = @ttl
          ip.dont_fragment!
          ip.ipid = rand(2**16)
        end
      end
      @matcher = Matcher.new do |m|
        m.layers(Ethernet, IP, ICMP) do |icmp|
          (icmp[:time_exceeded]) and 
          (icmp.code_name == :in_ttl) and
          (icmp.req_start.is_a? IP) and
          (icmp.req_start.ipid == @packet.payload.ipid)
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
      if item.first
        IP.unparse_ip item.first.payload.src
      end
    end
  end

  class Traceroute

    attr_accessor :target, :max_ttl, :retry, :probecraft

    def initialize(tgt, params={})
      @target = tgt
      @max_ttl = params[:max_ttl] || 32
      @retry = params[:retry] || 1
      @timeout = params[:timeout] || 3
    end

    def perform!
      route = []
      (1 .. @max_ttl).each do |ttl|
        ary = (1 .. @retry).map do |try| 
          LostPacket.new(@target, ttl, {:timeout => @timeout})
        end
        ret = @probecraft.perform(ary)
        route << ret
        break if should_stop?
      end
      route
    end

    def should_stop?
      #TODO: stop criterium
      false
    end
  end
end
