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

require 'timeout'
require 'capby'
require 'racket'
require 'socket'

require 'probecraft/protocols/ethernet'

module Probecraft
  class Probecraft

    attr_reader :sent, :received,
      :device,
      :capture, :injector, :link_layer

    attr_accessor :iface_peer_hw_addr, :iface_hw_addr

    @@link_layers = { :en10mb => Ethernet ,
      :ieee802_11 => nil  } #TODO

    def initialize(devname)
      @iface_peer_hw_addr = 'ff:ff:ff:ff:ff:ff'
      @iface_hw_addr      = nil
      if File.file?(devname)
        @capture = Capby::FileCapture.new devname
      else

        @device = Capby::Device.all.find{|d| d.name == devname}
        raise ArgumentError.new("no such device #{devname}") unless @device
        @capture = Capby::LiveCapture.new @device
        @injector = Capby::LiveCapture.new @device
        @injector.bufsize = 0 #not used to sniff
        @injector.snaplen = 0 #not used to sniff
      end
      @link_layer = @@link_layers[@capture.datalink]
      raise RuntimeError.new("Don't know how to decapsulate #{@capture.datalink} link layer") unless @link_layer
    end

    def iface_addr
      addr = nil
      @device.addresses.each do |h|
        begin
          addr = Socket.unpack_sockaddr_in h[:addr]
          break
        rescue ArgumentError
          nil
        end
      end
      addr.last || '0.0.0.0'
    end

    def iface_hw_addr
      dflt = '00:00:00:00:00:00'
      addr = if @device.respond_to? :link_address
               @device.link_address || dflt
             else
               dflt
             end
      @iface_hw_addr || addr
    end

    def link_layer_pkt
      pkt = __send__ "#{link_layer.name.downcase.split('::').last}_ll"
      yield pkt if block_given?
      pkt
    end

    private

    def ethernet_ll
      Ethernet.new do |eth|
        eth.src = iface_hw_addr
        eth.dst = iface_peer_hw_addr
      end
    end

    public

    # sniff for up to cnt packets in less than timeout seconds
    # a 0 value means `infinite quantity' for timeout and cnt
    # the TimeoutError is not handled in this method, thus take care of it by yourself
    # if no block given, returns an array of the sniffed packets, else, nil is returned
    # we do so to avoid infinite loops to need unbounded amount of memory
    def sniff(cnt = 0, timeout=0, params={})
      ret = nil
      Timeout.timeout(timeout) do 
        if block_given?
          sniff_and_yield(cnt, params) do |pkt|
            yield pkt
          end
        else
          unless cnt > 0
            raise ArgumentError, "must provide a block if no pkt limit" 
          end
          ret = sniff_only(cnt)
        end
      end
      ret
    end

    def sniff_and_yield(cnt, params)
      @capture.each(cnt) do |raw_pkt|
        break unless raw_pkt
        if params[:dont_decode]
          yield raw_pkt
        else
          pkt = @link_layer.new(raw_pkt.data)
          pkt.pkt_timestamp = raw_pkt.timestamp
          pkt.decode!
          yield pkt
        end
      end
    end

    def sniff_only(cnt, params)
      raws = []
      @capture.each(cnt) do |raw_pkt|
        break unless raw_pkt
        raws << raw_pkt
      end
      if params[:dont_decode]
        raws
      else
        raws.map do |raw_pkt| 
          pkt = @link_layer.new(raw_pkt.data)
          pkt.pkt_timestamp = raw_pkt.timestamp
          pkt.decode!
          pkt
        end
      end
    end

    # timeout is per sniffed pkt (i.e. total timeout = cnt*timeout)
    def match(cnt=1, timeout=0, &blk)
      got = []
      begin
        sniff(0, timeout) do |pkt| #TODO: timeout is not correct here
          got << pkt if yield(pkt)
          break if got.size >= cnt
        end
      rescue TimeoutError
      end
      got
    end

    # sniff for up to cnt packet(s) matching at least one Matcher in matchers
    # each expected packet is waited timeout seconds
    # returns a hash of Matcher in argument => Array of packets
    # if duplicate is true, then a packet matched twice is referenced twice in the returned hash's values
    def dispatch(cnt=1, timeout=0, matchers=[], duplicate=false)
      h = {}
      matchers.each{|m| h[m] = []}
      match(cnt, timeout) do |pkt|
        if duplicate
          ary = matchers.select {|m| m.match?(pkt)}
          ary.each{|f| h[f] << pkt}
        else
          f = matchers.find {|m| m.match?(pkt)}
          h[f] << pkt if f
        end
      end
      h
    end

    # sniff packets for timeout seconds
    def multimatch(cnt=1, timeout=0, matchers=[], duplicate=false)
      ret = {:status => :ok}
      matchers.each{|m| ret[m] = []}
      matched = 0
      begin
        lbd = if duplicate
                proc do |pkt| 
                  ary = matchers.select {|m| m.match?(pkt)}
                  ary.each{|f| ret[f] << pkt}
                  matched += 1 if ary.any?
                  throw :done if matched == cnt
                end
              else
                proc do |pkt|
                  f = matchers.find {|m| m.match?(pkt)}
                  if f
                    ret[f] << pkt 
                    matched += 1
                    throw :done if matched == cnt
                  end
                end
              end
        catch :done do
          sniff(0, timeout, &lbd)
        end
      rescue TimeoutError
        ret[:status] = :timeout
      end
      ret
    end

    # sends a set of packets in a raw, these packets can be either raw strings, either Capby::Packet,
    # Racket's Packet is not supported (thus we *force* you to encode/transform it to string before)
    # indeed, it's faster if no string processing has to be done
    def send(ary=[])
      ary = [ary].flatten #can send one or many packets
      capby_pkts = ary.map do |pkt|
        case pkt
        when Capby::Packet
          pkt
        else
          Capby::Packet.new(pkt.to_s) 
        end
      end
      @injector.send_packets!(capby_pkts)
    end

    def perform(measurements=[])
      ProbeCollection.new([measurements].flatten).run_on self
    end
  end
  PC = Probecraft
end

