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
        @injector.bufsize = 3000 #not used to sniff
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
    def sniff(cnt = 0, timeout=0)
      a = nil
      a = [] unless block_given?
      Timeout.timeout(timeout) do 
        @capture.each(cnt) do |pkt|
          break unless pkt
          ll = @link_layer.new(pkt.data)
          ll.pkt_timestamp = pkt.timestamp
          if block_given?
            ll.decode!
            yield ll
          else
            a << ll
          end
        end
      end
      a.each{|ll| ll.decode!} if a
      a
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

    # sends a set of packets in a raw, these packets can be either raw strings, either Capby::Packet,
    # Racket's Packet is not supported (thus we *force* you to encode/transform it to string before)
    # indeed, it's faster if no string processing has to be done
    # TODO: allow accurate timeinterval in sending
    def send(raws=[])
      raws = [raws].flatten #can send one or many packets
      pkts = raws.map { |pkt| Capby::Packet.new(pkt.to_s) unless pkt.is_a? Capby::Packet }
      @injector.send_packets! pkts
    end

    def perform(measurements=[])
      ProbeCollection.new([measurements].flatten).run_on self
    end
  end
  PC = Probecraft
end

