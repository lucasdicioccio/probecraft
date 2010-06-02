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

require 'racket'
require 'probecraft/protocols/ip'
require 'probecraft/protocols/arp'

module  Probecraft
  class Ethernet < Racket::Packet

    ADDR_BCAST = 'ffffffffffff'
    ADDR_ANY   = '000000000000'

    @@protos = { 0x800 => IP,
      0x806 => ARP}

    fields  [:dst, 'H12'],
      [:src, 'H12'],
      [:proto, 'n'],
      [:payload, '?']

    def decode_payload
      if @@protos[@proto]
        decode_known_proto
      else
        @payload = nil
        @trailing_data
      end
    end

    def decode_known_proto
      @payload = @@protos[@proto].new(@trailing_data)
      @payload.decode!
    end

    def encode_payload
      @payload.encode! if @payload.respond_to? :encode!
      @payload.to_s
    end

    def payload=(val)
      if val.is_a? Racket::Packet and @proto.nil?
        @proto = @@protos.keys.find{|k| @@protos[k] == val.class}
      end
      @payload = val
    end

    #some helpers

    def self.const_missing(konst)
      @@protos.invert[Kernel.const_get(konst.to_s.sub(/^PROTO_/,''))] if konst.to_s =~ /^PROTO_/
    end

    def src=(val)
      @src = self.class.parse_addr(val)
    end

    def dst=(val)
      @dst = self.class.parse_addr(val)
    end


    def self.parse_addr(str)
      str.tr(':','')
    end

    def self.unparse_addr(str)
      desc = case str
             when ADDR_BCAST
               ' (broadcast)'
             when ADDR_ANY
               ' (any)'
             else
               ''
             end

      ret = str.scan(/\w{2}/).join(':') + desc
      ret
    end

    #clean print

    def inspect_src
      '| src: ' + self.class.unparse_addr(@src) + "\n"
    end

    def inspect_dst
      '| dst: ' + self.class.unparse_addr(@dst) + "\n"
    end

    def inspect_proto
      str = "| proto: 0x%04x" % @proto
      proto_name = @@protos[@proto]
      str << " (#{proto_name})" if proto_name
      str << "\n"
    end

  end
end
