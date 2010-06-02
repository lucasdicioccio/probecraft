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

module Probecraft
  class UDPPseudoHeader < Racket::Packet
    fields [:src, 'C4'],
      [:dst, 'C4'],
      [:empty, 'c'],
      [:proto, 'C'],
      [:total_length, 'n', "\x00\x00"]

    attr_reader :ip_layer, :tcp_actual

    def initialize(ip, tcp, *args)
      self.empty = [0x00]
      @ip_layer = ip
      @tcp_actual = tcp
      super(*args)
    end

    def src
      @ip_layer.src
    end

    def dst
      @ip_layer.dst
    end

    def total_length
      @tcp_actual.to_s.size
      #@ip_layer.total_length - @ip_layer.header_length
    end

    def proto
      @ip_layer.proto
    end

  end

  class UDP < Racket::Packet
    fields [:srcport, 'n'],
      [:dstport, 'n'],
      [:length, 'n', "\x00\x00"],
      [:chksum, 'H4', "\x00\x00"],
      [:payload, 'a*', "\x00\x00"]

    encode_order :srcport, :dstport,
      :payload, :length, :chksum

    attr_accessor :use_chksum
    attr_reader :ip_layer

    def initialize(ip=nil, str='')
      @ip_layer = ip
      @use_chksum = false
      super(str)
    end

    def encode_length
      @length = self.to_s.size if @length.nil?
      encode_rawfield( self.class.field_for_name(:length) )
    end

    def pseudo_header
      head = UDPPseudoHeader.new(@ip_layer, self, '')
      head.encode!
      head
    end

    def encode_chksum
      if use_chksum
        str = pseudo_to_s
        sum = Convenience.compute_checksum str
        self.chksum = if sum == 0
                        'ffff'
                      else
                        '%04x' % sum
                      end
        [self.chksum].pack('H4')
      else
        "\x00\x00"
      end
    end

    private

    def pseudo_to_s
      s1 = self.to_s
      s0 = self.pseudo_header.to_s
      str = s0 + s1
    end

  end
end
