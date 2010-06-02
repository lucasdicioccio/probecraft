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
require 'probecraft/protocols/tcpoptions'
require 'probecraft/convenience'

module Probecraft
  class TCPPseudoHeader < Racket::Packet
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

  class TCP < Racket::Packet

    fields [:srcport, 'n'],
      [:dstport, 'n'],
      [:seq, 'N'],
      [:ack, 'N'],
      [:headlen,'C'],
      [:flagval, 'C'],
      [:window, 'n', "\xa0\x00"],
      [:chksum, 'H4', "\x00\x00"],
      [:urgent, 'n', "\x00\x00"],
      [:options, '?'],
      [:stuffing, '?'],
      [:payload, 'a*']

    BASE_HEADER_LENGTH = 20

    encode_order :srcport, :dstport, :seq, :ack, :flagval, :window,
      :payload,
      :options, :stuffing, :headlen, :urgent,
      :chksum

    attr_reader :ip_layer, :flags

    def initialize(ip=nil, str='')
      @ip_layer = ip
      @options = []
      @flags = {}
      @stuffing = ''
      super(str)
    end

    def inspect_headlen
      '| header_length: ' + self.header_length.to_s + " bytes \n"
    end

    def header_length
      ((headlen & 0xf0) >> 2)
    end

    def decode_options
      @options = []
      ret = @trailing_data
      options_len = header_length - BASE_HEADER_LENGTH
      while (options_len > 0) do
        opt = TCPOption.new_for_trailer(@trailing_data)
        @trailing_data = opt.decode!
        @options << opt
        options_len -= opt.length
        #TODO: stuffing
        if opt.last_one? #there is stuffing
          @stuffing = @trailing_data.slice!(0, options_len)
          break
        end
      end
      @trailing_data 
    end

    def decode_stuffing
      #was done when decoding
      @trailing_data
    end

    def encode_stuffing
      #TODO: auto_stuff
      @stuffing
    end

    def inspect_stuffing
      str = '|   stuffing: '
      str << if @stuffing.empty?
               '(none)' 
      else
        @stuffing.unpack('H*').to_s
      end
      str << "\n"
      str
    end

    def encode_options
      @options.each{|o| o.encode!}
      tot = @options.inject(''){|str, o| str + o.to_s}
      @headlen = ((20 + tot.size) << 2) & 0xf0
      tot
    end

    def inspect_options
      if options.empty?
        "| options: none\n"
      else
        "|   options:\n" + options.inject(''){|str,o| str + o.inspect}.gsub(/^/,"|   ")
      end
    end

    def decode_flagval
      ret = decode_rawfield(self.class.field_for_name(:flagval))
      @flags = {}
      @flags[:CWR]  = true if Convenience.flag_set_at?(@flagval, 7)
      @flags[:ECN]  = true if Convenience.flag_set_at?(@flagval, 6)
      @flags[:URG]  = true if Convenience.flag_set_at?(@flagval, 5)
      @flags[:ACK]  = true if Convenience.flag_set_at?(@flagval, 4)
      @flags[:PUSH] = true if Convenience.flag_set_at?(@flagval, 3)
      @flags[:RST]  = true if Convenience.flag_set_at?(@flagval, 2)
      @flags[:SYN]  = true if Convenience.flag_set_at?(@flagval, 1)
      @flags[:FIN]  = true if Convenience.flag_set_at?(@flagval, 0)
      ret
    end

    def encode_flagval
      if @flagval.nil?
        flgs = 0
        flgs |= (1<<7) if @flags[:CWR]
        flgs |= (1<<6) if @flags[:ECN]
        flgs |= (1<<5) if @flags[:URG]
        flgs |= (1<<4) if @flags[:ACK]
        flgs |= (1<<3) if @flags[:PUSH]
        flgs |= (1<<2) if @flags[:RST]
        flgs |= (1<<1) if @flags[:SYN]
        flgs |= (1<<0) if @flags[:FIN]
        @flagval = flgs
      end
      encode_rawfield( self.class.field_for_name(:flagval) )
    end

    def inspect_flagval
      "| flags: #{@flags.inspect}\n"
    end

    def pseudo_header
      head = TCPPseudoHeader.new(@ip_layer, self, '')
      head.encode!
      head
    end

    def encode_chksum
      str = pseudo_to_s
      sum = Convenience.compute_checksum str
      self.chksum = '%04x' % sum
      [self.chksum].pack('H4')
    end

    def inspect_payload
      "| payload: #{@payload.unpack('H*')}\n"
    end

    private

    def pseudo_to_s
      s1 = self.to_s
      s0 = self.pseudo_header.to_s
      str = s0 + s1
    end
  end
end
