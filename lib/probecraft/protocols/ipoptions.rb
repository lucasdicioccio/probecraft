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
require 'probecraft/protocols/iplikeoptions'

module Probecraft
  class IPOption < Racket::Packet

    include IPLikeOption

    @kinds = {} # will be shared with subclasses

    def copied?
      Convenience.flag_set_at?(@kind, 7)
    end

    def opt_class
      vals = [:control, :reserved1, :debug, :reserved2]
      vals[((@kind & 0x60) >> 4)]
    end

    def opt_num
      @kind & 0x1f
    end

    define_opt(0, :EOOL, 'end of option list')
    define_opt(1, :NOP, 'no operation')
    define_opt(130, :SEC, 'security',
               [:lvl, 'n'],
               [:compartment, 'n'],
               [:restrictions, 'n'],
               [:control_code, 'n'])

    define_opt(68, :TS, 'timestamp',
               [:ptr, 'c'],
               [:oflw_flags, 'c'],
               [:addr_tst, '?'])

    class TS
      attr_accessor :tsonly, :tsandaddr, :tsprespec, :oflw_flags, :ptr
      attr_reader :timestamps

      def initialize(*params, &blk)
        @timestamps = []
        @tsonly     = false
        @tsandaddr  = false
        @tsprespec  = false
        @ptr        = 5
        @oflw_flags  = 0
        super
      end

      def oflw
        @oflw || ((@oflw_flags & 0xf0) >> 4)
      end

      def flags
        @flags || (@oflw_flags & 0x0f)
      end

      def tsonly?
        flags == 0x00
      end

      def tsandaddr?
        flags == 0x01
      end

      def tsprespec?
        flags == 0x03
      end

      def inspect_oflw_flags
        str =  "| overflow: #{oflw}\n"
        str << "| flags: "
        str << [:tsonly, :tsandaddr, :tsprespec].map{|s| send("#{s}?") ? "(#{s})": ''}.join(' ')
        str << " (#{flags})\n"
      end

      def decode_addr_tst
        if tsonly?
          decode_tsonly
        else tsandaddr?
          decode_tsandaddr
        end
      end

      def encode_addr_tst
        if tsonly?
          encode_tsonly
        else tsandaddr?
          encode_tsandaddr
        end
      end

      def inspect_addr_tst
        if tsonly?
          inspect_tsonly
        else
          #specified hops has same syntax
          inspect_tsandaddr
        end
      end

      def decode_tsonly
        ret = @trailing_data
        len = @length - 4
        while (len > 0) do
          len -= 4
          decoded = @trailing_data.unpack('Na*')
          @trailing_data = decoded.pop
          @timestamps << decoded.first
        end
        @trailing_data
      end

      def decode_tsandaddr
        ret = @trailing_data
        len = @length - 4
        while (len > 0) do
          len -= 8
          decoded = @trailing_data.unpack('C4Na*')
          @trailing_data = decoded.pop
          @timestamps << decoded
        end
        @trailing_data
      end

      def encode_tsonly
        @timestamps.pack('N'*@timestamps.size)
      end

      def encode_tsandaddr
        @timestamps.inject(''){|str, tst| str + tst.pack('C4N')}
      end

      def inspect_tsonly
        str = "| timestamps:\n"
        str << @timestamps.map{|t| "| > #{t}"}.join("\n")
        str << "\n"
      end

      def inspect_tsandaddr
        str = "| timestamps:\n"
        str << @timestamps.map{|t| "| > #{IP.unparse_ip(t[0, 4])}: #{t.last}"}.join("\n")
        str << "\n"
      end
    end

    define_opt(131, :LSR, 'loose source routing',
               [:ptr, 'c'],
               [:route, '?'])

    module RRorLSR
      def initialize(*args, &blk)
        @route = []
        @ptr = 4
        super
      end

      def decode_route
        ret = @trailing_data
        len = @length - 3
        while (len > 0) do 
          len -= 4
          decoded = @trailing_data.unpack('C4')
          @trailing_data = decoded.pop
          @route << decoded
        end
        @trailing_data
      end

      def encode_route
        @route.inject(''){|str, r| str + r.pack('C4')}
      end

      def inspect_route
        str = "| route:\n"
        str << @route.map{|r| "| > #{IP.unparse_ip(r)}"}.join("\n")
        str << "\n"
      end
    end

    class LSR
      include RRorLSR
    end

    define_opt(7, :RR, 'record route',
               [:ptr, 'c'],
               [:route, '?'])

    class RR
      include RRorLSR
      def encode_route
        if @route.empty?
          "\x00"
        else
          @route.inject(''){|str, r| str + r.pack('C4')}
        end
      end
    end

    #TODO: non RFC-791 options
  end
end

