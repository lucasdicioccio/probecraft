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
  class TCPOption < Racket::Packet

    include IPLikeOption

    @kinds = {} # will be shared with subclasses

    # RFC-793 options
    define_opt(0, :EOOL, 'end of option list')
    define_opt(1, :NOP, 'no operation')
    define_opt(2, :MSS, 'maximum segment size',
               [:val, 'n'])

    # RFC-1323
    define_opt(3, :WSOPT, 'window scale option',
               [:shift_cnt, 'c'])
    define_opt(8, :TSOPT, 'timestamps option',
               [:sender_ts, 'N'],
               [:rcver_ts, 'N'])

    # RFC-2018
    define_opt(4, :SACKPermitted, 'allow selective ACK')
    define_opt(5, :SACK, 'selective ACK',
               [:blocks, '?'])
    class SACK
      def initialize(*args, &blk)
        @blocks = []
        super
      end

      def decode_blocks
        len = @length - 2
        while (len > 0) do
          len -= 8
          decoded = @trailing_data.unpack('NNa*')
          @trailing_data = decoded.pop
          @blocks << decoded
        end
        @trailing_data
      end

      def encode_blocks
        @blocks.inject(''){|str, b| str + b.pack('NN')}
      end
    end

    # RFC-1072
    define_opt(6, :EchoRequest, 'echo request (obsolete)',
               [:data, 'N'])
    define_opt(7, :EchoReply, 'echo reply (obsolete)',
               [:data, 'N'])

    #TODO: other RFCs
  end
end
