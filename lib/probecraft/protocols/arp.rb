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

module  Probecraft
  class ARP < Racket::Packet
    fields ['hw_type', 'H4'],  #TODO
      ['proto_type', 'H4'], #TODO
      ['hw_size', 'c'],
      ['proto_size', 'c'],
      ['opcode', 'H4'], #TODO
      ['src_hw', '?'],
      ['src_proto', '?'],
      ['tgt_hw', '?'],
      ['tgt_proto', '?']

    #hacky way of doing all the src/tgt/hw/proto dynamic methods
    [:src, :tgt].each do |d|
      [:hw, :proto].each do |k|
        [:encode, :decode].each do |m|
          meth_name = "#{m}_#{d}_#{k}"
          code_meth = "#{m}_var_len"
          size_meth = "#{k}_size"
          fieldname = "#{d}_#{k}".to_sym
          define_method(meth_name) do
            size = send(size_meth)
            send(code_meth, fieldname, size)
          end
        end
      end
    end

    private

    def encode_var_len(name, size)
      packstr = 'H*'
      val = send name.to_sym
      [val].pack(packstr)
    end

    def decode_var_len(name, size)
      packstr = 'H2'*size + 'a*'
      decoded = @trailing_data.unpack('H2'*size + 'a*')
      ret = decoded.pop
      meth = name.to_s + "="
      send meth, decoded
      ret
    end

  end
end
