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

module Probecraft
  module Convenience
    def self.compute_checksum(data, len=nil)
      str = data
      str = str.slice(0, len) if len
      str << "\x00" if str.size.odd?

      u16s ||= str.unpack('n*')
      total = u16s.inject(0) {|sum, i| sum+i}
      while (total >> 16 != 0)
        total = (total >> 16) + (total & 0xffff)
      end
      total += total >> 16
      total = (~total) & 0xffff
    end

    def self.flag_set_at?(val, idx)
      mask = (1<<idx)
      (val & mask) == mask #0 is true in Ruby
    end

    def self.bit_masked_at(val, idx)
      mask = (1<<idx)
      val & mask
    end
  end
end

