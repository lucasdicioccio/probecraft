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
  module IPLikeOption

    def self.included(mod)
      raise ArgumentError.new("#{self} can only be included in a Class") unless mod.is_a? Class
      #base fields for mother class of every "define_opt" one
      mod.fields [:kind, 'C'],
        [:length, 'C', ''],
        [:data, '?']

      mod.encode_order :kind, :data, :length

      class << mod
        attr_reader :kinds, :kinds_vals, :kind_val, :description

        def inherited(subklass)
          subklass.instance_variable_set(:@kinds, 
                                         self.instance_variable_get(:@kinds))
        end

        def define_opt(val, sym, desc='', *rest)
          base_fields = [:kind, 'C'], [:length, 'C', '']
          rest = [[:data, '?']] if rest.empty?
          all_fields = base_fields + rest
          order = all_fields.map{|i| i.first}
          order = (order - [:length]) + [:length]
          klass = Class.new(self) do |c|
            c.fields *all_fields
            c.encode_order *order
            c.instance_variable_set(:@description, desc)
            c.instance_variable_set(:@kind_val, val)
          end
          self.const_set(sym, klass)
          kinds[val] = klass
          kinds[sym] = klass
        end

        def new_for_trailer(trailer)
          klass = kinds[trailer[0]]
          if klass
            klass.new(trailer)
          else
            self.new(trailer)
          end
        end
      end
    end

    def kinds
      self.class.instance_variable_get :@kinds
    end

    def kind_name
      kinds[@kind]
    end


    def last_one?
      (kinds[:EOOL] == self.class) or 
      (kinds[@kind] == kinds[:EOOL])
    end

    def not_opt?
      (kinds[:NOP] == self.class) or
      (kinds[@kind] == kinds[:NOP])
    end

    def unit_opt?
      not_opt? or last_one?
    end

    def initialize(*args)
      @kind = self.class.kind_val
      super
    end

    def decode_length
      if unit_opt?
        @length = 1
        @trailing_data
      else
        decode_rawfield :length
      end
    end

    def encode_length
      # here we need to add 1 because for 
      #"unit_opt" (NOP, EOOL), we default returned chunk to ''
      unless @length
        @length = self.to_s.size
        if @length > 1
          @length += 1 
        else
          @length = nil
          return ''
        end
      end
      encode_rawfield(self.class.field_for_name(:length))
    end

    def decode_data
      if @length > 1
        packstr = 'H2'*(@length-2) + 'a*'
        decoded = @trailing_data.unpack(packstr)
        ret = decoded.pop
        @data = if decoded.size == 1
                  decoded.first
                else
                  decoded
                end

        ret
      else
        @data = ''
        @trailing_data
      end
    end

    def encode_data
      if @length and @length > 2
        packstr = 'H2'*(@length-2)
        encoded = @data.pack(packstr)
      else
        ''
      end
    end

    def inspect_kind
      str = "| kind: 0x%02x" % @kind
      kind_name = kinds[@kind]
      str << " (#{kind_name})" if kind_name
      str << "\n"
    end

    def inspect_length
      if @length and @length > 1
        "| length: #{@length}\n"
      else
        ''
      end
    end

    def inspect_data
      if @data
        if @length > 1
          "| data: #{@data.to_s}\n"
        else
          "| data: #{@data.unpack('H*')}\n"
        end
      else
        ''
      end
    end
  end
end
