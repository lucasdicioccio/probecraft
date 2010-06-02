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

module  Probecraft
  class Matcher

    class LayerCondition
      attr_reader :layers, :lambda
      def initialize(*args, &blk)
        @layers = args
        @lambda = blk
      end

      def true_for?(pkt)
        pkt_layers = Enumerator.new(pkt, :each_layer).map{|i| i}
        uncapsulated = pkt_layers[0, @layers.size]
        layer_klasses = uncapsulated.map{|i| i.class}

        return false unless (@layers == layer_klasses)
        if @lambda
          return false unless @lambda.call(uncapsulated.last)
        end
        true
      end
    end

    attr_accessor :conditions

    def initialize
      @conditions = []
      yield self if block_given?
    end

    def layers(*args, &blk)
      @conditions << LayerCondition.new(*args, &blk)
    end

    def match?(pkt)
      not @conditions.find{|i| not i.true_for?(pkt)}
    end

  end

  #XXX monkey patch!!!
  require 'racket'
  class Racket::Packet
    # iterates on pkt from this one and into upper layers,
    # an upper layer is a field named :payload
    def each_layer
      yield self
      self.payload.each_layer{|l| yield l}  if self.respond_to? :payload and self.payload.is_a? Racket::Packet
    end
  end
end


