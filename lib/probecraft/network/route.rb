module Probecraft
  class Route
    attr_accessor :hops, :target

    def initialize(tgt)
      @hops = []
      @target = tgt
    end

    def complete?
      hops.last == target
    end
  end
end
