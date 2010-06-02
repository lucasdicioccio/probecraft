module Probecraft
  class Host
    @@all

    def self.all
      @@all
    end

    attr_accessor :routes, :distances

    def initialize
      @routes = []
      @distances = {}
      @all << self
    end
  end

  class KnownHost < Host
    attr_accessor :addr, :capabilities
    def initialize(addr)
      super()
      @capabilities = {}
      @addr = addr
    end

    def self.for_addr(addr)
      i = @@all.find{|h| h.is_a? KnownHost and h.addr == addr}
      i || self.new(addr)
    end
  end

  class UnknownHost < Host
  end
end

