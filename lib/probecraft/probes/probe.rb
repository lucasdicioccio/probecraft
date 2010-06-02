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

require 'probecraft/protocols/ip'
require 'probecraft/protocols/icmp'
require 'probecraft/protocols/tcp'
require 'probecraft/protocols/udp'

module Probecraft
  class Probe

    attr_accessor :probecraft

    def run_on(probecraft)
      @probecraft ||= probecraft
      run
    end

    def run
      prepare if respond_to? :prepare
      ret = perform! #mandatory
      ret = report if respond_to? :report
      ret
    end

  end

  class ProbeCollection < Array

    def run_on(probecraft)
      @probecraft = probecraft
      run
    end

    def run(parrallel=false)
      parrallel ? run_parralel : run_iterating
    end

    def run_parrallel
      each{|probe| probe.prepare if probe.respond_to? :prepare}
      ret1 = collect{|probe| probe.perform!}
      ret2 = collect{|probe| probe.report if probe.respond_to? :report}
      #TODO: update ret2 that was not in ret1
    end

    def run_iterating
      collect{|probe| probe.run_on @probecraft}
    end

  end
end
