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
module Probecraft
  class ICMP < Racket::Packet

    fields [:kind, 'C', "\x08"],
      [:code, 'C', "\x00"],
      [:chksum, 'H4', "\x00\x00"],
      [:optional, 'N', "\x00\x00\x00\x00"],
      [:data, 'a*']

    encode_order :kind, :code, :optional,
      :data, :chksum


    @@kinds = {}
    @@kinds_codes = {}

    def self.add_to_have_list(opt, name)
      var = "@@have_#{opt}"
      class_variable_set(var, []) unless class_variable_defined? var
      ary = class_variable_get(var)
      ary << name
    end

    def can_have?(field)
      self.class.send(:class_variable_get, "@@have_#{field}".to_sym).include? kind_name
    end

    def self.attr_optional(*attrs)
      attrs.each do |sym|
        define_method(sym) do
          instance_variable_get("@#{sym}".to_sym) if can_have? sym
        end
        define_method("#{sym}=") do |val|
          instance_variable_set("@#{sym}".to_sym, val) if can_have? sym
        end
      end
    end

    def self.define_msg(kind, name, codes={}, *opts)
      @@kinds[kind] = name
      @@kinds_codes[kind] = codes
      opts.each do |opt|
        attr_optional opt
        add_to_have_list opt, name
      end
    end

    define_msg(0, :echo_reply, {}, :seqnum, :identifier)
    define_msg(3, :destination_unreachable, {0 => :net, 1 => :host,
               2 => :proto, 3 => :port, 4 => :frag_and_DF_set, 
               5 => :source_route_failed}, 
               :req_start)
    define_msg(4, :source_quench, :req_start)
    define_msg(5, :redirect, {0 => :for_net, 1 => :for_host, 
               2 => :for_tos_and_net, 3 => :for_tos_and_host}, 
               :gw_ip, :req_start)
    define_msg(8, :echo_request, {}, :seqnum, :identifier)
    define_msg(11, :time_exceeded, {0 => :in_ttl, 1 => :in_reassembly}, 
               :req_start)
    define_msg(12, :parameter_problem, {}, :ptr, :req_start)
    define_msg(13, :timestamp_request, {}, :seqnum, :identifier, :ot, :rt, :tt)
    define_msg(14, :timestamp_reply, {}, :seqnum, :identifier, :ot, :rt, :tt)
    define_msg(15, :information_request, {}, :seqnum, :identifier)
    define_msg(16, :information_reply, {}, :seqnum, :identifier)

=begin
**complete list
                6  =>  :alternate_host_address,
                9  =>  :router_advertisement,
                10 =>  :router_solicitation,
                17 =>  :address_mask_request,
                18 =>  :address_mask_reply,
                30 =>  :traceroute,
                31 =>  :conversion_error,
                32 =>  :mobile_host_redirect,
                33 =>  :ipv6_where_are_you,
                34 =>  :ipv6_include_am_here,
                35 =>  :mobile_registration_request,
                36 =>  :mobile_registration_reply,
                37 =>  :domain_name_request,
                38 =>  :domain_name_reply,
                39 =>  :skip_algorithm_discovery_protocol,
                40 =>  :photuris_security_failures,
                41 =>  :experimental_mobility_protocols
=end

    def initialize(str='')
      @optional = 0
      @code = 0
      @identifier = 0
      @seqnum = 0
      @tt = 0
      @rt = 0
      @ot = 0
      @gw_ip = [0,0,0,0]
      @ptr = 0
      @rest = ''
      super
    end

    def kind=(val)
      if val.is_a? Symbol
        raise ArgumentError.new("#{val} not understood icmp type") unless @@kinds.values.include? val
        @kind = @@kinds.invert[val]
      else
        @kind = val
      end

    end

    def kind_name
      @@kinds[@kind]
    end

    def code=(val)
      h = @@kinds_codes[@kind]
      if val.is_a? Symbol
        raise ArgumentError.new("#{val} not understood code") unless h and h.values.include? val
        @code = h.invert[val]
      else
        @code = val
      end
    end

    def code_name
      h = @@kinds_codes[@kind]
      h[@code] if h
    end

    def before_encoding
      if @optional == 0
        if can_have? :identifier
          @optional |= ((self.identifier << 16) & 0xffff0000)
        end

        if can_have? :seqnum
          @optional |= (self.seqnum & 0x0000ffff)
        end

        if can_have? :gw_ip
          @optional = (self.gw_ip.pack('C4')).unpack('N')
        end

        if can_have? :ptr
          @optional = ((self.ptr & 0xfc) << 18)
        end

      end

      if @data.nil?
        if can_have? :req_start
          @data = self.req_start
        end
      end

      @data ||= ''

      unless [:ot, :rt, :tt].find{|i| not can_have?(i)}
        @data = [@ot, @rt, @tt].pack('NNN')
      end
    end

    def after_decoding
      if can_have? :identifier
        self.identifier = (@optional & 0xffff0000) >> 16
      end

      if can_have? :seqnum
        self.seqnum = (@optional & 0x0000ffff)
      end

      if can_have? :gw_ip
        self.gw_ip = [@optional].pack('N').unpack('C4')
      end

      if can_have? :ptr
        self.ptr = ((@optional >> 18) & 0xfc)
      end
    end

    def gw_ip=(obj)
      @gw_ip = if obj.is_a? String
                 IP.parse_ip obj
               else
                 obj
               end
    end

    def encode_chksum
      str = self.to_s
      sum = Convenience.compute_checksum(str)
      self.chksum = '%04x' % sum
      [self.chksum].pack('H4')
    end

    def decode_data

      if can_have? :req_start
        self.req_start = IP.new(@trailing_data)
        @data = self.req_start
        @trailing_data = self.req_start.decode!
      end

      unless [:ot, :rt, :tt].find{|i| not can_have?(i)}
        decoded = @trailing_data.unpack('NNNa*')
        @trailing_data = decoded.pop
        self.ot = decoded[0]
        self.rt = decoded[1]
        self.tt = decoded[2]
      end

      @rest = decode_rawfield(self.class.field_for_name(:data)) unless @data.is_a? Racket::Packet

      ''
    end

    def encode_data
      @data.encode! if @data.respond_to? :encode!
      @data.to_s 
    end

    # Kind of translator for chaining

    def [](name)
      self if kind_name == name
    end

    # Cleanly print everything

    def inspect_kind
      str = "| kind: 0x%02x " % @kind
      str << "(#{kind_name})" if kind_name
      str << "\n"
    end

    def inspect_code
      str = "| code: 0x%02x " % @code
      str << "(#{code_name})" if code_name
      str << "\n"
    end

    def inspect_optional
      str = "| optional: 0x%08x\n" % @optional
      str << "|   > identifier: 0x%04x\n" % @identifier if can_have? :identifier
      str << "|   > seqnum: 0x%04x\n" % @seqnum if can_have? :seqnum
      str << "|   > ptr: #{@ptr}\n" if can_have? :ptr
      str << "|   > gw_ip: #{IP.unparse_ip(@gw_ip)}\n" if can_have? :gw_ip
      str
    end

    def inspect_data
      str = "| data:\n"
      unless [:ot, :rt, :tt].find{|i| not can_have?(i)}
        str << [:ot, :rt, :tt].collect{|t| "|  > #{t}: #{send(t)}\n"}.join('')
      end

      if @data.is_a? Racket::Packet
        str << "|  > req_start: \n#{@data.inspect.gsub(/^/,"|    ")}"
      else
        str << "|  > rest: #{@rest.inspect}\n" unless @rest.empty?
      end
      str
    end
  end
end
