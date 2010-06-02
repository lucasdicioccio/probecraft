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

require 'probecraft/protocols/tcp'
require 'probecraft/protocols/udp'
require 'probecraft/protocols/icmp'
require 'probecraft/protocols/ipoptions'
require 'probecraft/convenience'

module Probecraft
  class IP < Racket::Packet

    @@protos = { 6 => TCP,
      17 => UDP,
      1 => ICMP,
      0 => 'HOPOPT', 2 => 'IGMP', 3 => 'GGP', 4 => 'IP', 5 => 'ST',
      7 => 'CBT', 8 => 'EGP', 9 => 'IGP', 10 => 'BBN-RCC-MON', 11 => 'NVP-II',
      12 => 'PUP', 13 => 'ARGUS', 14 => 'EMCON', 15 => 'XNET', 16 => 'CHAOS',
      18 => 'MUX', 19 => 'DCN-MEAS', 20 => 'HMP', 21 => 'PRM',
      22 => 'XNS-IDP', 23 => 'TRUNK-1', 24 => 'TRUNK-2', 25 => 'LEAF-1',
      26 => 'LEAF-2', 27 => 'RDP', 28 => 'IRTP', 29 => 'ISO-TP4',
      30 => 'NETBLT', 31 => 'MFE-NSP', 32 => 'MERIT-INP', 33 => 'DCCP',
      34 => '3PC', 35 => 'IDPR', 36 => 'XTP', 37 => 'DDP', 38 => 'IDPR-CMTP',
      39 => 'TP++', 40 => 'IL', 41 => 'IPv6', 42 => 'SDRP',
      43 => 'IPv6-Route', 44 => 'IPv6-Frag', 45 => 'IDRP', 46 => 'RSVP',
      47 => 'GRE', 48 => 'DSR', 49 => 'BNA', 50 => 'ESP', 51 => 'AH',
      52 => 'include-NLSP', 53 => 'SWIPE', 54 => 'NARP', 55 => 'MOBILE',
      56 => 'TLSP', 57 => 'SKIP', 58 => 'IPv6-ICMP', 59 => 'IPv6-NoNxt',
      60 => 'IPv6-Opts', 62 => 'CFTP', 64 => 'SAT-EXPAK', 65 => 'KRYPTOLAN',
      66 => 'RVD', 67 => 'IPPC', 69 => 'SAT-MON', 70 => 'VISA', 71 => 'IPCV',
      72 => 'CPNX', 73 => 'CPHB', 74 => 'WSN', 75 => 'PVP',
      76 => 'BR-SAT-MON', 77 => 'SUN-ND', 78 => 'WB-MON', 79 => 'WB-EXPAK',
      80 => 'ISO-IP', 81 => 'VMTP', 82 => 'SECURE-VMTP', 83 => 'VINES',
      84 => 'TTP', 85 => 'NSFNET-IGP', 86 => 'DGP', 87 => 'TCF',
      88 => 'EIGRP', 89 => 'OSPFIGP', 90 => 'Sprite-RPC', 91 => 'LARP',
      92 => 'MTP', 93 => 'AX.25', 94 => 'IPIP', 95 => 'MICP', 96 => 'SCC-SP',
      97 => 'ETHERIP', 98 => 'ENCAP', 100 => 'GMTP', 101 => 'IFMP',
      102 => 'PNNI', 103 => 'PIM', 104 => 'ARIS', 105 => 'SCPS', 106 => 'QNX',
      107 => 'A/N', 108 => 'IPComp', 109 => 'SNP', 110 => 'Compaq-Peer',
      111 => 'IPX-in-IP', 112 => 'VRRP', 113 => 'PGM', 115 => 'L2TP',
      116 => 'DDX', 117 => 'IATP', 118 => 'STP', 119 => 'SRP', 120 => 'UTI',
      121 => 'SMP', 122 => 'SM', 123 => 'PTP', 124 => 'ISIS over IPv4',
      125 => 'FIRE', 126 => 'CRTP', 127 => 'CRUDP', 128 => 'SSCOPMCE',
      129 => 'IPLT', 130 => 'SPS', 131 => 'PIPE', 132 => 'SCTP',
      133 => 'FC', 134 => 'RSVP-E2E-IGNORE', 135 => 'Mobility Header',
      136 => 'UDPLite', 137 => 'MPLS-in-IP', 138 => 'manet', 139 => 'HIP',
      140 => 'Shim6', 255 => 'Reserved '
    }

    BASE_HEADER_LENGTH = 20

    fields  [:version_headlen, 'c'],
      [:services, 'H2'],
      [:total_length, 'n', "\x00\x00"],
      [:ipid, 'n', "\x00\x00\x00\x00"],
      [:flags_offset, 'n'],
      [:ttl, 'C'],
      [:proto, 'C', "\x00"],
      [:chksum, 'H4', "\x00\x00"],
      [:src, 'C4'],
      [:dst, 'C4'],
      [:options, '?'], #stuffing
      [:stuffing, '?'],
      [:payload, '?']

    encode_order :services, :ipid, :flags_offset, :ttl, :proto, :src, :dst,
      :options, :stuffing, :version_headlen,
      :payload, :total_length, :chksum

    attr_accessor :version, :header_length, :flags, :offset, :auto_stuff

    def self.const_missing(konst)
      @@protos.invert[Kernel.const_get(konst.to_s.sub(/^PROTO_/,''))] if konst.to_s =~ /^PROTO_/
    end

    def initialize(*args, &blk)
      @auto_stuff = true
      @version = 4
      @services = '00'
      @flags = {}
      @offset = 0
      @ttl = 64
      @header_length = BASE_HEADER_LENGTH
      @options = []
      @stuffing = ''
      super
    end

    def decode_options
      @options = []
      ret = @trailing_data
      options_len = header_length - BASE_HEADER_LENGTH
      while (options_len > 0) do
        opt = IPOption.new_for_trailer(@trailing_data)
        @options << opt
        @trailing_data = opt.decode!
        options_len -= opt.length
        if opt.last_one? #there is stuffing
          @stuffing = @trailing_data.slice!(0, options_len)
          break
        end
      end
      @trailing_data 
    end

    def decode_stuffing
      #was done when decoding
      @trailing_data
    end

    def encode_options
      @options.each{|o| o.encode!}
      ret = @options.inject(''){|str, o| str + o.to_s}
      @header_length += ret.size
      ret
    end

    def encode_stuffing
      if auto_stuff
        #@header_length is computed when encode_options is performed 
        stufflen = @header_length % 4
        @header_length += stufflen
        @stuffing += ("\x00" * stufflen)
      else
        @stuffing
      end
    end

    def decode_version_headlen
      ret = decode_rawfield(self.class.field_for_name(:version_headlen))
      @version = (@version_headlen & 0xf0) >> 4
      @header_length = (@version_headlen & 0x0f) << 2
      ret
    end

    def encode_version_headlen
      #@header_length is computed when encode_options is performed 
      # and increased when stuffing is added
      #TODO: warn if header_length > 60
      @version_headlen = ((@header_length >> 2) & 0x0f) | ((@version << 4) & 0xf0)
      encode_rawfield( self.class.field_for_name(:version_headlen) )
    end

    def decode_flags_offset
      ret = decode_rawfield(self.class.field_for_name(:flags_offset))
      @offset = @flags_offset & 0x1fff
      @flags = {}
      @flags[:MF] = true if Convenience.flag_set_at?(@flags_offset, 13)
      @flags[:DF] = true if Convenience.flag_set_at?(@flags_offset, 14)
      @flags[:reserved] = true if Convenience.flag_set_at?(@flags_offset, 15)
      ret
    end

    def encode_flags_offset
      if @flags_offset.nil?
        flgs = 0
        flgs |= (1<<13) if @flags[:MF]
        flgs |= (1<<14) if @flags[:DF]
        flgs |= (1<<15) if @flags[:reserved]
        @flags_offset = @offset | flgs
      end
      encode_rawfield( self.class.field_for_name(:flags_offset) )
    end

    def inspect_flags_offset
      str = "| fragment_offset: #{@offset}\n"
      str << "| flags: #{@flags.inspect}\n"
    end

    def dont_fragment!
      @flags[:DF] = true
    end

    def more_fragments!
      @flags[:MF] = true
    end

    def fragmented?
      @flags[:DF] && true
    end

    def more_fragments?
      @flags[:MF] && true
    end

    def encode_total_length
      @total_length = self.to_s.size if @total_length.nil?
      encode_rawfield( self.class.field_for_name(:total_length) )
    end

    def decode_payload
      if @@protos[@proto].is_a? Class #else its a string/sym for inspect
        decode_known_proto
      else
        @payload = @trailing_data.unpack('H*')
        ''
      end
    end

    def decode_known_proto
      begin
        #some upper layers might want this layer (e.g. for TCP pseudo header)
        @payload = @@protos[@proto].new(self, @trailing_data)
      rescue ArgumentError
        @payload = @@protos[@proto].new(@trailing_data)
      end
      @payload.decode!
    end

    def encode_payload
      @payload.encode! if @payload.respond_to? :encode!
      @payload.to_s
    end

    def payload=(val)
      if val.is_a? Racket::Packet and @proto.nil?
        @proto = @@protos.keys.find{|k| @@protos[k] == val.class}
      end
      @payload = val
    end

    def encode_chksum
      str = self.to_s
      sum = Convenience.compute_checksum(str, header_length)
      self.chksum = '%04x' % sum
      [self.chksum].pack('H4')
    end

    def inspect_version_headlen
      str = '| version: ' + self.version.to_s + "\n"
      str << '| header_length: ' + (self.header_length).to_s + " bytes \n"
    end

    def inspect_proto
      str = "| proto: 0x%02x" % @proto
      proto_name = @@protos[@proto]
      str << " (#{proto_name})" if proto_name
      str << "\n"
    end

    def inspect_stuffing
      str = '|   stuffing: '
      str << if @stuffing.empty?
               '(none)' 
      else
        @stuffing.unpack('H*').to_s
      end
      str << "\n"
      str
    end

    def inspect_options
      if options.empty?
        "| options: none\n"
      else
        "|   options:\n" + options.inject(''){|str,o| str + o.inspect}.gsub(/^/,"|   ")
      end
    end


    # helpers and clean printing for ipaddr

    [:src, :dst].each do |addr|

      define_method("inspect_#{addr}") do 
        str = self.class.unparse_ip(send(addr))
        "| #{addr}: #{str}\n"
      end

      define_method("#{addr}=") do |obj|
        ary = if obj.is_a? String
                self.class.parse_ip obj
              else
                obj
              end
        instance_variable_set("@#{addr}", ary)
      end

    end

    def self.parse_ip(str)
      str.split('.').map{|s| s.to_i}
    end

    def self.unparse_ip(ary)
      str = ''
      if ary
        str << ary.join('.')
      else
        'unset'
      end
      str
    end

  end
end

