# This example shows how to passively snoop for certain kinds of packets and select only the good ones.
#
begin
        require 'capby'
        require 'racket'
        require 'probecraft'
        require 'probecraft/matcher'
        require 'probecraft/protocols/ethernet'
        require 'probecraft/protocols/ip'
        require 'probecraft/protocols/icmp'
rescue LoadError
        require 'rubygems'
        require 'capby'
        require 'racket'
        require 'probecraft'
        require 'probecraft/matcher'
        require 'probecraft/protocols/ethernet'
        require 'probecraft/protocols/ip'
        require 'probecraft/protocols/icmp'
end

if Capby::Device.all.empty?
        puts "No interface found, maybe you should run that as root"
        exit
end

if ARGV.empty?
        puts "usage 'test.rb <ifacename>'"
        puts "\tavail. ifaces: #{Capby::Device.all.collect{|d| d.name}.join(" ")}"
        exit
end

devname = ARGV.first
b = Probecraft.new devname


def build_matcher_for_id(i=nil, j=nil)
        if i and j
                Matcher.new do |m|
                        m.layers(Ethernet, IP, ICMP) do |icmp|
                                (icmp[:echo_request] or icmp[:echo_reply]) and
                                (i == icmp.identifier) and (j == icmp.seqnum)
                        end
                end
        else
                Matcher.new do |m|
                        m.layers(Ethernet, IP, ICMP) do |icmp|
                                (icmp[:echo_request] or icmp[:echo_reply])
                        end
                end

        end
end


loop do
        pair = []
        matcher = build_matcher_for_id
        begin
                b.sniff(0, 10) do |pkt|
                        if matcher.match? pkt
                                pair << pkt 
                                icmp = pkt.payload.payload
                                matcher = build_matcher_for_id(icmp.identifier, icmp.seqnum)
                        end
                        break if pair.size == 2
                end
        rescue TimeoutError
                pair = []
        end

        if pair.size == 2
#                puts pair.inspect
                puts (pair[1].pkt_timestamp - pair[0].pkt_timestamp) * 1000
        end
end
