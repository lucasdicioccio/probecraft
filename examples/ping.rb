
begin
        require 'capby'
        require 'racket'
        require 'probecraft'
        require 'probecraft/matcher'
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

# creates two correctly done packets
max = 5
reqs = (1 .. max).map{|seq|
        Ethernet.new do |eth|
                eth.src = "001c233B614A"
                eth.dst = "00:16:3e:ff:ff:ff"
                eth.payload = IP.new do |ip|
                        ip.src = "10.0.0.1"
                        ip.dst = "10.0.0.216"
                        ip.ttl = 5
                        ip.dont_fragment!
                        ip.ipid = rand(2**16)
                        ip.payload = ICMP.new do |icmp|
                                icmp.kind = :echo_request
                                icmp.seqnum = seq
                                icmp.identifier = rand(2**16)
                                icmp.data = "\x00"*100*seq
                        end
                end
        end
}

reqs.each{|ping| ping.encode!}

# get their identifier to prepare their matching
identifiers = reqs.map{|ping| ping.payload.payload.identifier}

m1 = Matcher.new do |m|
        m.layers(Ethernet, IP, ICMP) do |icmp|
                icmp[:echo_reply] and identifiers.include? icmp.identifier
        end
end

m2 = Matcher.new do |m|
        m.layers(Ethernet, IP, ICMP) do |icmp|
                icmp[:echo_request] and identifiers.include? icmp.identifier
        end
end

# send the data
b.send(reqs.map{|r| r.to_s})

# match
matchers = [m1, m2]
@matched = b.dispatch(2*max, 1, matchers)

puts "Replies" + "\n"*3
puts @matched[m1].inspect
puts "Requests" + "\n"*3
puts @matched[m2].inspect
