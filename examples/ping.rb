
$LOAD_PATH.unshift './lib'
require 'rubygems'
require 'capby'
require 'racket'
require 'probecraft'
require 'probecraft/probecraft'
require 'probecraft/matcher'
require 'probecraft/protocols/ethernet'
require 'probecraft/protocols/ip'
require 'probecraft/protocols/icmp'
require 'probecraft/protocols/ipoptions'

if Capby::Device.all.empty?
  puts "No interface found, maybe you should run that as root"
  exit
end

if ARGV.empty?
  puts "usage 'test.rb <ifacename>'"
  puts "\tavail. ifaces: #{Capby::Device.all.collect{|d| d.name}.join(" ")}"
  exit
end

include Probecraft

devname = ARGV.first
b = Probecraft::Probecraft.new devname

# creates two correctly done packets
max = 5
reqs = (1 .. max).map{|seq|
  Ethernet.new do |eth|
    eth.src = "c4:2c:03:1d:d2:f7"
    eth.dst = "00:00:0c:07:ac:01"
    eth.payload = IP.new do |ip|
      ip.src  = "132.227.127.78"
      ip.dst  = "132.227.126.1"
      ip.ttl = 64
      #ip.dont_fragment!
      ip.ipid = rand(2**16)
      ip.payload = ICMP.new do |icmp|
        icmp.kind = :echo_request
        icmp.seqnum = seq
        icmp.identifier = rand(2**16)
        icmp.data = "\x00"*56
      end
      ip.options << IPOption::TS.new do |tst|
        tst.oflw_flags = 0x03
        tst.timestamps << [132,227,126,1, 0]
        tst.timestamps << [132,227,127,78, 0]
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
