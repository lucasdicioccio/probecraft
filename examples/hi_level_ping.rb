begin
        require 'capby'
        require 'racket'
        require 'probecraft'
        require 'probecraft/probes/ping'
rescue LoadError
        require 'rubygems'
        require 'capby'
        require 'racket'
        require 'probecraft'
        require 'probecraft/probes/ping'
end


$SAFE = 2

if Capby::Device.all.empty?
        puts "No interface found, maybe you should run that as root"
        exit
end

if ARGV.empty?
        puts "usage 'test.rb <ifacename> <ip1> [ip2[...]]'"
        puts "\tavail. ifaces: #{Capby::Device.all.collect{|d| d.name}.join(" ")}"
        exit
end

devname = ARGV.shift
@probecraft = Probecraft.new devname

pings = []
ARGV.each do |addr|
        10.times do |t|
                #pings << ICMPPing.new(addr, {:timeout => 5, :size => 1024})
                pings << ICMPPing.new(addr, {:timeout => 5})
                #pings << TCPPing.new(addr, {:timeout => 5, :size => 10*t + 50, :dstport => 80, :srcport => rand(2**16)})
                #pings << UDPPing.new(addr, {:timeout => 5, :size => 70})
        end
end

res =  @probecraft.perform pings

unless res.empty?
        puts res.collect{|r| "#{r} us"}
        if not res.include? nil
                puts "=> #{(res.inject(0){|sum,i| i+sum}*1000)/res.length}ms avg"
        end
end
