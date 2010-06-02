begin
        require 'capby'
        require 'racket'
        require 'probecraft'
        require 'probecraft/probes/traceroute'
rescue LoadError
        require 'rubygems'
        require 'capby'
        require 'racket'
        require 'probecraft'
        require 'probecraft/probes/traceroute'
end

$SAFE = 2

if Capby::Device.all.empty?
        puts "No interface found, maybe you should run that as root"
        exit
end

if ARGV.empty?
        puts "usage 'test.rb <ifacename> <ip>'"
        puts "\tavail. ifaces: #{Capby::Device.all.collect{|d| d.name}.join(" ")}"
        exit
end

devname = ARGV.shift
@probecraft = Probecraft.new devname

pkt = LostPacket.new(ARGV.first, 1, {:timeout => 1})
@probecraft.perform pkt

tr = Traceroute.new(ARGV.first, {:retry => 3, :max_ttl => 2, :timeout => 1})
tr.probecraft = @probecraft
p tr.perform!
