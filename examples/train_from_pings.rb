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
@probecraft.iface_hw_addr      = "00:1c:bf:16:70:c8"
@probecraft.iface_peer_hw_addr = "aa:02:00:00:04:01"

class DelayedICMPPing < ICMPPing
        attr_accessor :before_delay
        attr_reader :result
        def perform!
                @packet.encode!
                raw = Capby::Packet.new(@packet.to_s)
                t = Time.now
                @probecraft.send raw
                @result = @probecraft.dispatch(@expected, @timeout, [@matcher])
                @result
        end
end

count = 100
size = 1400

pings = []
ARGV.each do |addr|
        count.times do |t|
                ping = DelayedICMPPing.new(addr, {:timeout => 5, :size => 50+10*t})
                #ping.before_delay = 10_000
                pings << ping
        end
end

res =  @probecraft.perform pings

times = pings.map{|p| p.result.values.sort_by{|i| i.first.pkt_timestamp}.flatten.map{|v| v ? v.pkt_timestamp : nil}}.transpose
send_tst = times.first
rcv_tst = times.last

ist = []
send_tst.each_cons(2) {|t| ist << t[1] - t[0]}
p ist
avg = ist.inject(0){|sum,i| i+sum}
avg = avg / count
p avg * 1000
var = ist.inject(0){|sum,i| sum + (avg-i)**2}
var = var / count
p var * 1000

iat = []
rcv_tst.each_cons(2) {|t| iat << t[1] - t[0]}
p iat
avg = iat.inject(0){|sum,i| i+sum}
avg = avg / count
p avg * 1000
var = iat.inject(0){|sum,i| sum + (avg-i)**2}
var = var / count
p var * 1000



__END__
unless res.empty?
        puts res.collect{|r| "#{r} us"}
        if not res.include? nil
                puts "=> #{(res.inject(0){|sum,i| i+sum}*1000)/res.length}ms avg"
        end
end
