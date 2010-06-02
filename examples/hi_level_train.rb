
require 'rubygems'
require 'capby'
require 'racket'
require 'probecraft'
require 'probecraft/probes/train'


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

@probecraft.iface_peer_hw_addr = "00:16:3e:ff:ff:ff"

train = Train.new(@probecraft)

10.times do |t|
        train << { :type => :icmp_echo,
                :target => '10.0.0.216',
                :size => 30,
                :idle => 100,
                #:use_ip_tst => true
        }
end

2.times do |t|
        train << { :type => :ttl_expired,
                :target => '216.239.59.104',
                :dport => rand(2**16),
                :sport => rand(2**16),
                :size => rand(1300),
                :idle => 500,
                :ttl => 1,
                :use_ip_tst => true,
        }
end

def tst2secs(tst)
        tst.hour * 3600 + t.min * 60 + t.sec + t.usec / 1e6
end

def dump_pkt_info(pkt)
        src = IP.unparse_ip( pkt.payload.src )
        dst = IP.unparse_ip( pkt.payload.dst )
        puts "#{src} >> #{dst} ; #{pkt.payload.total_length} @ #{tst2secs(pkt.pkt_timestamp)}"
end

values = train.perform
p @probecraft.capture.stats
p values

__END__

ordrered = train.packets.map{|i| val[i[1]]}

ordered.flatten.each do |pkt|
        dump_pkt_info pkt
end

