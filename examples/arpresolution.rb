begin
        require 'capby'
        require 'racket'
        require 'probecraft'
rescue LoadError
        require 'rubygems'
        require 'capby'
        require 'racket'
        require 'probecraft'
        require 'probecraft/probes/arpresolv'
end

if ARGV.empty?
        puts "usage 'test.rb <ifacename> <ip1> [ip2 [...]]'"
        puts "\tavail. ifaces: #{Capby::Device.all.collect{|d| d.name}.join(" ")}"
        exit
end

devname = ARGV.shift
@probecraft = Probecraft.new devname

hw = ARGV.collect do |ip|
        ARPResolution.new ip
end

p @probecraft.perform(hw)[0].join(':')

