# alarm.rb
# => webserver log analyzer 
# => - detects NMAP scans
# => - detects HTTP errors
# => - detects shellcode
# => live packet analysis
# => - detects NMAP, NULL, XMAS Scans
# => - checks for plaintext credit card numbers 

require 'packetfu'
require 'apachelogregex'



def alert(incident_number, attack, source_ip, protocol, payload)
	puts "#{incident_number}. ALERT: #{attack} is detected from #{source_ip} (#{protocol}) (#{payload})"
end


def cc_alert(incident_number, source_ip, protocol, payload)
	puts "#{incident_number}. ALERT: Credit card leaked in the clear from #{source_ip} HTTP (#{payload})"
end

def null_scan?(flags)
	(flags.urg == 0) && (flags.ack == 0) && (flags.psh == 0) && (flags.rst == 0) && (flags.syn == 0) && (flags.fin == 0)
end

def xmas_scan?(flags)
	(flags.fin == 1) && (flags.urg == 1) && (flags.psh == 1)
end

def nmap_scan?(packet)
	packet.payload.scan(/nmap/i)[0] != nil
end

def credit_card(packet)
	if (packet.payload.scan(/4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/)[0] != nil)
		return "VISA"
	elsif (packet.payload.scan(/5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/)[0] != nil)
		return "MasterCard"
	elsif (packet.payload.scan(/6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/)[0] != nil)
		return "Discover"
	elsif (packet.payload.scan(/4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/)[0] != nil)
		return "Amex"
	else
		return "N/A"
	end		
end

def proto(packet)
	if (packet.orig_kind_of? PacketFu::TCPPacket)
		return "TCP"	
	elsif (packet.orig_kind_of? PacketFu::EthPacket)
		return "ETH"	
	elsif (packet.orig_kind_of? PacketFu::ARPPacket)
		return "Arp"	
	elsif (packet.orig_kind_of? PacketFu::UDPPacket)
		return "UDP"	
	elsif (packet.orig_kind_of? PacketFu::HSRPPacket)
		return	"HSRP"
	elsif (packet.orig_kind_of? PacketFu::ICMPPacket)
		return	"ICMP"
	elsif (packet.orig_kind_of? PacketFu::IPv6Packet)
		return	"IPv6"
	elsif (packet.orig_kind_of? PacketFu::IPv6Packet)
		return	"IPv6"
	elsif (packet.orig_kind_of? PacketFu::InvalidPacket)
		return	"Invalid"
	else
		return	"N/A"
	end
end 


# WEB SERVER LOG ANALYSIS
if (ARGV[0] == "-r")
	format = '%source %l %u %t \"%request\" %>status %b \"%{Referer}i\" \"%{User-Agent}i\"'
	parser = ApacheLogRegex.new(format)
	incident_number = 0

	File.foreach(ARGV[1]) do |line|
  	begin
    	hash = parser.parse(line)
		request = hash["%request"]

    	if( hash["%>status"] =~ /^4\d\d$/ ) # response codes in 400 range
    		ip = hash["%source"]
    		incident_number += 1
    		alert(incident_number, "HTTP error", ip, "HTTP", request)
    	end
    	if( request =~ /\\x\h\h\h?\\x\h\h\h?/)						# line 38495 of the weblog has shell code for example
    		incident_number += 1
    		alert(incident_number, "Shellcode", ip, "HTTP", request)
    	end
    	if( line =~ (/nmap/i) )
			alert(incident_number, "Nmap scan", ip, "HTTP", request)
    	end
  	rescue ApacheLogRegex::ParseError => e
    	puts "Error parsing log file: " + e.message
  	end
end

#LIVE PACKET ANALYSIS
else
	cap = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
	incident_number = 0

	cap.stream.each do |p|
		
		packet = PacketFu::Packet.parse(p)
		protocol = proto(packet)

		if (protocol == "TCP")
			if null_scan?(packet.tcp_flags)
				incident_number += 1
				alert(incident_number, "Null scan", packet.ip_saddr, protocol, packet.payload)
			elsif xmas_scan?(packet.tcp_flags)
				incident_number += 1
				alert(incident_number, "Xmas scan", packet.ip_saddr, protocol, packet.payload)		
			elsif nmap_scan?(packet)
				incident_number += 1
				alert(incident_number, "Nmap scan", packet.ip_saddr, protocol, packet.payload)
			end
		end

		cc = credit_card(packet)

		if (cc != "N/A")
			incident_number += 1
			cc_alert(incident_number, packet.ip_saddr, protocol, packet.payload)
		end
	end
end


