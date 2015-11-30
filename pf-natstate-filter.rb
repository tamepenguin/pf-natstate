#!/usr/bin/env ruby
STDOUT.sync = true


# Main 

debug = false
# Format of nat line
#all 17 195.37.70.100:56992 (192.168.168.68:56598) -> 82.140.114.226:53318       SINGLE:NO_TRAFFIC
#TODO: Limit Logging to single egress IP
#TODO: Logrotate





if ARGV.index("-h")
  puts "Usage: <script> [-o outfile]
Filters the output of 'tcpdump -l -tt -s 65535 -p -n -e -i pfsync0' for the pure, anonymous natstates.
Options:
-o:    Write to file instead of stdout (default)
"

end



 
output_started=false
logentry=""


if ARGV.index("-o") 
  outfilename = ARGV[ ARGV.index("-o")+1 ]
end

outfile = outfilename ? open(outfilename, "w") : $stdout

while line = STDIN.gets
  trap ("HUP") do
    if outfile === $stdout
      outfile.puts "Received SigHUP!"
    else 
      outfile.reopen(outfilename, "w")
    end	
  end

  if line =~ /PFSYNCv6/ 
    outfile.puts logentry unless logentry.empty? 
    timestamp, protocol, len, lenvalue = line.split " "
    output_started=true
    logentry = ""      
    $stdout.puts line if debug
  else      
    if output_started
      if info = line.match(/all \d ([0-9.:]+) \(([0-9.:]+)\) -> ([0-9.])+:([0-9]+)/)
        all, egress, ingress, target, target_port = info.to_a
        logentry += "#{Time.at(timestamp.to_f)}: nat #{ingress} to #{egress} dport #{target_port} \n"
        $stdout.puts line if debug
      end
    end
  end
end

