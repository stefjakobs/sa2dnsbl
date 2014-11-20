#!/usr/bin/perl -w
#
# Script for sending ip(s) to the sa2dnsbl server

#TODO: manpage

use strict;
use IO::Socket;
my (%addresses, %config);
my ($ip) = @ARGV;
my $retries = 3;
my $timeout = 2;
my $configfile = '/etc/sa2dnsbld.cf';

# read config file and check input from config file
if ( -r $configfile ) {
   %config = do $configfile;
} else {
   die("can not read $configfile");
}
if ( $config{LOCALPORT} !~ /^\d+$/) { die("$configfile: LOCALPORT has wrong format"); }
if ( $config{LOCALIP} !~ /^[.:a-f\d]+$/i) { die("$configfile: LOCALIP is not an IP address"); }

# check IP addresses
if(not $ip) {
   while (<STDIN>) {
      chomp;
      if($_ =~ m/^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$/ or
         $_ =~ m/^[a-f:0-9]{2,41}/i ) {
         $addresses{$_}++;
      }
   }
} else {
   if($ip =~ m/^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$/ or
      $ip =~ m/^[a-f:0-9]{2,41}/i ) {
       $addresses{$ip}++;
   }
}

# open socket
my $sock = IO::Socket::INET->new(Proto => 'udp', PeerPort => $config{LOCALPORT}, PeerAddr => $config{LOCALIP});
if(!defined($sock)) {
   # Error if socket connection failed!
   die("failed to create socket");
}

foreach my $address (keys %addresses) {
   my $output = "$address:'spam'#''#''#'ip2dnsbl client'";
   $sock->send($output);
   my $input = udp_recieve($sock, $timeout);
   my $retry = 1;
   while(!$input && $retry <= $retries) {
   print "retry: $retry\n";
      $sock->send($output);
      $input = udp_recieve($sock, $timeout);
      $retry++;
   }
   if($retry > $retries) {
      print "error: failed to send data\n";
   }
   if($input > 0) {
      printf("Send %s to sa2dnsbld on %s:%d (Result: %d)\n", $address, $config{LOCALIP}, $config{LOCALPORT}, $input);
   }
}
$sock->close();

sub udp_recieve {
   my ($sock, $timeout) = @_;
   my $input;
   eval {
      local $SIG{ALRM} = sub { return 0 };
      alarm $timeout;
      $sock->recv($input, 1024);
      alarm 0;
      return $input;
   } or return 0;
}
