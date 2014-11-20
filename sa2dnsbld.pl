#!/usr/bin/perl -w

package sa2dnsbld;
use strict;
use IO::Socket;
use Sys::Syslog;
use Getopt::Long;
use Pod::Usage;
use DBI;

### Variables ### 
my $max_package_length = 1024;
my $configfile = '/etc/sa2dnsbld.cf';
my ($help, $daemon, $verbose, %config);
my ($dbh, $sock, $input, $output, $a, $b);
my %tmpconfig = (
   DIV   => 5,
   DECAY => 3*24*60*60,
   MAX   => 100,
);
   

#$|=1;

### Functions ###
sub logit {
  my ($priority, $msg) = @_;
  return 0 unless ($priority =~ /info|err/ or ($priority =~ /debug/ and $verbose));
  if ($daemon) {
    syslog($priority, $msg);
  } else {
    print "$msg\n";
  }
}

sub logdie {
  my ($msg) = @_;
  syslog('LOG_CRIT', $msg);
  die $msg
}

sub TERM_handler {
  exit 0;
}
$SIG{'TERM'} = \&TERM_handler;

### Main ###

# Read arguments
Getopt::Long::Configure ('no_ignore_case');
if (@ARGV > 0) {
  GetOptions(  'help|?|h'  => \$help,
               'daemon|d'  => \$daemon,
               'verbose|v' => \$verbose, 
            ) or pod2usage(1);
}
if ($help) { pod2usage(VERBOSE => 2) }

# check and read config file
if ( -r $configfile ) {
  %config = do $configfile;
} else {
  die("can not read $configfile");
}

# initialise syslog
if ($config{LOG_FACILITY} and $config{LOG_FACILITY} !~ /^LOG_(?:DAEMON|LOCAL\d|MAIL|SYSLOG|USER|KERN|CONSOLE)$/) {
  $config{LOG_FACILITY} = 'LOG_DAEMON';
}
openlog("sa2dnsbld", , $config{LOG_FACILITY});

# set %config default values if not set via config file
foreach my $key (keys %tmpconfig) {
   if ($tmpconfig{$key} and ! $config{$key}) {
      $config{$key} = $tmpconfig{$key};
   }
} 

# check if input is in right format
if ( $config{LOCALPORT} !~ /^\d+$/) { logdie("error: LOCALPORT has wrong format"); }
if ( $config{LOCALIP} !~ /^[.:a-f\d]+$/i) { logdie("error: LOCALIP is not an IP address"); }
if ( $config{DB_HOST} !~ /^[\w.-]+$/)   { logdie("error: DB_HOST has wrong format"); }
if ( $config{DB_NAME} !~ /^\w+$/)   { logdie("error: DB_NAME has wrong format"); }
if ( $config{DB_USER} !~ /^\w+$/)   { logdie("error: DB_USER has wrong format"); }
if ( $config{DB_TABLE} !~ /^\w+$/)  { logdie("error: DB_TABLE has wrong format"); }
if ( $config{DIV} !~ /^\d+$/)       { logdie("error: DIV is not a number"); }
if ( $config{MAX} !~ /^\d+$/)       { logdie("error: MAX is not a number"); }
if ( $config{DECAY} !~ /^\d+$/)     { logdie("error: DECAY is not a number"); }
if ( $config{MAX} <= 0 or $config{DECAY} <= 0) {
   logdie("error: MAX and/or DECAY must be greater than 0");
}

# metrics
# spam: reputation = reputation+(MAX-reputation)*a*EXP(-(t_0-t_last)/b)
# ham : reputation = reputation*(1-a*EXP((t_0-t_last)/b)
# reputation: [0 ... MAX]
$a = 0.2;
$b = $config{DECAY}/log(1/($config{MAX}/$config{DIV})/$a); # b<0

do {
  $dbh = DBI->connect("DBI:mysql:$config{DB_NAME}:$config{DB_HOST}", 
                      "$config{DB_USER}", "$config{DB_PASS}")
    or logit('Cant connect to Database! Will try again in 5 seconds');
    if (! defined($dbh)) { sleep 5; };
} until (defined($dbh));
    
$sock = IO::Socket::INET->new(LocalAddr => $config{LOCALIP}, 
                              LocalPort => $config{LOCALPORT},
                              Proto     => 'udp')
  or logdie("socket: $@");
$dbh->disconnect;

logit('info', "Starting up SA2DNSBL Server on $config{LOCALIP}:$config{LOCALPORT}");

while ($sock->recv($input, $max_package_length)) {
  $output = '';
  my ($remote_port, $remote_addr) = sockaddr_in($sock->peername);
  my $remote_ip = inet_ntoa($remote_addr);
  my $remote_host = gethostbyaddr($remote_addr, AF_INET);

  if($input =~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ or
     $input =~ /^[:a-f0-9]{2,41}/i ) {
    my @buffer = split(/#/, $input, 5);
    chomp(@buffer);
    # check if ip is already listed and get its values
    $dbh = DBI->connect("DBI:mysql:$config{DB_NAME}:$config{DB_HOST}",
                        "$config{DB_USER}", "$config{DB_PASS}");
    my $sql = "SELECT ip,reputation FROM $config{DB_TABLE} WHERE ip=INET6_ATON('$buffer[0]')";
    my $cursor = $dbh->prepare($sql);
    if (! $cursor->execute) { 
      logit('err', "error: failed to execute SQL statement");
      logit('err', $sql);
      $output = '0';
    } else {  # got a result from mysql query
      my @columns = $cursor->fetchrow;

      if(!@columns) {	# ip is not listed
        # list IP with default value
        $output = '50';
        $sql = "INSERT INTO $config{DB_TABLE} (ip,reputation,lastchange,spam_hits, ham_hits) \
                VALUES (INET6_ATON('$buffer[0]'),50,NOW(),0,0)";
      } else {	# ip is listed
	     if($buffer[1] =~ /spam/) {
          $output = $columns[1]; #Column 'reputation' in table
          $sql = "UPDATE $config{DB_TABLE} SET reputation=reputation+($config{MAX}-reputation)*$a*EXP((NOW()-lastchange)/$b), \
                     lastchange=NOW(), spam_hits=spam_hits+1 WHERE ip=INET6_ATON('$buffer[0]')";
	     } else { #spam
          $output = $columns[1]; #Column 'reputation' in table
          $sql = "UPDATE $config{DB_TABLE} SET reputation=reputation*(1-$a*EXP((NOW()-lastchange)/$b)), \
                  lastchange=NOW(), ham_hits=ham_hits+1 WHERE ip=INET6_ATON('$buffer[0]')";
	     }
      }
      $cursor = $dbh->prepare($sql);
      if (! $cursor->execute) { 
        logit('err', "error: failed to execute SQL statement");
        logit('err', $sql);
        $output = '0';
      } else {  # mysql update was successful
        logit('debug', sprintf("remote_ip: %15s last reputation score: %3i %%", $buffer[0], $output));
      }
    }
    $dbh->disconnect;
  }
  $sock->send($output);
} logdie("recv: $!");

END {
  logit('info', 'shuting down ...');
  closelog();
}


=head1 NAME

sa2dnsbld.pl - Calculates reputation and interacts with MySQL Database.

=head1 DESCRIPTION

B<sa2dnsbld.pl> is a simple udp server written in Perl that listens on an
UDP port, recieves IP addresses with a message status (ham or spam) from
sa2dnsblc and stores them in a MySQL Database. After recieving an IP
address, B<sa2dnsbld.pl> checks if this IP is already known. If so, the
reputation score value will be recalculated. If not, a new record in the
table is created. 

B<sa2dnsbld.pl> uses the following equations to calculate the reputation scores:

  spam: reputation = reputation+(MAX-reputation)*a*EXP(-(t_0-t_last)/b)
  ham : reputation = reputation*(1-a*EXP((t_0-t_last)/b)

  with a=0.2 and b=DECAY/log(1/(MAX/DIV)/a) < 0
  The reputation score may range from 0 to MAX.

To let the B<sa2dnsblc> know that everything is right, B<sa2dnsbld.pl> returns the
reputation score. If something went wrong, a '0' is returned.

=head2 OPTIONS

=over 12

=item C<-d | --daemon>

Runs B<sa2dnsbld.pl> as a daemon. Output to STDOUT is suppressed, but all
messages will be logged to syslog.

=item C<-v | --verbose>

Let B<sa2dnsbld.pl> print debug messages.

=item C<-h | --help>

Prints this manual page.

=back

=head2 CONFIGURATION

Confguration of B<sa2dnsbld.pl> takes place in F</etc/sa2dnsbld.cf>. Available options
are:

=over 12

=item C<LOCALPORT>

UDP port B<sa2dnsbld.pl> will bind to. Default: 5055.

=item C<LOCALIP>

IP address B<sa2dnsbld.pl> will bind to. Default: 127.0.0.1.

=item C<DB_HOST>

Host name or IP address of host which runs the MySQL daemon to which 
B<sa2dnsbld.pl> will connect. Default: 127.0.0.1

=item C<DB_NAME>

Name of database which holds sa2dnsbl data. Default: sa2dnsbl.

=item C<DB_USER>

MySQL user name to connect to C<DB_HOST>. Default: root.

=item C<DB_PASS>

MySQL passwort to connect to C<DB_HOST>.

=item C<DB_TABLE>

Name of MySQL table which contains sa2dnsbl data: Default: sa2dnsbl.

=item C<LOG_FACILITY>

B<sa2dnsbld.pl> will send its logs to this syslog facility. Possible values
are LOG_DAEMON (default), LOG_USER, LOG_LOCAL0 to LOG_LOCAL7, LOG_MAIL,
LOG_SYSLOG, LOG_KERN or LOG_CONSOLE

=item C<MAX>

Reputation ranges between 0 and C<MAX> (default: 100). With 0 as hamiest
and C<MAX> as spamiest value. 

=item C<DIV>

Default: 5

=item C<DECAY>

after C<DECAY> seconds decrease the reputation score by one.
Default: 3*24*60*60 = 259200 seconds = 3 days

=back

=head1 SEE ALSO

sa2dnsblc.pm(3), sa2dnsblw.pl(8)

=head1 AUTHOR

Frank Blechschmitt, FBIS (http://www.fbis.ch)

Stefan Jakobs, localside.net (http://www.localside.net) 

=head1 LICENSE

Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements.  See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The ASF licenses this file to you under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License.  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

=cut
