#!/usr/bin/perl -w

package sa2dnsblw;
use strict;
use POSIX;
use Getopt::Long;
use Pod::Usage;
use Sys::Syslog;
use DBI;
use NetAddr::IP;

### Variables ###
my $configfile = '/etc/sa2dnsbld.cf';
my ($help, %config, %tmpconfig, %whitelisted, @tmpwhitelisted);
my ($ip, $reputation, $lastchange, $lastrun);
my ($affected_rows, $sql, $cursor, $result);
my $verbose = 0;

### Functions ###
sub logit {
  my ($priority, $msg) = @_;
  return 0 unless ($priority =~ /info|err|debug/);
  syslog($priority, $msg);
  if ($verbose) {
    print "$msg";
  }
}

sub logdie {
  my ($msg) = @_;
  syslog('LOG_CRIT', $msg);
  die $msg
}

### main ###

# The following script is not Part of this Distribution!
# '$' is a substitution for the ip address
$tmpconfig{INFO_URL} = 'Blocked - see http://www.mydomain.com/blocked.cgi?ip=$'; 
#Path to the Data file of your rbldns installation
$tmpconfig{RBLDNS_PATH} = '/var/lib/rbldns/';

# metrics
$tmpconfig{THRESHOLD} = 80;      # IP with reputation > $threshold will be blacklisted
$tmpconfig{REMOVE_TIME} = 5*24;  # remove IP after ~ hours of inactivity from BL
$tmpconfig{INTERVAL} = 15;       # process changes every X minutes (run this script every X minutes)

# Read arguments
Getopt::Long::Configure ('no_ignore_case');
if (@ARGV > 0) {
  GetOptions(  'help|?|h'        => \$help,
               'config|c=s'      => \$configfile,
               'verbose|v+'      => \$verbose,
               'host|H=s'        => \$tmpconfig{DB_HOST},
               'name|n=s'        => \$tmpconfig{DB_NAME},
               'user|u=s'        => \$tmpconfig{DB_USER},
               'passwd|p=s'      => \$tmpconfig{DB_PASS},
               'table|t=s'       => \$tmpconfig{DB_TABLE},
               'url|l=s'         => \$tmpconfig{INFO_URL},
               'rbldns-path|r=s' => \$tmpconfig{RBLDNS_PATH},
               'whitelisted|w=s' => \@tmpwhitelisted,
               'threshold|T=i'   => \$tmpconfig{THRESHOLD},
               'remove-time|R=i' => \$tmpconfig{REMOVE_TIME},
               'interval|I=i'    => \$tmpconfig{INTERVAL},
            ) or pod2usage(1);
}
if ($help) { pod2usage(VERBOSE => 2) }

# check and read config file
if ( -r $configfile ) {
  %config = do $configfile;
} else {
  die("error: can not read $configfile");
}

# initialise syslog
if ($config{LOG_FACILITY} !~ /^LOG_(?:DAEMON|LOCAL\d|MAIL|SYSLOG|USER|KERN|CONSOLE)$/) {
  $config{LOG_FACILITY} = 'LOG_DAEMON';
}
openlog("sa2dnsblw", , $config{LOG_FACILITY});

# set and overwrite %config with values from %tmpconfig
foreach my $key (keys %tmpconfig) {
   if ($tmpconfig{$key}) {
      $config{$key} = $tmpconfig{$key};
   }
}

# generate a hash list with whitelisted ip addr as key
if ($config{WHITELISTED}) {
   @tmpwhitelisted = split(/,/,join(',',@tmpwhitelisted, $config{WHITELISTED}));
} else {
   @tmpwhitelisted = split(/,/,join(',',@tmpwhitelisted));
}
foreach my $elem (@tmpwhitelisted) {
   $whitelisted{"$elem"} = 1;
}

# check if input is in right format
if ( $config{DB_HOST} !~ /^[\w.-]+$/)  { logdie("error: DB_HOST has wrong format"); }
if ( $config{DB_NAME} !~ /^\w+$/)      { logdie("error: DB_NAME has wrong format"); }
if ( $config{DB_USER} !~ /^\w+$/)      { logdie("error: DB_USER has wrong format"); }
if ( $config{DB_TABLE} !~ /^\w+$/)     { logdie("error: DB_TABLE has wrong format"); }
if ( $config{THRESHOLD} !~ /^\d+$/)    { logdie("error: DIV is not a number"); }
if ( $config{REMOVE_TIME} !~ /^\d+$/)  { logdie("error: MAX is not a number"); }
if ( $config{INTERVAL} !~ /^\d+$/)     { logdie("error: DECAY is not a number"); }
if (! -w $config{RBLDNS_PATH})         { logdie("error: directory $config{RBLDNS_PATH} is not writeable"); }
if ( $config{THRESHOLD} <= 0 or $config{REMOVE_TIME} <= 0 or $config{INTERVAL} <= 0) {
   logdie("error: THRESHOLD, REMOVE_TIME and/or INTERVAL must be greater than 0");
}
 
my $dbh = DBI->connect("DBI:mysql:$config{DB_NAME}:$config{DB_HOST}", 
                        $config{DB_USER}, $config{DB_PASS})
   or logdie "error: Can't connect to Database!";

# check if the database was recently changed
$sql        = "select UNIX_TIMESTAMP(MAX(lastchange)) as 'lastchange' from $config{DB_TABLE} LIMIT 1";
$cursor     = $dbh->prepare($sql);
$cursor->execute 
   or logdie("error: Can't execute SQL statement!");
$result     = $cursor->fetchrow_hashref();
$lastchange = $result->{'lastchange'};
# we don't fetch all results, so:
$cursor->finish();
$lastrun    = strftime("%s", localtime) - $config{INTERVAL}*60;

if ( $lastchange < $lastrun ) {
   logit("warning: database hasn't change since last run. Skipping.");
   $dbh->disconnect;
   exit 0;
}

# start creating new ip list and delete old entries
logit('info', "start creating new rbldns data file ...\n");
open(OUTPUT, '>'.$config{RBLDNS_PATH}.'data')
   or logdie("error: Can't open $config{RBLDNS_PATH} data");
print OUTPUT "# File created by sa2dnsblw.pl, ".gmtime(time())."\n";
print OUTPUT ":127.0.0.2:$config{INFO_URL}\n";
print OUTPUT "127.0.0.2\n";

open(OUTPUT6, '>'.$config{RBLDNS_PATH}.'data6')
   or logdie("error: Can't open $config{RBLDNS_PATH} data6");
print OUTPUT6 "# File created by sa2dnsblw.pl, ".gmtime(time())."\n";
print OUTPUT6 ":127.0.0.2:$config{INFO_URL}\n";
print OUTPUT6 "!0:0:0:0:0:ffff:7f00:1\n";
# TODO: Replace this with the down mentioned version, as soon as it will work with rbldnsd
print OUTPUT6 "!2001:db8:2041:25:4000:3000:2000:2000\n";
print OUTPUT6 "2001:db8:2041:25\n";
# TODO: Should only list ::ffff:7f00:1, according to
# http://tools.ietf.org/html/rfc5782.html#section-5
# But that's not yet possible with rbldnsd0.996-ipv6
# The following will not work, because it will match on all IPv4 and IPv6 addresses
# print OUTPUT6 "0:0:0:0\n";

# cleanup table (logging how? xxx rows affected)
$sql = "DELETE FROM $config{DB_TABLE} WHERE HOUR(TIMEDIFF(NOW(), lastchange)) > '$config{REMOVE_TIME}'"; 
$cursor = $dbh->prepare($sql);
$affected_rows = $cursor->execute 
   or logdie("error: Can't execute SQL statement!");
if ($affected_rows == 0 ) { $affected_rows = 0 }  # reformat $affected_rows
logit('info', "$affected_rows inactive IP addresses removed.\n");
$affected_rows = -1;

# decrease reputation of inactive IPs (logging ? )
# Substract 5*DAYS_OF_INACTIVITY per Day, e.g. UPDATE after 24 hours of inactivity
$sql = "UPDATE $config{DB_TABLE} SET reputation=reputation-5*DATEDIFF(NOW(),lastchange) \
        WHERE reputation > $config{THRESHOLD} AND DATEDIFF(NOW(),lastchange) > 0 AND \
        MOD(HOUR(TIMEDIFF(NOW(), lastchange)), 24) <= TRUNCATE($config{INTERVAL}/60, 0) AND \
        MINUTE(TIMEDIFF(NOW(), lastchange)) < $config{INTERVAL}";
$cursor = $dbh->prepare($sql);
$affected_rows = $cursor->execute
   or logdie("error: Can't execute SQL statement!");
if ($affected_rows == 0 ) { $affected_rows = 0 }
logit('info', "$affected_rows reputation scores decreased.\n");
$affected_rows = -1;

# set IP on BL
$sql = "SELECT INET6_NTOA(ip),reputation,lastchange FROM $config{DB_TABLE}
        WHERE reputation > $config{THRESHOLD} ORDER BY ip";
$cursor = $dbh->prepare($sql);
$cursor->execute
   or logdie("error: Can't execute SQL statement!");
$cursor->bind_columns( undef, \$ip, \$reputation, \$lastchange );
my @count;
my %count6;
while( $cursor->fetch() ) {
   if(! exists $whitelisted{"$ip"}) {
      if ($ip =~ /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/) {
         # ipv4
         #print OUTPUT "$ip\n";
         push(@count, $ip);
      } else {
         my $IPv6 = new NetAddr::IP->new("$ip", '64');
         ($ip) = ($IPv6->network()->addr() =~ /^([0-9a-fA-F:]+):0:0:0:0$/);
         # ipv6
         #print OUTPUT6 "$ip\n";
         $count6{$ip}++;
      }
      if ($verbose > 1) {
         logit('info', "$ip blacklisted\n");
      } 
   } elsif ($verbose > 1) {
      logit('info',"$ip whitelisted\n");
   }
}
$cursor->finish();

foreach (sort {$a cmp $b} @count) {
   print OUTPUT "$_\n";
}
foreach (sort {$a cmp $b} keys %count6) {
   print OUTPUT6 "$_\n";
}

close(OUTPUT);
close(OUTPUT6);
$dbh->disconnect;

my $value = scalar(keys %count6);
logit('info', "added $#count IP addresses to ".$config{RBLDNS_PATH}."data\n");
logit('info', "added $value IP addresses to ".$config{RBLDNS_PATH}."data6\n");


=head1 NAME

sa2dnsblw.pl - worker script which creates the rbldns data files 

=head1 SYNOPSIS

sa2dnsblw.pl [--help|-h|-?] [--config|-c <configfile>]
    [--verbose|-v] [--host|-H <db host>] [--name|-n <db name>]
    [--user|-u <db_user>] [--passwd|-p <db password>] [--table|-t <db table>]
    [--url|-l <info url>] [--rbldns-path|-r <path>] [--whitelisted|-w <ip addr>]
    [--threshold|-T <#>] [--remove-time|-R <#>] [--interval|-I <#>]

=head1 DESCRIPTION

sa2dnsblw.pl is selecting all IP addresses from the SQL Database with a
reputation score higher as the threshold and creates a 'data' and a 'data6'
file inside your rbldns installation. To complete the work of this part,
the needed 'data.cdb' is refreshed.

=head1 CONFIGURATION

Confguration of B<sa2dnsblw.pl> takes place in F</etc/sa2dnsbld.cf>.
Available options are:

=head2 OPTIONS

=over 8 

=item --help|-?|-h

print this manual page

=item --config|-c C<config file>

use C<config file> instead of F</etc/sa2dnsbld.cf>

=item --verbose|-v

increase output to STDOUT and syslog. Use -v -v to make the script
very verbose.

=item --host|-H C<hostname|ip addr>

Connect to MySQL on C<hostname|ip addr>. Overwrites option C<DB_HOST>.

=item --name|-n C<name>

Use MySQL Database C<name>. Overwrites option C<DB_NAME>.

=item --user|-u C<user>

Connect to MySQL as C<user>. Overwrites option C<DB_USER>.

=item --passwd|-p C<password>

Connect to MySQL with C<password>. Overwrites option C<DB_PASSWD>.

=item --table|-t C<table>

Store data in MySQL table C<table>. Overwrites option C<DB_TABLE>.

=item --url|-l C<url>

Add an info URL as TXT record to the data set. Overwrites option C<INFO_URL>.

=item --rbldns-path|-r C<path>

Store rbldns data files under C<path>. Overwrites option C<RBLDNS_PATH>.

=item --whitelisted|-w C<ip address>

Whitelist C<ip address>; e.g. don't list C<ip address> in the data file. 
This option may be used more than once. Addresses named here are added to
the set of addresses already listed by option C<WHITELISTED>.

=item --threshold|-T C<value>

IP addresses with a reputation score greater than C<value> will be blacklisted,
e.g. listed in the data file. Overwrites option C<THRESHOLD>.

=item --remove-time|-R C<value>

IP addresses will be removed from the blacklist, data file, if it status was
not updated for more than C<value> seconds. Overwrites option C<REMOVE_TIME>.

=item --interval|-I C<value>

Recalculate only reputation scores of IP addresses which status change is not
older than C<value> minutes. This should be the same intervall in which this
script will be run by cron. Overwrites option C<INTERVAL>.

=back

=head1 BUGS

With IPv6 only /64 subnets can be blacklisted and /128 addresses can be whitelisted.
But whitelisting means don't print the IPv6 IP into the dataset. So whitelisting
with IPv6 doesn't work.

=head1 SEE ALSO

sa2dnsblc.pm(3), sa2dnsbld.pl(8)

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

