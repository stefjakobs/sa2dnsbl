# SpamAssassin - sa2dnsbl plugin
###########################################################################

package Mail::SpamAssassin::Plugin::sa2dnsblc;
use IO::Socket;
use strict;
use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
our @ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg { Mail::SpamAssassin::dbg (@_); }

sub new {
  my ($class, $mailsa) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);
  $self->set_config($mailsa->{conf});
  $self->register_eval_rule ("sa2dnsblc");
  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds = ();
  push(@cmds, {
        setting => 'sa2dnsblc_spamscore',
        default => 5,
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  }, {
        setting => 'sa2dnsblc_hamscore',
        default => 0,
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  }, {
        setting => 'sa2dnsblc_host',
        default => 'localhost',
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  }, {
        setting => 'sa2dnsblc_port',
        default => '5055',
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  }, {
        setting => 'sa2dnsblc_timeout',
        default => '2',
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  }, {
        setting => 'sa2dnsblc_retries',
        default => '2',
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  }, {
	setting => 'sa2dnsblc_check_mynets',
	default => '0',
	type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });
 $conf->{parser}->register_commands(\@cmds);
}

sub sa2dnsblc {
  my ($self, $permsgstatus) = @_;

  my $sa2dnsblc_check_mynets = $permsgstatus->{main}->{conf}->{'sa2dnsblc_check_my_nets'} || '0';
  # avoid FPs (and wasted processing) by not checking when all_trusted
  if ($sa2dnsblc_check_mynets) {
    return 0 if $permsgstatus->check_all_trusted;
  }

  # if there is only one received header we can bail
  my $times_ref = ($permsgstatus->{received_header_times});
  #return 0 if (!defined($times_ref) || scalar(@$times_ref) < 2); # if it only hit one server we're done

  my $lasthop = $permsgstatus->{relays_external}->[0];
  my $lasthopip = $lasthop->{ip} || '';
  $lasthopip = $1 if $lasthopip =~ /^([0-9a-fA-F.:]+)$/; # untaint lasthopip;
  dbg("SA2DNSBLC: LASTHOP=$lasthopip");

  my $subject = $permsgstatus->get('Subject'); 
  $subject = $1 if $subject =~ /^([[:ascii:]]*)$/; # untaint subject;
  dbg("SA2DNSBLC: Subject=$subject");

  my $from = $permsgstatus->get('From');
  $from = $1 if $from =~ /^([[:ascii:]]*)$/; # untaint from;
  dbg("SA2DNSBLC: From=$from");
  my $to = $permsgstatus->get('To');
  $to = $1 if $to =~ /^([[:ascii:]]*)$/; # untaint to;
  dbg("SA2DNSBLC: To=$to");

  my $score  = sprintf("%2.1f", $permsgstatus->{score});
  dbg("SA2DNSBLC: SCORE=$score");

  my $sa2dnsblc_spamscore = $permsgstatus->{main}->{conf}->{'sa2dnsblc_spamscore'} || '5';
  dbg("SA2DNSBLC: REQUIRED SPAM SCORE=$sa2dnsblc_spamscore");
  my $sa2dnsblc_hamscore = $permsgstatus->{main}->{conf}->{'sa2dnsblc_hamscore'} || '0';
  dbg("SA2DNSBLC: REQUIRED HAM SCORE=$sa2dnsblc_hamscore");

  # if the sa scoring hits our defined scoring to report, send the ip to the sa2dnsbld
  if(($score >= $sa2dnsblc_spamscore || $score <= $sa2dnsblc_hamscore) && $lasthopip) {
	my $status = '';
	if($score >= $sa2dnsblc_spamscore) {
		$status = 'spam';
	} else {
		$status = 'ham';
	}
        my $sa2dnsblc_host = $permsgstatus->{main}->{conf}->{'sa2dnsblc_host'} || '127.0.0.1';
        $sa2dnsblc_host = $1 if $sa2dnsblc_host =~ /^([a-zA-Z0-9\-.:]{1,255})$/; # untaint fqdn or ip;
        my $sa2dnsblc_port = $permsgstatus->{main}->{conf}->{'sa2dnsblc_port'} || '5055';
        $sa2dnsblc_port = $1 if $sa2dnsblc_port =~ /^([0-9]{1,5})$/; # untaint port;
        my $sa2dnsblc_timeout = $permsgstatus->{main}->{conf}->{'sa2dnsblc_timeout'} || '2';
        $sa2dnsblc_timeout = $1 if $sa2dnsblc_timeout =~ /^([0-9]+)$/; # untaint timeout;
        my $sa2dnsblc_retries = $permsgstatus->{main}->{conf}->{'sa2dnsblc_retries'} || '2';
        $sa2dnsblc_retries = $1 if $sa2dnsblc_retries =~ /^([0-9]+)$/; # untaint retries;

        my $input = '';
        my $output = "$lasthopip#$status#$from#$to#$subject";
        my $sock = IO::Socket::INET->new(Proto => 'udp', PeerPort => $sa2dnsblc_port, PeerAddr => $sa2dnsblc_host);
        return 0 if(!defined($sock)); # Error if socket connection failed!

        $sock->send($output);
        $input = udp_recieve($sock, $sa2dnsblc_timeout);
        my $retry = 1;
        while(!$input && $retry < $sa2dnsblc_retries) {
        	$sock->send($output);
        	$input = udp_recieve($sock, $sa2dnsblc_timeout);
        	$retry++;
        }
        return 0 if($retry > $sa2dnsblc_retries);
        if($input == 0) {
        	dbg("SA2DNSBLC: sa2dnsbld could not be reached!");
        } else {
        	dbg("SA2DNSBLC: sa2dnsbld reports a reputation of $input % on this ip");
        }
        $sock->close();
  }
}

sub udp_recieve {
my ($sock, $sa2dnsblc_timeout) = @_;
my $input;
eval {
    local $SIG{ALRM} = sub { return 0 };
    alarm $sa2dnsblc_timeout;
    $sock->recv($input, 1024);
    alarm 0;
    return $input;
} or return 0;
}

1;

=head1 NAME

Mail::SpamAssassin::Plugin::sa2dnsblc - report spamming ip to the sa2dnsbld server

=head1 SYNOPSIS

/etc/mail/spamassassin/sa2dnsblc.cf:

    loadplugin Mail::SpamAssassin::Plugin::sa2dnsblc sa2dnsblc.pm
    sa2dnsblc_spamscore     5
    sa2dnsblc_hamscore      0
    sa2dnsblc_host          127.0.0.1
    sa2dnsblc_port          5055
    sa2dnsblc_timeout       2
    sa2dnsblc_retries       2
    sa2dnsblc_check_mynets  0

    body     SA2DNSBLC eval:sa2dnsblc()
    describe SA2DNSBLC IP will reported to sa2dnsbld Server if hit
    priority SA2DNSBLC 2000
    score    SA2DNSBLC 0.001

=head1 DESCRIPTION

sa2dnsblc.pm is a plugin for SpamAssassin 3.1.0 and up. It sends the
gateway IP of mails with a scoring equal and higher than
I<sa2dnsblc_spamscore> or equal or lower than I<sa2dnsbl_hamscore>
to the sa2dnsbld server. The communication uses the UDP Protocol and
restrictions to the sa2dnsbld server should be implemented into your
firewall settings. This Plugin can be configured to repeat x-times to
get an answer from the server. The answer contains the count of hits on
the reported ip, but is currently not used from the plugin itself.

You can set the accuracy of the reporting function by adjusting the
I<sa2dnsblc_spamscore> and I<sa2dnsblc_hamscore> values. These values
are responsible for triggering the reporting function. The priority of
this plugin should be that high, to ensure that it is executed after all
other rules are processed.

To use this plugin you'll need also the B<sa2dnsbld> server and the
B<sa2dnsblw> script. Only these three components are the complete package.

=head1 AUTHOR

Frank Blechschmitt, FBIS (http://www.fbis.ch)

Stefan Jakobs, (http://www.localside.net)

=head1 SEE ALSO

README, sa2dnsbld.pl(8), sa2dnsblw.pl(8)

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
