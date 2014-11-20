sa2dnsbl
========

Description:
------------
use spamassassin to generate a DNS blackhole list

The sa2dnsbl package consists of:
  * sa2dnsblc.pm - the client, a SpamAssassin module
  * sa2dnsbld.pl - the daemon (run by init)
  * sa2dnsblw.pl - the worker script (run by cron)
  * ip2dnsbl.pl  - a helper script (run by the user)

The sa2dnsbl client collects the IP address from SpamAssassin,
sends them to the daemon sa2dnsbld.pl which runs on the same host
or another. The daemon calculates the reputation score and writes
the IP address with its reputation score to the MySQL Database.
The worker script, sa2dnsblw.pl, runs periodic , e.g. every 15 minutes
and creates two blacklist files. One for IPv4 and one for IPv6 addresses.

To make this package work you need at least the following software:
  * SpamAssassin (>= 3.1.0)
  * MySQL (>= 5.6.3 or >=5.0 with mysql-udf-ipv6 Plugin)
  * rbldnsd (>= 0.996c = 0.996-ipv6)
  * cron

Please refer to the INSTALL file for an installation instruction.

Authors:
--------

Initial idea an release by: Frank Blechschmitt, FBIS
Further develoment by: Stefan Jakobs
