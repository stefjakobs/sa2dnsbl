%if 0%{?suse_version}
   %define    init        init.d
%else # fedora
   %define    init        rc.d/init.d
%endif

Name:             sa2dnsbld
Version:          20140123
Release:          1%{?dist}
Summary:          Generate DNSBL list from SpamAssassin results

URL:              https://github.com/stefjakobs/sa2dnsbl
Group:            Productivity/Networking/Email/Utilities
License:          Apache-2.0
Source0:          %{name}-%{version}.tar.gz
BuildRoot:        %{_tmppath}/%{name}-%{version}-build
BuildArch:        noarch

BuildRequires:    perl spamassassin 
Requires:         perl(IO::Socket) perl(DBI) perl(NetAddr::IP)
Requires:         util-linux
%if 0%{?suse_version}
Requires(pre):    %fillup_prereq %insserv_prereq 
Recommends:       logrotate rsyslog
%if 0%{?suse_version} >= 1140
Requires:         perl-base
BuildRequires:    sysconfig perl-base 
%endif
%else # fedora
Requires(post):   chkconfig
Requires(preun):  chkconfig initscripts
Requires:         logrotate perl
%endif


%description
sa2dnsbl creates a DNS black hole list in real time. A client, which runs
as a SpamAssassin plugin, sends the score level of each message to server,
which calculates a reputation score and saves the results in a MySQL Database.

This Package contains the server and worker scripts.

%package -n perl-Mail-SpamAssassin-sa2dnsblc
Summary:          Generate DNSBL list from SpamAssassin results - client
Group:            Productivity/Networking/Email/Utilities
Requires:         perl-base perl(IO::Socket) 
Requires:         perl(Mail::SpamAssassin)

%description -n perl-Mail-SpamAssassin-sa2dnsblc
sa2dnsbl creates a DNS black hole list in real time. A client, which runs
as a SpamAssassin plugin, sends the score level of each message to server,
which calculates a reputation score and saves the results in a MySQL Database.

This Package contains the client (SpamAssassin plugin)


%prep
%setup -q


%build
pod2man sa2dnsbld.pl > sa2dnsbld.pl.1
pod2man sa2dnsblw.pl > sa2dnsblw.pl.1
pod2man sa2dnsblc.pm > sa2dnsblc.pm.3


%install
install -Dm755 sa2dnsbld.init.suse %{buildroot}/%{_sysconfdir}/%{init}/sa2dnsbld
%if 0%{?suse_version}
install -d -m755 $RPM_BUILD_ROOT/%{_sbindir}
ln -sf %{_sysconfdir}/%{init}/sa2dnsbld %{buildroot}/%{_sbindir}/rcsa2dnsbld
%endif
install -Dm755 ip2dnsbl.pl  %{buildroot}/%{_sbindir}/ip2dnsbl.pl
install -Dm644 sa2dnsblc.cf %{buildroot}/%{_sysconfdir}/mail/spamassassin/sa2dnsblc.cf
install -Dm644 sa2dnsblc.pm %{buildroot}/%{perl_vendorlib}/Mail/SpamAssassin/Plugin/sa2dnsblc.pm
install -Dm755 sa2dnsbld.pl %{buildroot}/%{_sbindir}/sa2dnsbld.pl
install -Dm644 sa2dnsbld.cf %{buildroot}/%{_sysconfdir}/sa2dnsbld.cf
install -Dm755 sa2dnsblw.pl %{buildroot}/%{_sbindir}/sa2dnsblw.pl
install -Dm644 sa2dnsbld.logrotate %{buildroot}/%{_sysconfdir}/logrotate.d/sa2dnsbld
install -Dm644 sa2dnsbld.rsyslog %{buildroot}/%{_sysconfdir}/rsyslog.d/10sa2dnsbld.conf

# install manpages
for sec in 1 3 ; do
   for man in *.${sec} ; do
      install -Dm644 ${man} %{buildroot}/%{_mandir}/man${sec}/${man}
   done
done

%post
%if 0%{?suse_version}
  %{fillup_and_insserv -y sa2dnsbld}
%else # fedora
  %if 0%{?fedora_version} > 15
    if [ $1 -eq 1 ] ; then # Initial installation 
      /bin/systemctl daemon-reload >/dev/null 2>&1 || :
    fi
  %else
    /sbin/chkconfig --add sa2dnsbld 
  %endif
%endif

%preun
%if 0%{?suse_version}
  %stop_on_removal sa2dnsbld 
%else # fedora
  if [ $1 -eq 0 ] ; then
    %if 0%{?fedora_version} > 15
      /bin/systemctl stop sa2dnsbld.service > /dev/null 2>&1 || :
      /bin/systemctl --no-reload disable sa2dnsbld.service > /dev/null 2>&1 || :
    %else
      /sbin/service sa2dnsbld stop >/dev/null 2>&1
      /sbin/chkconfig --del sa2dnsbld
    %endif
  fi
%endif

%postun
%if 0%{?suse_version}
  %restart_on_update sa2dnsbld 
  %insserv_cleanup
%else # fedora
  %if 0%{?fedora_version} > 15
    /bin/systemctl daemon-reload >/dev/null 2>&1 || :
    if [ $1 -ge 1 ] ; then # Package upgrade, not uninstall
      /bin/systemctl try-restart sa2dnsbld.service >/dev/null 2>&1 || :
    fi
  %else
    if [ $1 -ge 1 ] ; then
      /sbin/service sa2dnsbld condrestart >/dev/null 2>&1 || :
    fi
  %endif
%endif


%clean
%__rm -rf "%{buildroot}"


%files
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/sa2dnsbld.cf
%config(noreplace) %{_sysconfdir}/logrotate.d/sa2dnsbld
%config(noreplace) %{_sysconfdir}/rsyslog.d/10sa2dnsbld.conf
%config %{_sysconfdir}/%{init}/sa2dnsbld
%dir %{_sysconfdir}/rsyslog.d

%if 0%{?suse_version}
%{_sbindir}/rcsa2dnsbld
%endif
%{_sbindir}/*
%doc %{_mandir}/man1/sa2dnsbld.pl.1*
%doc %{_mandir}/man1/sa2dnsblw.pl.1*
%doc LICENSE README sa2dnsbl.sql

%files -n perl-Mail-SpamAssassin-sa2dnsblc
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/mail/spamassassin/sa2dnsblc.cf
%{perl_vendorlib}/Mail/
%doc %{_mandir}/man3/sa2dnsblc.pm.3*


%changelog
* Fri Jan 04 2013 Stefan Jakobs <projects AT localside.net> - 20120810
- Initial version
