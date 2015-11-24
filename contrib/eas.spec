%global local_initrddir	%_initrddir
%global _sysconfdir	%_sysconfdir/eas/

Summary:	Enterprise Audit Shell
Name: eas
Version: 2.1.0
Release: 1%{dist}
License: LGPL
Group: Applications/System
URL: 		https://github.com/asquelt/eas
BuildRequires:	openssl-devel
Requires:	bash
Source0:        https://github.com/asquelt/%{name}/archive/%{version}.tar.gz
Source1:	eas.profile
Source2:	easd.init
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot

%description
Enterprise Audit Shell enables organizations to centrally control and audit
UNIX shell access. Audit logs are recorded and archived detailing shell input
and output, which can be played back and reviewed.

%package -n easd
Summary: 	Enterprise Audit Shell - Server
License: 	Open Software License
Group: 		Applications/System
Requires:	eash

%description -n easd
Enterprise Audit Shell enables organizations to centrally control and audit
UNIX shell access. Audit logs are recorded and archived detailing shell input
and output, which can be played back and reviewed.

This package contains the server portion.

%package -n eash
Summary: 	Enterprise Audit Shell - Client shell
License: 	GPL
Group: 		Shells

%description -n eash
Enterprise Audit Shell enables organizations to centrally control and audit
UNIX shell access. Audit logs are recorded and archived detailing shell input
and output, which can be played back and reviewed.

This package contains the client (shell) portion.

%prep
%setup -q
rm certs/mkcerts.noninteractive

%build
#%configure
#%make
%configure \
	--program-prefix="%{?_program_prefix}"
%{__make} %{?_smp_mflags}

%install
rm -rf %{buildroot}
install -d %{buildroot}/%{_sysconfdir}
install -d %{buildroot}/etc/profile.d
#-%-makeinstall
make install DESTDIR=%{buildroot}

install -d %{buildroot}//%{_sysconfdir}/certs/
chmod u+w %{buildroot}/%{_sysconfdir}/{certs/,}

install -m 755 %{SOURCE1} $RPM_BUILD_ROOT/etc/profile.d/eash.sh
install -d %{buildroot}/var/log/easd
install -d %{buildroot}/%{local_initrddir}
install -m 755 %{SOURCE2} %{buildroot}/%{local_initrddir}/easd

# these arent installing for some reason
install -m 644 src/root.pem %{buildroot}//%{_sysconfdir}/certs/
install -m 644 src/client.pem %{buildroot}//%{_sysconfdir}/certs/
install -m 644 src/server.pem %{buildroot}//%{_sysconfdir}/certs/



%pre -n easd
useradd easd -d /var/log/easd -s /bin/false || :

%post -n easd
/sbin/chkconfig --add easd

%preun -n easd
service easd stop 1>/dev/null 2>&1
/sbin/chkconfig --del easd


%clean
rm -rf $RPM_BUILD_ROOT

%files -n eash
%defattr(-,root,root,-)
%{_bindir}/eas*
%attr(644,root,root) %config(noreplace) %{_sysconfdir}/eash_config
%attr(644,root,root) %config(noreplace) %{_sysconfdir}/certs/root.pem
%attr(644,root,root) %config(noreplace) %{_sysconfdir}/certs/client.pem
/etc/profile.d/eash.sh

%files -n easd
%defattr(-,root,root,-)
%{_sbindir}/eas*
%attr(640,root,easd) %config(noreplace) %{_sysconfdir}/easd_config
%attr(700,easd,easd) /var/log/easd
%attr(640,root,easd) %config(noreplace) %{_sysconfdir}/certs/server.pem
%{local_initrddir}/easd
%dir %{_sysconfdir}/css
%config(noreplace) %attr(644,root,root) %{_sysconfdir}/css/*.css
%doc AUTHORS INSTALL README ChangeLog certs EAS_Admin_Guide.md


# Todo:
# -better default ssl paths?
# -cron scripts for backups (db and logs)?

%changelog
# Changelog for packages rebuilt on stable releases (leave it first):
%{!?_with_unstable:* %(LC_ALL=C date +"%a %b %d %Y") %{packager} %{version}-%{release}}
%{!?_with_unstable: - rebuild of %{version}-%{rel}}

* Thu Aug 23 2012 Andy Asquelt <asquelt+eas@gmail.com>
- sqlite segfault on lock fix

* Wed Aug 22 2012 Andy Asquelt <asquelt+eas@gmail.com>
- fixed eash config validation
- copyenv eash mode
- Makefile DESTDIR fix

* Fri Aug 17 2012 Andy Asquelt <asquelt+eas@gmail.com>
- fixed noninteractive issues (ie. rsync, scp)
- shutup eash mode
- minor fixes

* Wed Jun 28 2006 Buchan Milne <bgmilne@mandriva.org> 2.0.00-3mdk2007.0
- buildrequire openssl-devel

* Fri Jun 09 2006 Buchan Milne <bgmilne@mandriva.org> 2.0.00-2mdv2007.0
- add init script and user
- own log directory

* Fri May 19 2006 Buchan Milne <bgmilne@mandriva.org> 2.0.00-1mdk 
- switch from sudosh to eas

* Thu Apr 06 2006 Buchan Milne <bgmilne@mandriva.org> 1.8.2-1mdk
- initial mandriva package
