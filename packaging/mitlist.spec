Name:           mitlist
Version:        0.1.6
Release:        %{?rpm_release}%{!?rpm_release:ZWIEGNET.8.el10}
Summary:        List MIT Kerberos principals by principal type
License:        MIT
URL:            https://github.com/azwieg103/mitlist
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  krb5-devel
Requires:       krb5-workstation

%description
mitlist is a read-only command-line utility that lists MIT Kerberos
principals, grouping user and common service principals.

%prep
%autosetup -n %{name}

%build
%make_build

%install
rm -rf %{buildroot}
%make_install PREFIX=%{_prefix} BINDIR=%{_bindir}

%files
%{_bindir}/mitlist
%{_mandir}/man1/mitlist.1*

%changelog
* Fri Nov 20 2026 Andrew Zwieg <andyzwieg@gmail.com> - 0.1.6-ZWIEGNET.8.el10
- Retry failed kadmin principal-list requests up to five times with immediate service-ticket refresh.

* Fri Nov 20 2026 Andrew Zwieg <andyzwieg@gmail.com> - 0.1.6-ZWIEGNET.7.el10
- Pass the credential cache's actual default principal to kadmin with -p, avoiding its implicit /admin principal selection.

* Thu Nov 19 2026 Andrew Zwieg <andyzwieg@gmail.com> - 0.1.6-ZWIEGNET.1.el10
- Recognize common database, messaging, application, storage, and infrastructure service principal prefixes; omit empty categories.

* Thu Nov 19 2026 Andrew Zwieg <andyzwieg@gmail.com> - 0.1.5-ZWIEGNET.1.el10
- Display live Kerberos DNS SRV records, refresh a rejected admin service ticket once, and group MySQL/PostgreSQL principals separately.

* Thu Nov 19 2026 Andrew Zwieg <andyzwieg@gmail.com> - 0.1.4-ZWIEGNET.2.el10
- Add --info server discovery output, clean command output, and install the man page.

* Thu Nov 19 2026 ZWIEGNET <packages@zwiegnet.com> - 0.1.3-ZWIEGNET.1.el10
- Acquire the kadmin service ticket into the default cache before listing principals.

* Thu Nov 19 2026 ZWIEGNET <packages@zwiegnet.com> - 0.1.2-ZWIEGNET.1.el10
- Canonicalize the configured admin server hostname before invoking kadmin.

* Thu Nov 19 2026 ZWIEGNET <packages@zwiegnet.com> - 0.1.1-ZWIEGNET.1.el10
- Read admin_server from the active Kerberos configuration and use the default credential cache.

* Thu Nov 19 2026 ZWIEGNET <packages@zwiegnet.com> - 0.1.0-ZWIEGNET.1.el10
- Initial mitlist implementation.
