Name:           mitlist
Version:        0.1.0
Release:        %{?rpm_release}%{!?rpm_release:ZWIEGNET.1.el10}
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
%autosetup

%build
%make_build

%install
rm -rf %{buildroot}
%make_install PREFIX=%{_prefix} BINDIR=%{_bindir}

%files
%{_bindir}/mitlist

%changelog
* Thu Nov 19 2026 ZWIEGNET <packages@zwiegnet.com> - 0.1.0-ZWIEGNET.1.el10
- Initial mitlist implementation.
