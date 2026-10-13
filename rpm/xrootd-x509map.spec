Name:      xrootd-x509map
Version:   1.0.0
Release:   1%{?dist}
Summary:   X509/VOMS to local and pool account mapping plugins for XRootD

License:   Apache-2.0
# Generated from:
# git archive --prefix=xrootd-x509map-%{version}/ -o ~/rpmbuild/SOURCES/xrootd-x509map-%{version}.tar.gz HEAD
Source0:   %{name}-%{version}.tar.gz

%define xrootd_current_major 5
%define xrootd_current_minor 4
%define xrootd_next_major 6

BuildRequires: cmake >= 3.16
BuildRequires: gcc-c++
BuildRequires: xrootd-server-devel >= 1:%{xrootd_current_major}.%{xrootd_current_minor}
BuildRequires: xrootd-server-devel <  1:%{xrootd_next_major}
BuildRequires: gtest-devel

Requires: xrootd-server >= 1:%{xrootd_current_major}.%{xrootd_current_minor}
Requires: xrootd-server <  1:%{xrootd_next_major}.0.0-1
Requires: xrootd-voms
Recommends: xrootd-multiuser

%description
Two XRootD plugins sharing one mapping core:
 * libXrdSecEntityX509Map (sec.entitylib): replaces the entity name of xroot gsi
   logins with the mapped account; never rejects a login.
 * libXrdAccX509Map (ofs.authlib ++): enforcement point for xroot and HTTPS.
   Maps the X509 DN (local DN map) or VOMS FQAN (voms-mapfile syntax) to an
   account, sets request.name for xrootd-multiuser, and denies unmapped
   X509 clients. Coexists with XrdAccSciTokens and XrdMacaroons.

%prep
%setup -q

%build
%cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_TESTS=ON
%cmake_build

%check
%ctest

%install
%cmake_install

%files
%license LICENSE NOTICE
%{_docdir}/%{name}
%{_libdir}/libXrdSecEntityX509Map-5.so
%{_libdir}/libXrdAccX509Map-5.so
%config(noreplace) %{_sysconfdir}/xrootd/x509map-local.map
%config(noreplace) %{_sysconfdir}/xrootd/x509map-voms.map
%config(noreplace) %{_sysconfdir}/xrootd/x509map-authdb
%config(noreplace) %{_sysconfdir}/xrootd/xrootd-multiuser-x509map.cfg

%changelog
* Tue Oct 13 2026 Geonmo Ryu <geonmo@kisti.re.kr> - 1.0.0-1
- Initial release
