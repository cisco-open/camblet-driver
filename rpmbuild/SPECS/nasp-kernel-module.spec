Name:           nasp-kernel-module
Version:        0.1.0
Release:        1%{?dist}
Summary:        Kernel module for the NASP project.

License:        GPLv2
URL:            https://nasp.rocks
Source0:        %{name}-%{version}.orig.tar.xz

BuildRequires: make
BuildRequires: dkms

Requires:       

%description



%prep
%autosetup


%build
make

%configure
%make_build


%install
rm -rf $RPM_BUILD_ROOT
%make_install


%files
%license add-license-file-here
%doc add-docs-here



%changelog
* Mon Nov 27 2023 bmolnar
- 
