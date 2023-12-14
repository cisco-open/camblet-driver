Name:           nasp-kernel-module
Version:        0.3.0
Release:        1%{?dist}
Summary:        Kernel module for the NASP project.

License:        GPLv2
URL:            https://nasp.io
Source0:        %{name}-%{version}.tar.xz

Requires:       dkms
BuildArch:      noarch

%description
Kernel module for the NASP project.

%files
#%license LICENSE
/usr/src/nasp-%{version}

%install
# rm -rf %{buildroot}

# Create the destination directory in the build root
install -m 755 -d %{buildroot}/usr/src/nasp-%{version}

# # Copy the entire content of your Git repository to the build root
tar xvf %{_sourcedir}/nasp-kernel-module-%{version}.tar.xz -C %{buildroot}/usr/src/nasp-%{version} --strip-components=1 

%changelog
* Thu Dec 14 2023 Nandor Kracser <nandork@cisco.com> - 0.3.0-1
 - Initial build
