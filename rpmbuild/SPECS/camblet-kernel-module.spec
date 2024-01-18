Name:           camblet-driver
Version:        0.4.0
Release:        1%{?dist}
Summary:        Kernel module for the Camblet project.

License:        GPLv2
URL:            https://camblet.io
Source0:        %{name}-%{version}.tar.xz

Requires:       dkms
BuildArch:      noarch

%description
Kernel module for the Camblet project.

%files
/usr/src/camblet-%{version}

%install
# rm -rf %{buildroot}

# Create the destination directory in the build root
install -m 755 -d %{buildroot}/usr/src/camblet-%{version}

# # Copy the entire content of your Git repository to the build root
tar xvf %{_sourcedir}/camblet-driver-%{version}.tar.xz -C %{buildroot}/usr/src/camblet-%{version} --strip-components=1

%pre
PACKAGE_VERSION=$(dkms status -m camblet | head -1 | awk -F[/,] '{print $2}')

%post
PACKAGE_VERSION=%{version}

# Add the kernel module to the DKMS source control
dkms add -m camblet -v ${PACKAGE_VERSION} --force

# Build and install the kernel module against the current kernel version
dkms install -m camblet -v ${PACKAGE_VERSION} --force

%preun
PACKAGE_VERSION=%{version}

if sudo systemctl status camblet &>/dev/null ; then
    echo "Stopping camblet service"
    sudo systemctl stop camblet
fi

sudo modprobe -r camblet || true

if dkms status | grep camblet | grep "$PACKAGE_VERSION" ; then
    echo "Removing camblet-driver version $PACKAGE_VERSION"
    # dkms uninstall -m camblet -v $PACKAGE_VERSION --all
    dkms remove -m camblet -v $PACKAGE_VERSION --all
else
    echo "camblet-driver version $PACKAGE_VERSION not found in DKMS"
fi


%changelog
* Fri Dec 15 2023 Nasp maintainers <team@camblet.io> - 0.4.0-1
 - Create a new make target bump version (#128)

* Thu Dec 14 2023 Nandor Kracser <nandork@cisco.com> - 0.3.0-1
 - Initial build
