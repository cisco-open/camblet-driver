Name:           nasp-kernel-module
Version:        0.4.0
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
/usr/src/nasp-%{version}

%install
# rm -rf %{buildroot}

# Create the destination directory in the build root
install -m 755 -d %{buildroot}/usr/src/nasp-%{version}

# # Copy the entire content of your Git repository to the build root
tar xvf %{_sourcedir}/nasp-kernel-module-%{version}.tar.xz -C %{buildroot}/usr/src/nasp-%{version} --strip-components=1

%pre
PACKAGE_VERSION=$(dkms status -m nasp | head -1 | awk -F[/,] '{print $2}')

%post
PACKAGE_VERSION=%{version}

# Add the kernel module to the DKMS source control
dkms add -m nasp -v ${PACKAGE_VERSION} --force

# Build and install the kernel module against the current kernel version
dkms install -m nasp -v ${PACKAGE_VERSION} --force

%preun
PACKAGE_VERSION=%{version}

if sudo systemctl status nasp &>/dev/null ; then
    echo "Stopping nasp service"
    sudo systemctl stop nasp
fi

sudo modprobe -r nasp || true

if dkms status | grep nasp | grep "$PACKAGE_VERSION" ; then
    echo "Removing nasp-kernel-module version $PACKAGE_VERSION"
    # dkms uninstall -m nasp -v $PACKAGE_VERSION --all
    dkms remove -m nasp -v $PACKAGE_VERSION --all
else
    echo "nasp-kernel-module version $PACKAGE_VERSION not found in DKMS"
fi


%changelog
* Fri Dec 15 2023 Nasp maintainers <team@nasp.io> - 0.4.0-1
 - Create a new make target bump version (#128)

* Thu Dec 14 2023 Nandor Kracser <nandork@cisco.com> - 0.3.0-1
 - Initial build
