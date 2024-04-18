Name:           camblet-driver
Version:        0.7.0
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
* Thu Apr 18 2024 Camblet maintainers <team@camblet.io> - 0.7.0-1
  - socket: fix leaking tcp_connection_contexts and opa objects (#214)
  - socket: fixes around camblet_get/setsockopt and recvmsg waiting and other things (#209)
  - Add read/write buffer lock during send/recvmsg (#207)
  - socket: fix for bearrssl pre-read data vs poll() (#205)
  - socket: propagate non-block error codes upwards (#202)
  - add missing memory allocation checks (#199)
  - socket: fix bearssl close order and locking (#195)
  - Support aes gcm and ccm ciphers (#196)
  - change spinlocks to mutexes (unification)
  - check spiffe id validity without regex
  - fixes use = as key value separator in labels fix uniqueness in rego
  - support workload id templates
  - rust: update crates and remove unused imports
  - Use camblet_sendpage in case of kTLS under kernel version 6.5 (#191)
  - handle -ERESTARTSYS during TLS handshake
  - fix trace log message size calculation
  - ci: use build matrix to test on 6.5 and 5.15 kernel as well (#182)
  - Add BearSSL tests (#178)
  - opa: builtins parsing and some linkage fixes (#176)
  - proper and verbose wasm module error printing (#175)
  - implement camblet_sendpage
  - HTTP header injection (#167)

* Tue Feb 27 2024 Camblet maintainers <team@camblet.io> - 0.6.0-1
  - parametrize VERBOSE builds (#171)
  - chore: do not use deprecated -EXTRA_CFLAGS (#169)
  - add http parser library (#158)
  - handle nil msghdr
  - fix missing param
  - call ensure_tls_handshake at getsockopt to avoid timing issues
  - move tls_info struct to header
  - support getting connection spiffe ids through socket option
  - Update socket.c
  - remove unused uuid header
  - refactor passthrough
  - socket: implement automatic TLS passthrough
  - trace: lock less if possible (#157)
  - address review comment
  - address review comments
  - use socket pointer instead of uuid
  - add tcp connection context to trace messages
  - tracing requests implementation
  - add one-way message type command
  - change how camblet runs in ci
  - run ci on all branches
  - Add changelog to rpm spec as well (#146)
  - fix prerm check
  - tls: harmonize spiffe id checks
  - Add setup-tls-perf target and openssl to smoketest (#142)
  - Escape special characters in bump version script (#144)

* Fri Dec 15 2023 Nasp maintainers <team@camblet.io> - 0.4.0-1
 - Create a new make target bump version (#128)

* Thu Dec 14 2023 Nandor Kracser <nandork@cisco.com> - 0.3.0-1
 - Initial build
