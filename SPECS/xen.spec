%global package_speccommit 34db44d77f2f809d4dd3523faae86186987f2a01
%global usver 4.17.5
%global xsver 15
%global xsrel %{xsver}%{?xscount}%{?xshash}
# -*- rpm-spec -*-

# Commitish for Source0, required by tooling.
%global package_srccommit RELEASE-4.17.5

# Hypervisor release.  Should match the tag in the repository and would be in
# the Release field if it weren't for the %%{xsrel} automagic.
%global hv_rel 15

# Full hash from the HEAD commit of this repo during processing, usually
# provided by the environment.  Default to ??? if not set.

# Normally derived from the tag and provided by the environment.  May be a
# `git describe` when not building an from a tagged changeset.

%define base_dir  %{name}-%{version}

%define lp_devel_dir %{_usrsrc}/xen-%{version}-%{release}

# Prevent RPM adding Provides/Requires to lp-devel package, or mangling shebangs
%global __provides_exclude_from ^%{lp_devel_dir}/.*$
%global __requires_exclude_from ^%{lp_devel_dir}/.*$
%global __brp_mangle_shebangs_exclude_from ^%{lp_devel_dir}/.*$

%if 0%{?xenserver} < 9
%global __patch /usr/bin/patch --fuzz=0
%endif

Summary: Xen is a virtual machine monitor
Name:    xen
Version: 4.17.5
Release: %{?xsrel}.2%{?dist}
License: GPLv2 and LGPLv2 and MIT and Public Domain
URL:     https://www.xenproject.org
Source0: xen-4.17.5.tar.gz
Source1: sysconfig_kernel-xen
Source2: xl.conf
Source3: logrotate-xen-tools
Source5: gen_test_metadata.py
Patch0: build-tweaks.patch
Patch1: autoconf-libjson.patch
Patch2: configure-build.patch
Patch3: xenserver-configuration.patch
Patch4: coverity-model.patch
Patch5: backport-3ef9196234bd.patch
Patch6: backport-8d13862efa14.patch
Patch7: backport-d9606f9622bc.patch
Patch8: backport-06044960eae8.patch
Patch9: backport-4ae329d1d17b.patch
Patch10: backport-72064cfd1b23.patch
Patch11: backport-9a6bd1e7040f.patch
Patch12: backport-f65f18ec68ff.patch
Patch13: backport-962966190432.patch
Patch14: backport-1db4f1a3b75e.patch
Patch15: backport-a4e5191dc059.patch
Patch16: backport-b6eb7932a1c6.patch
Patch17: backport-d6654c63e76f.patch
Patch18: backport-d109962a2a05.patch
Patch19: backport-2aa9922c8983.patch
Patch20: backport-15bb4cccf50d.patch
Patch21: backport-ebf61f7699ad.patch
Patch22: backport-1d4361b041d7.patch
Patch23: backport-ddc5c1e0aafb.patch
Patch24: backport-3c31a87bcbdf.patch
Patch25: backport-015a7e3ab229.patch
Patch26: backport-ff95dae53e5e.patch
Patch27: backport-10acd21795a9.patch
Patch28: backport-60737ee9c590.patch
Patch29: backport-4a259353238d.patch
Patch30: backport-c4f9a3bad3f1.patch
Patch31: backport-cd8fc0e9f313.patch
Patch32: backport-c04b84ec74a4.patch
Patch33: backport-80ff09ffe2fc.patch
Patch34: backport-b5afdd2e1b73.patch
Patch35: backport-59bbbb823d3d.patch
Patch36: backport-e96f634b3dbb.patch
Patch37: backport-1d60c20260c7.patch
Patch38: backport-4e0b4ccfc504.patch
Patch39: backport-e51d31f79edc.patch
Patch40: backport-4a5577940240.patch
Patch41: backport-b2ea81d2b935.patch
Patch42: backport-07b167d17e84.patch
Patch43: backport-4af349a4047d.patch
Patch44: backport-7c7c436ccb9c.patch
Patch45: backport-e522c98c30a9.patch
Patch46: backport-5a8efb1bd092.patch
Patch47: backport-eaa324bfebcf.patch
Patch48: backport-f1e574fa6dea.patch
Patch49: backport-161c37d020a7.patch
Patch50: backport-b95a72bb5b2d.patch
Patch51: backport-5828b94b252c.patch
Patch52: backport-fb751d9a2431.patch
Patch53: backport-cb860a95a970.patch
Patch54: backport-3b5201e8cf87.patch
Patch55: backport-31c655497461.patch
Patch56: backport-694d79ed5aac.patch
Patch57: backport-defaf651631a.patch
Patch58: backport-43e863a02d81.patch
Patch59: backport-c81b287e00b1.patch
Patch60: backport-91d4159a34c4.patch
Patch61: backport-fc3090a47b21.patch
Patch62: backport-098e27578b0b.patch
Patch63: backport-484e88e31d14.patch
Patch64: backport-408a191b749b.patch
Patch65: backport-82f7f7be462d.patch
Patch66: backport-0742b0a081c2.patch
Patch67: backport-47342d8f490c.patch
Patch68: backport-8c01f267eff3.patch
Patch69: backport-58feb9e0ac70.patch
Patch70: backport-bc2cda8c5980.patch
Patch71: backport-63d077ede470.patch
Patch72: backport-88a9501a848a.patch
Patch73: backport-141db3325bf2.patch
Patch74: backport-b1fdd7d0e47e.patch
Patch75: backport-f29c2fb064ef.patch
Patch76: backport-e077d26621a3.patch
Patch77: backport-2c5f888204d9.patch
Patch78: backport-0902958b51a6.patch
Patch79: backport-a5823065558b.patch
Patch80: backport-9cf2b44c8eb5.patch
Patch81: backport-c2b804190437.patch
Patch82: backport-b9bf85b5fd91.patch
Patch83: backport-20d34c1e8240.patch
Patch84: backport-193126757d0f.patch
Patch85: backport-1cbeb625a355.patch
Patch86: backport-35fba21e512c.patch
Patch87: backport-4fa1c2ba00b0.patch
Patch88: backport-b623fde53740.patch
Patch89: backport-f30071fbb099.patch
Patch90: backport-28934a0748cd.patch
Patch91: backport-b6aa39f210d4.patch
Patch92: backport-916274cd6db8.patch
Patch93: backport-7bc02d1f08c5.patch
Patch94: backport-b44b7af7c8aa.patch
Patch95: backport-e48a3107f6e8.patch
Patch96: backport-60acdb3ab5fd.patch
Patch97: backport-5c61467f1658.patch
Patch98: backport-d3e954aab8fd.patch
Patch99: backport-aff7317d9fcb.patch
Patch100: backport-1f82dd558310.patch
Patch101: backport-aa057dbd3f36.patch
Patch102: backport-08f539a7fbb2.patch
Patch103: backport-5c05c4a2b261.patch
Patch104: backport-8eed56995dc6.patch
Patch105: backport-8974056f1f7a.patch
Patch106: backport-37b069fc3bb9.patch
Patch107: backport-e5865e780463.patch
Patch108: backport-1b7dfe88f5fb.patch
Patch109: backport-746df32732dc.patch
Patch110: backport-64d32b75e6e3.patch
Patch111: backport-94039d97e2e3.patch
Patch112: backport-c27c8922f2c6.patch
Patch113: backport-df2209f9b792.patch
Patch114: backport-b3a9037550df.patch
Patch115: backport-9de79317e844.patch
Patch116: backport-98ae35cab0e4.patch
Patch117: backport-72cad62abbaa.patch
Patch118: backport-024e7131be5c.patch
Patch119: backport-79fcc0e9d7df.patch
Patch120: backport-0e1bd15a1d5d.patch
Patch121: backport-4a7e71aa0851.patch
Patch122: backport-c852ca5c05f3.patch
Patch123: backport-66c8e9b76c61.patch
Patch124: backport-03e484a4f6fb.patch
Patch125: backport-6d5111b10e08.patch
Patch126: backport-64b21662b1b1.patch
Patch127: backport-9e30bd8f4a8c.patch
Patch128: backport-754a29cacf8e.patch
Patch129: backport-752ec9a9b195.patch
Patch130: backport-9b7d79388943.patch
Patch131: backport-b25b28ede1cb.patch
Patch132: backport-cc47813c4a2c.patch
Patch133: backport-5246924acf79.patch
Patch134: backport-8d336fcb6ea6.patch
Patch135: backport-6a039b050071.patch
Patch136: backport-3a28da8f4daf.patch
Patch137: backport-a184ac74f5e0.patch
Patch138: backport-dcbf8210f3f3.patch
Patch139: backport-2f413e22fa5e.patch
Patch140: backport-5c56361c618e.patch
Patch141: backport-28301682f492.patch
Patch142: backport-a1746cd4434d.patch
Patch143: backport-555866cb5600.patch
Patch144: backport-f29cc14de1d1.patch
Patch145: backport-2636fcdc15c7.patch
Patch146: backport-848b6bc8c9f3.patch
Patch147: backport-3fc44151d83d.patch
Patch148: backport-a2bbb140be9d.patch
Patch149: backport-b953a99da98d.patch
Patch150: backport-dd05d265b8ab.patch
Patch151: backport-1191ce954f64.patch
Patch152: backport-446a90345c89.patch
Patch153: backport-db6daa9bf411.patch
Patch154: backport-7ab695198123.patch
Patch155: backport-819c3cb186a8.patch
Patch156: backport-c11772277fe5.patch
Patch157: backport-c989ff614f6b.patch
Patch158: backport-8c12e47a5d3b.patch
Patch159: backport-b28b590d4a23.patch
Patch160: backport-9a474fcceccf.patch
Patch161: backport-4aae4452efee.patch
Patch162: backport-d444763f8ca5.patch
Patch163: backport-5873740e41ac.patch
Patch164: backport-50bbacacb814.patch
Patch165: backport-3125ca0da2d8.patch
Patch166: backport-2d779cabddfa.patch
Patch167: backport-61e10fc28ccd.patch
Patch168: backport-f77ef3443542.patch
Patch169: backport-07d7163334a7.patch
Patch170: backport-30f8fed68f3c.patch
Patch171: backport-10dc35c516f7.patch
Patch172: backport-3faf0866a330.patch
Patch173: backport-e7710dd843ba.patch
Patch174: backport-b0ca0f93f47c.patch
Patch175: backport-b473e5e212e4.patch
Patch176: backport-3e0bc4b50350.patch
Patch177: backport-9b0f0f6e2356.patch
Patch178: xsa470-4.17.patch
Patch179: x86-xen-cpuid-Fix-backports-of-new-features.patch
Patch180: x86-cpu-policy-Rearrange-guest_common_-_feature_adju.patch
Patch181: x86-cpu-policy-Infrastructure-for-CPUID-leaf-0x80000.patch
Patch182: x86-ucode-Digests-for-TSA-microcode.patch
Patch183: x86-idle-Rearrange-VERW-and-MONITOR-in-mwait_idle_wi.patch
Patch184: x86-spec-ctrl-Mitigate-Transitive-Scheduler-Attacks.patch
Patch185: 0006-x86-vpt-fix-injection-to-remote-vCPU.patch
Patch186: quirk-hp-gen8-rmrr.patch
Patch187: quirk-pci-phantom-function-devices.patch
Patch188: 0001-x86-hpet-Pre-cleanup.patch
Patch189: 0002-x86-hpet-Use-singe-apic-vector-rather-than-irq_descs.patch
Patch190: 0003-x86-hpet-Post-cleanup.patch
Patch191: 0002-libxc-retry-shadow-ops-if-EBUSY-is-returned.patch
Patch192: avoid-gnt-unmap-tlb-flush-if-not-accessed.patch
Patch193: 0001-x86-time-Don-t-use-EFI-s-GetTime-call.patch
Patch194: 0001-efi-Workaround-page-fault-during-runtime-service.patch
Patch195: 0001-libxl-Don-t-insert-PCI-device-into-xenstore-for-HVM-.patch
Patch196: livepatch-ignore-duplicate-new.patch
Patch197: 0001-lib-Add-a-generic-implementation-of-current_text_add.patch
Patch198: 0002-sched-Remove-dependency-on-__LINE__-for-release-buil.patch
Patch199: pygrub-Ignore-GRUB2-if-statements.patch
Patch200: libfsimage-Add-support-for-btrfs.patch
Patch201: quiet-broke-irq-affinity.patch
Patch202: xen-hide-AVX512-on-SKX-by-default.patch
Patch203: 0001-common-page_alloc-don-t-idle-scrub-before-microcode-.patch
Patch204: vpci-drop-const.patch
Patch205: pci-cache-memory-decode-bit.patch
Patch206: pci-cache-msi-x-enabled-bit.patch
Patch207: xen-tweak-cmdline-defaults.patch
Patch208: xen-tweak-debug-overhead.patch
Patch209: tweak-iommu-policy.patch
Patch210: tweak-sc-policy.patch
Patch211: disable-core-parking.patch
Patch212: remove-info-leak.patch
Patch213: 0001-Allocate-space-in-structs-pre-emptively-to-increase-.patch
Patch214: 0001-x86-mm-partially-revert-37201c62-make-logdirty-and-i.patch
Patch215: hitachi-driver-domain-ssid.patch
Patch216: install_targets_for_test_x86_emulator.patch
Patch217: xen-define-offsets-for-kdump.patch
Patch218: xen-scheduler-auto-privdom-weight.patch
Patch219: xen-hvm-disable-tsc-ramping.patch
Patch220: xen-default-cpufreq-governor-to-performance-on-intel.patch
Patch221: i8259-timers-pick-online-vcpu.patch
Patch222: revert-ca2eee92df44.patch
Patch223: libxc-cpuid-cores_per_socket.patch
Patch224: libxc-cpu-clear-deps.patch
Patch225: libxc-cpu-policies.patch
Patch226: max-featureset-compat.patch
Patch227: pygrub-add-disk-as-extra-group.patch
Patch228: pygrub-add-default-and-extra-args.patch
Patch229: pygrub-always-boot-default.patch
Patch230: pygrub-friendly-no-fs.patch
Patch231: pygrub-default-xenmobile-kernel.patch
Patch232: pygrub-blacklist-support.patch
Patch233: oem-bios-xensource.patch
Patch234: misc-log-guest-consoles.patch
Patch235: mixed-domain-runstates.patch
Patch236: xenguest.patch
Patch237: xen-vmdebug.patch
Patch238: oxenstore-censor-sensitive-data.patch
Patch239: oxenstore-large-packets.patch
Patch240: nvidia-vga.patch
Patch241: hvmloader-disable-pci-option-rom-loading.patch
Patch242: xen-force-software-vmcs-shadow.patch
Patch243: 0001-x86-vvmx-add-initial-PV-EPT-support-in-L0.patch
Patch244: use-msr-ll-instead-of-vmcs-efer.patch
Patch245: revert-4a7e71aa0851-partial.patch
Patch246: add-pv-iommu-headers.patch
Patch247: add-pv-iommu-local-domain-ops.patch
Patch248: add-pv-iommu-foreign-support.patch
Patch249: upstream-pv-iommu-tools.patch
Patch250: Add-PV-IOMMU-elf-note.patch
Patch251: allow-rombios-pci-config-on-any-host-bridge.patch
Patch252: gvt-g-hvmloader+rombios.patch
Patch253: xen-spec-ctrl-utility.patch
Patch254: vtpm-ppi-acpi-dsm.patch

# XCP-ng patches
Patch1000: 0001-xenguest-activate-nested-virt-when-requested.patch
Patch1001: 0001-x86-hvmloader-select-xen-platform-pci-MMIO-BAR-UC-or.patch
Patch1002: 0002-tools-golang-update-auto-generated-libxl-based-types.patch

ExclusiveArch: x86_64

BuildRequires: python3-devel
BuildRequires: python3-rpm-macros
%global py_sitearch %{python3_sitearch}
%global __python %{__python3}

%if 0%{?xenserver} < 9
# Interim, build Python2 bindings too
%global py2_compat 1
BuildRequires: python2-devel
BuildRequires: python2-rpm-macros
%endif

# These build dependencies are needed for building the xen.gz as
# well as live patches.
%define core_builddeps() %{lua:
    if tonumber(rpm.expand("0%{?xenserver}")) < 9 then
        deps = {
            'devtoolset-11-binutils',
            'devtoolset-11-gcc'
        }
    else
        deps = {
            'binutils',
            'gcc'
        }
    end

    -- For the banner
    table.insert(deps, 'figlet')

    -- For Kconfig
    table.insert(deps, 'bison')
    table.insert(deps, 'flex')

    for _, dep in ipairs(deps) do
        print(rpm.expand("%1") .. ': ' .. dep .. '\\n')
    end
}

%if 0%{?xenserver} < 9
%global _devtoolset_enable source /opt/rh/devtoolset-11/enable
%endif

%{core_builddeps BuildRequires}

BuildRequires: libtool

# For libxenguest (domain builder)
BuildRequires: bzip2-devel
BuildRequires: libzstd-devel
BuildRequires: lzo-devel
BuildRequires: xz-devel
BuildRequires: zlib-devel

# For libxl
BuildRequires: yajl-devel
BuildRequires: libuuid-devel
BuildRequires: perl-interpreter

# For libacpi
BuildRequires: iasl

# For libxenfsimage
BuildRequires: e2fsprogs-devel
BuildRequires: libblkid-devel

# For xentop
BuildRequires: ncurses-devel

# For RomBIOS
BuildRequires: dev86

# For ocaml components
BuildRequires: ocaml >= 4.13.1-3
BuildRequires: ocaml-findlib

# For manpages
BuildRequires: perl-podlators

# For xenguest
BuildRequires: json-c-devel
BuildRequires: libempserver-devel

%if 0%{?xenserver} < 9
BuildRequires: systemd
%else
BuildRequires: systemd-rpm-macros
%endif

# Need cov-analysis if coverity is enabled
%{?_cov_buildrequires}

%description
Xen Hypervisor.

%package hypervisor
Summary: The Xen Hypervisor
License: GPLv2
Requires(post): coreutils grep
%description hypervisor
This package contains the Xen Project Hypervisor combined with the XenServer patchqueue.

%package hypervisor-debuginfo
Summary: The Xen Hypervisor debug information
License: GPLv2
%description hypervisor-debuginfo
This package contains the Xen Hypervisor debug information.

%package tools
Summary: Xen Hypervisor general tools
License: GPLv2 and LGPLv2
Requires: xen-libs = %{version}
%description tools
This package contains the Xen Hypervisor general tools for all domains.

%package devel
Summary: The Xen Hypervisor public headers
License: MIT and Public Domain
%description devel
This package contains the Xen Hypervisor public header files.

%package libs
Summary: Xen Hypervisor general libraries
License: LGPLv2
%description libs
This package contains the Xen Hypervisor general libraries for all domains.

%package libs-devel
Summary: Xen Hypervisor general development libraries
License: LGPLv2
Requires: xen-libs = %{version}
Requires: xen-devel = %{version}
%description libs-devel
This package contains the Xen Hypervisor general development for all domains.

%package dom0-tools
Summary: Xen Hypervisor Domain 0 tools
License: GPLv2 and LGPLv2 and MIT
Requires: xen-dom0-libs = %{version}
Requires: xen-tools = %{version}
Obsoletes: xen-installer-files <= 4.13.5-10.42
Requires: edk2
Requires: ipxe
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
%description dom0-tools
This package contains the Xen Hypervisor control domain tools.

%package dom0-libs
Summary: Xen Hypervisor Domain 0 libraries
License: GPLv2 and LGPLv2 and MIT
Requires: xen-hypervisor = %{version}
Obsoletes: xen-installer-files <= 4.13.5-10.42
%description dom0-libs
This package contains the Xen Hypervisor control domain libraries.

%package dom0-libs-devel
Summary: Xen Hypervisor Domain 0 headers
License: GPLv2 and LGPLv2 and MIT
Requires: xen-devel = %{version}
Requires: xen-dom0-libs = %{version}
%description dom0-libs-devel
This package contains the Xen Hypervisor control domain headers.

%package ocaml-libs
Summary: Xen Hypervisor ocaml libraries
License: LGPLv2
Requires: xen-dom0-libs = %{version}
%description ocaml-libs
This package contains the Xen Hypervisor ocaml libraries.

%package ocaml-devel
Summary: Xen Hypervisor ocaml headers
License: LGPLv2
Requires: xen-ocaml-libs = %{version}
Requires: xen-dom0-libs-devel = %{version}
%description ocaml-devel
This package contains the Xen Hypervisor ocaml headers.

%package dom0-tests
Summary: Xen Hypervisor tests
License: GPLv2
%description dom0-tests
This package contains test cases for the Xen Hypervisor.

%package lp-devel_%{version}_%{release}
License: GPLv2
Summary: Development package for building livepatches
%{core_builddeps Requires}
%description lp-devel_%{version}_%{release}
Contains the prepared source files, config, and xen-syms for building live
patches against base version %{version}-%{release}.

%prep
%autosetup -p1
%{?_cov_prepare}
%{?_coverity:cp misc/coverity/nodefs.h %{_cov_dir}/config/user_nodefs.h}
%{?_cov_make_model:%{_cov_make_model misc/coverity/model.c}}

base_cset=$(sed -ne 's/Changeset: \(.*\)/\1/p' < .gitarchive-info)
pq_cset="%{package_speccommit}"
echo "${base_cset:0:12}, pq ${pq_cset:0:12}" > .scmversion

%build

%{?_devtoolset_enable}
export XEN_TARGET_ARCH=%{_arch}
export PYTHON="%{__python}"

%configure --disable-qemu-traditional \
           --disable-seabios \
           --disable-stubdom \
           --disable-xsmpolicy \
           --disable-pvshim \
           --enable-rombios \
           --enable-systemd \
           --with-xenstored=oxenstored \
           --with-system-qemu=%{_libdir}/xen/bin/qemu-system-i386 \
           --with-system-ipxe=/usr/share/ipxe/ipxe.bin \
           --with-system-ovmf=/usr/share/edk2/OVMF-release.fd

# Take a snapshot of the configured source tree for livepatches
mkdir ../livepatch-src
cp -a . ../livepatch-src/
echo %{?_devtoolset_enable} > ../livepatch-src/prepare-build

# Build tools and man pages
%{?_cov_wrap} %{make_build} build-tools
%{make_build} -C docs man-pages

%if 0%{?py2_compat}
# Interim python2 bindings too
%{make_build} DESTDIR=%{buildroot} PYTHON=python2 -C tools/python
%{make_build} DESTDIR=%{buildroot} PYTHON=python2 -C tools/pygrub
%endif

# The hypervisor build system can't cope with RPM's {C,LD}FLAGS
unset CFLAGS
unset LDFLAGS

build_xen () { # $1=vendorversion $2=buildconfig $3=outdir $4=cov
    local mk ver cov

    [ -n "$1" ] && ver="XEN_VENDORVERSION=$1"
    [ -n "$4" ] && cov="%{?_cov_wrap}"

    mk="$cov %{make_build} -C xen $ver O=$3"

    mkdir xen/$3 && cp -a buildconfigs/$2 xen/$3/.config
    $mk olddefconfig
    $mk build MAP
}

# Builds of Xen
build_xen -%{hv_rel}   config-release         build-xen-release
build_xen -%{hv_rel}-d config-debug           build-xen-debug      cov
build_xen ""           config-pvshim          build-shim


%install

%{?_devtoolset_enable}
export XEN_TARGET_ARCH=%{_arch}
export PYTHON="%{__python}"

# The existence of this directory causes ocamlfind to put things in it
mkdir -p %{buildroot}%{_libdir}/ocaml/stublibs

%if 0%{?py2_compat}
# Interim python2 bindings.  Must be installed ahead of the main install-tools
# so the Python3 scripts take priority.
%{make_build} DESTDIR=%{buildroot} PYTHON=python2 install -C tools/python
%{make_build} DESTDIR=%{buildroot} PYTHON=python2 install -C tools/pygrub
%endif

# Install tools and man pages
%{make_build} DESTDIR=%{buildroot} install-tools
%{make_build} DESTDIR=%{buildroot} -C docs install-man-pages

# Install artefacts for livepatches
%{__install} -p -D -m 644 xen/build-xen-release/xen-syms %{buildroot}%{lp_devel_dir}/xen-syms
%{__install} -p -D -m 644 xen/build-xen-debug/xen-syms %{buildroot}%{lp_devel_dir}/xen-syms-d
cp -a ../livepatch-src/. %{buildroot}%{lp_devel_dir}

# Install release & debug Xen
install_xen () { # $1=vendorversion $2=outdir
    %{__install} -p -D -m 644 xen/$2/xen.gz     %{buildroot}/boot/xen-%{version}$1.gz
    %{__install} -p -D -m 644 xen/$2/System.map %{buildroot}/boot/xen-%{version}$1.map
    %{__install} -p -D -m 644 xen/$2/.config    %{buildroot}/boot/xen-%{version}$1.config
    %{__install} -p -D -m 644 xen/$2/xen-syms   %{buildroot}/boot/xen-syms-%{version}$1
}
install_xen -%{hv_rel}   build-xen-release
install_xen -%{hv_rel}-d build-xen-debug

# Install release shim
%{__install} -p -D -m 644 xen/build-shim/xen      %{buildroot}%{_libexecdir}/%{name}/boot/xen-shim
%{__install} -p -D -m 644 xen/build-shim/xen-syms %{buildroot}%{_libexecdir}/%{name}/boot/xen-shim-syms

# Build test case metadata
%{__python} %{SOURCE5} -i %{buildroot}%{_libexecdir}/%{name} -o %{buildroot}%{_datadir}/xen-dom0-tests-metadata.json

%{__install} -D -m 644 %{SOURCE1} %{buildroot}%{_sysconfdir}/sysconfig/kernel-xen
%{__install} -D -m 644 %{SOURCE2} %{buildroot}%{_sysconfdir}/xen/xl.conf
%{__install} -D -m 644 %{SOURCE3} %{buildroot}%{_sysconfdir}/logrotate.d/xen-tools
%{?_cov_install}

%files hypervisor
/boot/%{name}-%{version}-%{hv_rel}.gz
/boot/%{name}-%{version}-%{hv_rel}.map
/boot/%{name}-%{version}-%{hv_rel}.config
/boot/%{name}-%{version}-%{hv_rel}-d.gz
/boot/%{name}-%{version}-%{hv_rel}-d.map
/boot/%{name}-%{version}-%{hv_rel}-d.config
%config %{_sysconfdir}/sysconfig/kernel-xen
%license COPYING
%ghost %attr(0644,root,root) %{_sysconfdir}/sysconfig/kernel-xen-args

%files hypervisor-debuginfo
/boot/%{name}-syms-%{version}-%{hv_rel}
/boot/%{name}-syms-%{version}-%{hv_rel}-d
%{_libexecdir}/%{name}/boot/xen-shim-syms

%files tools
%{_bindir}/xenstore
%{_bindir}/xenstore-chmod
%{_bindir}/xenstore-control
%{_bindir}/xenstore-exists
%{_bindir}/xenstore-list
%{_bindir}/xenstore-ls
%{_bindir}/xenstore-read
%{_bindir}/xenstore-rm
%{_bindir}/xenstore-watch
%{_bindir}/xenstore-write

%files devel
%{_includedir}/%{name}/COPYING
%{_includedir}/%{name}/arch-arm.h
%{_includedir}/%{name}/arch-arm/hvm/save.h
%{_includedir}/%{name}/arch-arm/smccc.h
%{_includedir}/%{name}/arch-x86/cpuid.h
%{_includedir}/%{name}/arch-x86/cpufeatureset.h
%{_includedir}/%{name}/arch-x86/guest-acpi.h
%{_includedir}/%{name}/arch-x86/hvm/save.h
%{_includedir}/%{name}/arch-x86/hvm/start_info.h
%{_includedir}/%{name}/arch-x86/pmu.h
%{_includedir}/%{name}/arch-x86/xen-mca.h
%{_includedir}/%{name}/arch-x86/xen-x86_32.h
%{_includedir}/%{name}/arch-x86/xen-x86_64.h
%{_includedir}/%{name}/arch-x86/xen.h
%{_includedir}/%{name}/arch-x86_32.h
%{_includedir}/%{name}/arch-x86_64.h
%{_includedir}/%{name}/argo.h
%{_includedir}/%{name}/callback.h
%{_includedir}/%{name}/device_tree_defs.h
%{_includedir}/%{name}/dom0_ops.h
%{_includedir}/%{name}/domctl.h
%{_includedir}/%{name}/elfnote.h
%{_includedir}/%{name}/errno.h
%{_includedir}/%{name}/event_channel.h
%{_includedir}/%{name}/features.h
%{_includedir}/%{name}/foreign/arm32.h
%{_includedir}/%{name}/foreign/arm64.h
%{_includedir}/%{name}/foreign/x86_32.h
%{_includedir}/%{name}/foreign/x86_64.h
%{_includedir}/%{name}/grant_table.h
%{_includedir}/%{name}/hvm/dm_op.h
%{_includedir}/%{name}/hvm/e820.h
%{_includedir}/%{name}/hvm/hvm_info_table.h
%{_includedir}/%{name}/hvm/hvm_op.h
%{_includedir}/%{name}/hvm/hvm_vcpu.h
%{_includedir}/%{name}/hvm/hvm_xs_strings.h
%{_includedir}/%{name}/hvm/ioreq.h
%{_includedir}/%{name}/hvm/params.h
%{_includedir}/%{name}/hvm/pvdrivers.h
%{_includedir}/%{name}/hvm/save.h
%{_includedir}/%{name}/hypfs.h
%{_includedir}/%{name}/io/9pfs.h
%{_includedir}/%{name}/io/blkif.h
%{_includedir}/%{name}/io/cameraif.h
%{_includedir}/%{name}/io/console.h
%{_includedir}/%{name}/io/displif.h
%{_includedir}/%{name}/io/fbif.h
%{_includedir}/%{name}/io/fsif.h
%{_includedir}/%{name}/io/kbdif.h
%{_includedir}/%{name}/io/libxenvchan.h
%{_includedir}/%{name}/io/netif.h
%{_includedir}/%{name}/io/pciif.h
%{_includedir}/%{name}/io/protocols.h
%{_includedir}/%{name}/io/pvcalls.h
%{_includedir}/%{name}/io/ring.h
%{_includedir}/%{name}/io/sndif.h
%{_includedir}/%{name}/io/tpmif.h
%{_includedir}/%{name}/io/usbif.h
%{_includedir}/%{name}/io/vscsiif.h
%{_includedir}/%{name}/io/xenbus.h
%{_includedir}/%{name}/io/xs_wire.h
%{_includedir}/%{name}/kexec.h
%{_includedir}/%{name}/memory.h
%{_includedir}/%{name}/nmi.h
%{_includedir}/%{name}/physdev.h
%{_includedir}/%{name}/platform.h
%{_includedir}/%{name}/pmu.h
%{_includedir}/%{name}/pv-iommu.h
%{_includedir}/%{name}/sched.h
%{_includedir}/%{name}/sys/evtchn.h
%{_includedir}/%{name}/sys/gntalloc.h
%{_includedir}/%{name}/sys/gntdev.h
%{_includedir}/%{name}/sys/privcmd.h
%{_includedir}/%{name}/sys/xenbus_dev.h
%{_includedir}/%{name}/sysctl.h
%{_includedir}/%{name}/tmem.h
%{_includedir}/%{name}/trace.h
%{_includedir}/%{name}/vcpu.h
%{_includedir}/%{name}/version.h
%{_includedir}/%{name}/vm_event.h
%{_includedir}/%{name}/xen-compat.h
%{_includedir}/%{name}/xen.h
%{_includedir}/%{name}/xencomm.h
%{_includedir}/%{name}/xenoprof.h
%{_includedir}/%{name}/xsm/flask_op.h

%files libs
%{_libdir}/libxenevtchn.so.1
%{_libdir}/libxenevtchn.so.1.2
%{_libdir}/libxengnttab.so.1
%{_libdir}/libxengnttab.so.1.2
%{_libdir}/libxenstore.so.4
%{_libdir}/libxenstore.so.4.0
%{_libdir}/libxentoolcore.so.1
%{_libdir}/libxentoolcore.so.1.0
%{_libdir}/libxentoollog.so.1
%{_libdir}/libxentoollog.so.1.0
%{_libdir}/libxenvchan.so.4.17
%{_libdir}/libxenvchan.so.4.17.0

%files libs-devel

# Common
%{_includedir}/xen_list.h

# Lib Xen Evtchn
%{_includedir}/xenevtchn.h
%{_libdir}/libxenevtchn.a
%{_libdir}/libxenevtchn.so
%{_libdir}/pkgconfig/xenevtchn.pc

# Lib Xen Gnttab
%{_includedir}/xengnttab.h
%{_libdir}/libxengnttab.a
%{_libdir}/libxengnttab.so
%{_libdir}/pkgconfig/xengnttab.pc

# Lib XenStore
%{_includedir}/xenstore.h
%{_includedir}/xenstore_lib.h
%{_libdir}/libxenstore.a
%{_libdir}/libxenstore.so
%{_libdir}/pkgconfig/xenstore.pc
# Legacy XenStore header files, excluded to discourage their use
%exclude %{_includedir}/xs.h
%exclude %{_includedir}/xenstore-compat/xs.h
%exclude %{_includedir}/xs_lib.h
%exclude %{_includedir}/xenstore-compat/xs_lib.h

%{_includedir}/xentoolcore.h
%{_libdir}/libxentoolcore.a
%{_libdir}/libxentoolcore.so
%{_libdir}/pkgconfig/xentoolcore.pc

%{_includedir}/xentoollog.h
%{_libdir}/libxentoollog.a
%{_libdir}/libxentoollog.so
%{_libdir}/pkgconfig/xentoollog.pc

# Lib Xen Vchan
%{_includedir}/libxenvchan.h
%{_libdir}/libxenvchan.a
%{_libdir}/libxenvchan.so
%{_libdir}/pkgconfig/xenvchan.pc

%files dom0-tools
%{_sysconfdir}/bash_completion.d/xl
%exclude %{_sysconfdir}/rc.d/init.d/xencommons
%exclude %{_sysconfdir}/rc.d/init.d/xendomains
%exclude %{_sysconfdir}/rc.d/init.d/xendriverdomain
%exclude %{_sysconfdir}/sysconfig/xendomains
%exclude %{_sysconfdir}/rc.d/init.d/xen-watchdog
%config %{_sysconfdir}/logrotate.d/xen-tools
%config %{_sysconfdir}/sysconfig/xencommons
%config %{_sysconfdir}/xen/oxenstored.conf
%{_sysconfdir}/xen/scripts/block
%{_sysconfdir}/xen/scripts/block-common.sh
%{_sysconfdir}/xen/scripts/block-drbd-probe
%{_sysconfdir}/xen/scripts/block-dummy
%{_sysconfdir}/xen/scripts/block-enbd
%{_sysconfdir}/xen/scripts/block-iscsi
%{_sysconfdir}/xen/scripts/block-nbd
%{_sysconfdir}/xen/scripts/block-tap
%{_sysconfdir}/xen/scripts/colo-proxy-setup
%{_sysconfdir}/xen/scripts/external-device-migrate
%{_sysconfdir}/xen/scripts/hotplugpath.sh
%{_sysconfdir}/xen/scripts/launch-xenstore
%{_sysconfdir}/xen/scripts/locking.sh
%{_sysconfdir}/xen/scripts/logging.sh
%{_sysconfdir}/xen/scripts/vif-bridge
%{_sysconfdir}/xen/scripts/vif-common.sh
%{_sysconfdir}/xen/scripts/vif-nat
%{_sysconfdir}/xen/scripts/vif-openvswitch
%{_sysconfdir}/xen/scripts/vif-route
%{_sysconfdir}/xen/scripts/vif-setup
%{_sysconfdir}/xen/scripts/vscsi
%{_sysconfdir}/xen/scripts/xen-hotplug-common.sh
%{_sysconfdir}/xen/scripts/xen-network-common.sh
%{_sysconfdir}/xen/scripts/xen-script-common.sh
%exclude %{_sysconfdir}/%{name}/cpupool
%exclude %{_sysconfdir}/%{name}/README
%exclude %{_sysconfdir}/%{name}/xlexample.hvm
%exclude %{_sysconfdir}/%{name}/xlexample.pvhlinux
%exclude %{_sysconfdir}/%{name}/xlexample.pvlinux
%config %{_sysconfdir}/xen/xl.conf
%{_bindir}/pygrub
%{_bindir}/vchan-socket-proxy
%{_bindir}/xen-cpuid
%{_bindir}/xen-detect
%{_bindir}/xenalyze
%exclude %{_bindir}/xencons
%{_bindir}/xencov_split
%{_bindir}/xentrace_format

# Pygrub python libs
%{py_sitearch}/grub/
%{py_sitearch}/xenfsimage.cpython*.so
%{py_sitearch}/pygrub-0.7-py*.egg-info

%if 0%{?py2_compat}
%{python2_sitearch}/grub/
%{python2_sitearch}/xenfsimage.so
%{python2_sitearch}/pygrub-0.7-py*.egg-info
%endif

# Xen python libs
%{py_sitearch}/xen-3.0-py*.egg-info
%{py_sitearch}/xen/

%if 0%{?py2_compat}
%{python2_sitearch}/xen-3.0-py*.egg-info
%{python2_sitearch}/xen/
%endif

%{_libexecdir}/%{name}/bin/convert-legacy-stream
%{_libexecdir}/%{name}/bin/init-xenstore-domain
%{_libexecdir}/%{name}/bin/libxl-save-helper
%{_libexecdir}/%{name}/bin/lsevtchn
%{_libexecdir}/%{name}/bin/pygrub
%{_libexecdir}/%{name}/bin/readnotes
%{_libexecdir}/%{name}/bin/verify-stream-v2
%{_libexecdir}/%{name}/bin/xen-init-dom0
%{_libexecdir}/%{name}/bin/xenconsole
%{_libexecdir}/%{name}/bin/xenctx
%{_libexecdir}/%{name}/bin/xendomains
%{_libexecdir}/%{name}/bin/xenguest
%{_libexecdir}/%{name}/bin/xenpaging
%exclude %{_libexecdir}/%{name}/bin/xenpvnetboot
%{_libexecdir}/%{name}/boot/hvmloader
%{_libexecdir}/%{name}/boot/xen-shim
%{_sbindir}/flask-get-bool
%{_sbindir}/flask-getenforce
%{_sbindir}/flask-label-pci
%{_sbindir}/flask-loadpolicy
%{_sbindir}/flask-set-bool
%{_sbindir}/flask-setenforce
%{_sbindir}/gdbsx
%{_sbindir}/oxenstored
%{_sbindir}/xen-access
%{_sbindir}/xen-diag
%{_sbindir}/xen-hptool
%{_sbindir}/xen-hvmcrash
%{_sbindir}/xen-hvmctx
%{_sbindir}/xen-kdd
%{_sbindir}/xen-livepatch
%{_sbindir}/xen-lowmemd
%{_sbindir}/xen-mceinj
%{_sbindir}/xen-memshare
%{_sbindir}/xen-mfndump
%{_sbindir}/xen-spec-ctrl
%{_sbindir}/xen-ucode
%{_sbindir}/xen-vmdebug
%{_sbindir}/xen-vmtrace
%{_sbindir}/xenbaked
%{_sbindir}/xenconsoled
%{_sbindir}/xencov
%{_sbindir}/xenhypfs
%{_sbindir}/xenmon
%{_sbindir}/xenperf
%{_sbindir}/xenpm
%{_sbindir}/xenpmd
%{_sbindir}/xenstored
%{_sbindir}/xentop
%{_sbindir}/xentrace
%{_sbindir}/xentrace_setmask
%{_sbindir}/xentrace_setsize
%{_sbindir}/xenwatchdogd
%{_sbindir}/xl
%exclude %{_sbindir}/xenlockprof
%{_mandir}/man1/xenhypfs.1.gz
%{_mandir}/man1/xentop.1.gz
%{_mandir}/man1/xentrace_format.1.gz
%{_mandir}/man1/xenstore-chmod.1.gz
%{_mandir}/man1/xenstore-ls.1.gz
%{_mandir}/man1/xenstore-read.1.gz
%{_mandir}/man1/xenstore-write.1.gz
%{_mandir}/man1/xenstore.1.gz
%{_mandir}/man1/xl.1.gz
%{_mandir}/man5/xl-disk-configuration.5.gz
%{_mandir}/man5/xl-network-configuration.5.gz
%{_mandir}/man5/xl-pci-configuration.5.gz
%{_mandir}/man5/xl.cfg.5.gz
%{_mandir}/man5/xl.conf.5.gz
%{_mandir}/man5/xlcpupool.cfg.5.gz
%{_mandir}/man7/xen-pci-device-reservations.7.gz
%{_mandir}/man7/xen-pv-channel.7.gz
%{_mandir}/man7/xen-tscmode.7.gz
%{_mandir}/man7/xl-numa-placement.7.gz
%exclude %{_mandir}/man7/xen-vtpm.7.gz
%exclude %{_mandir}/man7/xen-vtpmmgr.7.gz
%{_mandir}/man8/xentrace.8.gz
%dir /var/lib/xen
%dir /var/log/xen
%{_unitdir}/proc-xen.mount
%{_unitdir}/xen-init-dom0.service
%{_unitdir}/xen-watchdog.service
%{_unitdir}/xenconsoled.service
%{_unitdir}/xenstored.service
%exclude %{_prefix}/lib/modules-load.d/xen.conf
%exclude %{_unitdir}/xen-qemu-dom0-disk-backend.service
%exclude %{_unitdir}/xendomains.service
%exclude %{_unitdir}/xendriverdomain.service

%files dom0-libs
%{_libdir}/libxencall.so.1
%{_libdir}/libxencall.so.1.3
%{_libdir}/libxenctrl.so.4.17
%{_libdir}/libxenctrl.so.4.17.0
%{_libdir}/libxendevicemodel.so.1
%{_libdir}/libxendevicemodel.so.1.4
%{_libdir}/libxenforeignmemory.so.1
%{_libdir}/libxenforeignmemory.so.1.4
%{_libdir}/libxenfsimage.so.4.17
%{_libdir}/libxenfsimage.so.4.17.0
%{_libdir}/libxenguest.so.4.17
%{_libdir}/libxenguest.so.4.17.0
%{_libdir}/libxenhypfs.so.1
%{_libdir}/libxenhypfs.so.1.0
%{_libdir}/libxenlight.so.4.17
%{_libdir}/libxenlight.so.4.17.0
%{_libdir}/libxenstat.so.4.17
%{_libdir}/libxenstat.so.4.17.0
%{_libdir}/libxlutil.so.4.17
%{_libdir}/libxlutil.so.4.17.0
%{_libdir}/xenfsimage/btrfs/fsimage.so
%{_libdir}/xenfsimage/ext2fs-lib/fsimage.so
%{_libdir}/xenfsimage/fat/fsimage.so
%{_libdir}/xenfsimage/iso9660/fsimage.so
%{_libdir}/xenfsimage/reiserfs/fsimage.so
%{_libdir}/xenfsimage/ufs/fsimage.so
%{_libdir}/xenfsimage/xfs/fsimage.so
%{_libdir}/xenfsimage/zfs/fsimage.so

%files dom0-libs-devel
%{_includedir}/xenfsimage.h
%{_includedir}/xenfsimage_grub.h
%{_includedir}/xenfsimage_plugin.h
%{_libdir}/libxenfsimage.so

%{_includedir}/xencall.h
%{_libdir}/libxencall.a
%{_libdir}/libxencall.so
%{_libdir}/pkgconfig/xencall.pc

%{_includedir}/xenctrl.h
%{_includedir}/xenctrl_compat.h
%{_libdir}/libxenctrl.a
%{_libdir}/libxenctrl.so
%{_libdir}/pkgconfig/xencontrol.pc

%{_includedir}/xendevicemodel.h
%{_libdir}/libxendevicemodel.a
%{_libdir}/libxendevicemodel.so
%{_libdir}/pkgconfig/xendevicemodel.pc

%{_includedir}/xenforeignmemory.h
%{_libdir}/libxenforeignmemory.a
%{_libdir}/libxenforeignmemory.so
%{_libdir}/pkgconfig/xenforeignmemory.pc

%{_includedir}/xenguest.h
%{_libdir}/libxenguest.a
%{_libdir}/libxenguest.so
%{_libdir}/pkgconfig/xenguest.pc

%{_includedir}/xenhypfs.h
%{_libdir}/libxenhypfs.a
%{_libdir}/libxenhypfs.so
%{_libdir}/pkgconfig/xenhypfs.pc

%{_includedir}/_libxl_types.h
%{_includedir}/_libxl_types_json.h
%{_includedir}/libxl.h
%{_includedir}/libxl_event.h
%{_includedir}/libxl_json.h
%{_includedir}/libxl_utils.h
%{_includedir}/libxl_uuid.h
%{_includedir}/libxlutil.h
%{_libdir}/libxenlight.a
%{_libdir}/libxenlight.so
%{_libdir}/libxlutil.a
%{_libdir}/libxlutil.so
%{_libdir}/pkgconfig/xenlight.pc
%{_libdir}/pkgconfig/xlutil.pc

%{_includedir}/xenstat.h
%{_libdir}/libxenstat.a
%{_libdir}/libxenstat.so
%{_libdir}/pkgconfig/xenstat.pc

%files ocaml-libs
%exclude %{_libdir}/ocaml/stublibs/dllxenbus_stubs.so
%exclude %{_libdir}/ocaml/stublibs/dllxenbus_stubs.so.owner
%{_libdir}/ocaml/stublibs/dllxenctrl_stubs.so
%{_libdir}/ocaml/stublibs/dllxenctrl_stubs.so.owner
%{_libdir}/ocaml/stublibs/dllxeneventchn_stubs.so
%{_libdir}/ocaml/stublibs/dllxeneventchn_stubs.so.owner
%{_libdir}/ocaml/stublibs/dllxenmmap_stubs.so
%{_libdir}/ocaml/stublibs/dllxenmmap_stubs.so.owner
%exclude %{_libdir}/ocaml/xenbus/META
%exclude %{_libdir}/ocaml/xenbus/xenbus.cma
%exclude %{_libdir}/ocaml/xenbus/xenbus.cmo
%{_libdir}/ocaml/xenctrl/META
%{_libdir}/ocaml/xenctrl/xenctrl.cma
%{_libdir}/ocaml/xeneventchn/META
%{_libdir}/ocaml/xeneventchn/xeneventchn.cma
%{_libdir}/ocaml/xenmmap/META
%{_libdir}/ocaml/xenmmap/xenmmap.cma
%exclude %{_libdir}/ocaml/xenstore/META
%exclude %{_libdir}/ocaml/xenstore/xenstore.cma
%exclude %{_libdir}/ocaml/xenstore/xenstore.cmo

%files ocaml-devel
%exclude %{_libdir}/ocaml/xenbus/libxenbus_stubs.a
%exclude %{_libdir}/ocaml/xenbus/xenbus.a
%exclude %{_libdir}/ocaml/xenbus/xenbus.cmi
%exclude %{_libdir}/ocaml/xenbus/xenbus.cmx
%exclude %{_libdir}/ocaml/xenbus/xenbus.cmxa
%{_libdir}/ocaml/xenctrl/libxenctrl_stubs.a
%{_libdir}/ocaml/xenctrl/xenctrl.a
%{_libdir}/ocaml/xenctrl/xenctrl.cmi
%{_libdir}/ocaml/xenctrl/xenctrl.cmx
%{_libdir}/ocaml/xenctrl/xenctrl.cmxa
%{_libdir}/ocaml/xeneventchn/libxeneventchn_stubs.a
%{_libdir}/ocaml/xeneventchn/xeneventchn.a
%{_libdir}/ocaml/xeneventchn/xeneventchn.cmi
%{_libdir}/ocaml/xeneventchn/xeneventchn.cmx
%{_libdir}/ocaml/xeneventchn/xeneventchn.cmxa
%{_libdir}/ocaml/xenmmap/libxenmmap_stubs.a
%{_libdir}/ocaml/xenmmap/xenmmap.a
%{_libdir}/ocaml/xenmmap/xenmmap.cmi
%{_libdir}/ocaml/xenmmap/xenmmap.cmx
%{_libdir}/ocaml/xenmmap/xenmmap.cmxa
%exclude %{_libdir}/ocaml/xenstore/xenstore.a
%exclude %{_libdir}/ocaml/xenstore/xenstore.cmi
%exclude %{_libdir}/ocaml/xenstore/xenstore.cmx
%exclude %{_libdir}/ocaml/xenstore/xenstore.cmxa

%files dom0-tests
%exclude %{_libexecdir}/%{name}/bin/depriv-fd-checker
%{_libexecdir}/%{name}/bin/test-cpu-policy
%{_libexecdir}/%{name}/bin/test-paging-mempool
%{_libexecdir}/%{name}/bin/test-resource
%{_libexecdir}/%{name}/bin/test-tsx
%{_libexecdir}/%{name}/bin/test-xenstore
%{_libexecdir}/%{name}/bin/test_x86_emulator
%{_datadir}/xen-dom0-tests-metadata.json

%files lp-devel_%{version}_%{release}
%{lp_devel_dir}

%doc

%post hypervisor
# Update the debug and release symlinks
ln -sf %{name}-%{version}-%{hv_rel}-d.gz /boot/xen-debug.gz
ln -sf %{name}-%{version}-%{hv_rel}.gz /boot/xen-release.gz

# Point /boot/xen.gz appropriately
if [ ! -e /boot/xen.gz ]; then
    # Use a production hypervisor by default
    ln -sf %{name}-%{version}-%{hv_rel}.gz /boot/xen.gz
elif [ ! -L /boot/xen.gz ]; then
    # Use the production hypervisor, but keep it unlinked
    cp -f /boot/%{name}-%{version}-%{hv_rel}.gz /boot/xen.gz
else
    # Else look at the current link, and whether it is debug
    path="`readlink -f /boot/xen.gz`"
    if [ ${path} != ${path%%-d.gz} ]; then
        ln -sf %{name}-%{version}-%{hv_rel}-d.gz /boot/xen.gz
    else
        ln -sf %{name}-%{version}-%{hv_rel}.gz /boot/xen.gz
    fi
fi

if [ -e %{_sysconfdir}/sysconfig/kernel ] && ! grep -q '^HYPERVISOR' %{_sysconfdir}/sysconfig/kernel ; then
  cat %{_sysconfdir}/sysconfig/kernel-xen >> %{_sysconfdir}/sysconfig/kernel
fi

%post dom0-tools
%systemd_post proc-xen.mount
%systemd_post var-lib-xenstored.mount
%systemd_post xen-init-dom0.service
%systemd_post xen-watchdog.service
%systemd_post xenconsoled.service
%systemd_post xenstored.service

%preun dom0-tools
%systemd_preun proc-xen.mount
%systemd_preun var-lib-xenstored.mount
%systemd_preun xen-init-dom0.service
%systemd_preun xen-watchdog.service
%systemd_preun xenconsoled.service
%systemd_preun xenstored.service

%postun dom0-tools
%systemd_postun proc-xen.mount
%systemd_postun var-lib-xenstored.mount
%systemd_postun xen-init-dom0.service
%systemd_postun xen-watchdog.service
%systemd_postun xenconsoled.service
%systemd_postun xenstored.service

%{?_cov_results_package}

%changelog
* Fri Jul 11 2025 Anthoine Bourgeois <anthoine.bourgeois@vates.tech> - 4.17.5-15.2
- Backport 22650d605462 "x86/hvmloader: select xen platform pci MMIO BAR UC or WB MTRR
  cache attributes"
- Backport fd06f8700769 "tools/golang: update auto-generated libxl based types"

* Wed Jul 09 2025 Teddy Astie <teddy.astie@vates.tech> - 4.17.5-15.1
- Sync with 4.17.5-15
- *** Upstream changelog ***
  * Fri Jul  4 2025 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.5-15
  - Fix for XSA-471 CVE-2024-36350 CVE-2024-36357
  - Perform provenance checks on AMD microcode blobs

* Tue Jul 02 2025 Thierry Escande <thierry.escande@vates.tech> - 4.17.5-14.1
- Sync with 4.17.5-14
- Remove xsa470-4.17.patch included in XS release
- *** Upstream changelog ***
  * Fri Jun 13 2025 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.5-14
  - Fix for XSA-470 CVE-2025-27465
  - Fix booting on servers with RAM above the 16T boundary
  - Fix possible watchdog timeout caused by unnecessary cache flushing

* Tue Jul 01 2025 Thierry Escande <thierry.escande@vates.tech> - 4.17.5-13.2
- Fix for XSA-470

* Mon May 12 2025 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.17.5-13.1
- Sync with 4.17.5-13
- Remove xen-4.17.5-x86-intel-Fix-PERF_GLOBAL-fixup-when-virtualised.patch included in XS
- *** Upstream changelog ***
  * Thu May  8 2025 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.5-13
  - Fix for XSA-469 CVE-2024-28956
  * Mon Apr 28 2025 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.5-12
  - Work around Ice Lake erratum ICX143, which manifests as a hang on boot
  - Fix crash on boot when perf counters are unavailable
  * Wed Mar 26 2025 Roger Pau Monné <roger.pau@citrix.com> - 4.17.5-11
  - Add xenguest support for the platform:mmio_hole_size attribute
  - Identify which domain watchdog fired

* Wed May 07 2025 Thierry Escande <thierry.escande@vates.tech> - 4.17.5-10.1
- Sync with 4.17.5-10
- Remove xsa467.patch now provided by XS package
- *** Upstream changelog ***
  * Thu Feb 27 2025 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.5-10
  - Fix for XSA-467 CVE-2025-1713
  - Fix reboot/shutdown issues on AMD due to local APIC ESR interrupts

* Mon May 05 2025 Tu Dinh <ngoc-tu.dinh@vates.tech> - 4.17.5-9.3
- Backport dd05d265b8ab "x86/intel: Fix PERF_GLOBAL fixup when virtualised"

* Tue Apr 29 2025 Yann Dirson <yann.dirson@vates.tech> - 4.17.5-9.2
- Rebuild against ncurses 6.4-6.20240309 to pull abi5 (compat) libs

* Mon Mar 31 2025 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.17.5-9.1
- Sync with 4.17.5-9
- *** Upstream changelog ***
  * Fri Feb 07 2025 Javi Merino <javi.merino@cloud.com> - 4.17.5-9
  - Fix PCI config reads patch
  * Tue Feb  4 2025 Javi Merino <javi.merino@cloud.com> - 4.17.5-8
  - Fix IO_PAGE_FAULT reported by AMD
  - Reduce PCI config reads
  * Wed Dec 18 2024 Roger Pau Monné <roger.pau@citrix.com> - 4.17.5-7
  - Fix IO-APIC initialization with ExtINT mode pins
  - Fix emulation of MOVBE instruction
  - Fix Ocaml rpath setting

* Wed Mar 05 2025 Thierry Escande <thierry.escande@vates.tech> - 4.17.5-6.1
- Sync with 4.17.5-6
- *** Upstream changelog ***
  * Tue Dec  3 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.5-6
  - Fix migration of VMs from CH 8.2 CU1 to XS8 when the guest is using BHI_DIS_S
  * Mon Nov 25 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.5-5
  - Initial AMD Turin support
  - Fix dom0 pIRQ limit calculation
  - Fix emulation of BMI1/2 instructions

* Fri Feb 28 2025 David Morel <david.morel@vates.tech> - 4.17.5-4.2
- Fix for XSA-467 / CVE-2025-1713

* Mon Feb  6 2025 Yann Dirson <yann.dirson@vates.tech> - 4.17.5-4.1
- xenguest: activate nested virt when requested

* Tue Nov  5 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.5-4
- Fixes for
  - XSA-463 CVE-2024-45818
  - XSA-464 CVE-2024-45819
- Fix IO-APIC directed EOIs when using AMD-Vi interrupt remapping
- Fix a crash during livepatch loading caused by an incorrect order of checks
- Switch xAPIC flat driver to use physical destination mode for external
  interrupts
- Remove an overly strict check when parsing AMD IVRS ACPI tables
- Fix a leak of pending interrupts during CPU offline

* Wed Sep 11 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.5-3
- Fix for XSA-462 CA-399169

* Tue Sep 10 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.5-2
- Fix x2APIC cluster handling across S3
- Avoid clobbering firmware memory during the load-base calculation
- Fix ASAN issues identified in `xentop` and `xl dmesg`

* Wed Aug 21 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.5-1
- Update to Xen 4.17.5

* Fri Aug  2 2024 Roger Pau Monné <roger.pau@citrix.com> - 4.17.4-8
- Fix for XSA-460 CVE-2024-31145
- Fix IO breakpoint recognition in PV guests
- Fix libxenstore.so to not modify SIGBUS behind the back of the application
- Fix a integer overflow in Xen's bunzip2(), leading to a rare decompression
  faliure

* Mon Jul 22 2024 Matthew Barnes <matthew.barnes@cloud.com> - 4.17.4-7
- Fix CLOEXEC handling in libxenstore
- Don't package Ocaml Xenbus library
- Inject #DF instead of overwriting RIP in xen-hvmcrash

* Wed Jul  3 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.4-6
- Fix for XSA-458 CVE-2024-31143
- Fix early detection of CPU features on hardware with the CPUID Limit active
  in firmware
- Fix a bug whereby dynamic XSTATE CPUID information was provided to all
  guests, even those with XSAVE disabled
- Fix a bug on Intel where HVM guests may have MMIO mappings forced to UC even
  if the guest kernel wanted a different cacheability
- Fix multiple bugs with interrupt affinity handling around CPU hotplug

* Fri May 31 2024 Pau Ruiz Safont <pau.ruizsafont@cloud.com> - 4.17.4-5
- Rebuild with OCaml 4.14.2 compiler.

* Thu May 30 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.4-4
- Don't link oxenstored against libsystemd, and remove systemd-devel as a
  build dependency
- Fix population of the online vCPU bitmap for PVH guests
- Drop unused openssl-devel build dependency

* Wed May 15 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.4-3
- Pass all MSI-X vector control writes to the device model
- Distinguish "ucode already up to date" and treat it as success
- Optimise HVMLoader AP bringup
- Fix xentop cpu% sort order
- Fix possible watchdog timeouts or NULL pointer deference with CPU hotplug

* Tue May  7 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.4-2
- Fix a heterogeneous CPU levelling bug between ICX and CLX

* Tue Apr 30 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.4-1
- Update to Xen 4.17.4
- Fix a bug in RTC emulation for HVM guests which occasionally causes OVMF to
  fail an assertion
- Fix a bug in livepatch application when CET-IBT is active, leading to a full
  host crash
- Include the debug xen debug symbols in in the lp-devel subpackage

* Tue Apr  9 2024 Alex Brett <alex.brett@cloud.com> - 4.17.3-6
- CA-391273: Rebuild to resolve xen-dom0-tools dependency issue

* Wed Apr  3 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.3-5
- Fixes for:
  - XSA-454 CVE-2023-46842
  - XSA-455 CVE-2024-31142
  - XSA-456 CVE-2024-2201

* Fri Mar  8 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.3-4
- Fixes for:
  - XSA-453 CVE-2024-2193, off by default
  - XSA-452 CVE-2023-28746
- Fix levelling of MD_CLEAR/FB_CLEAR across a pool
- Hide x2APIC from PV guests by default
- Fixes to livepatching, including the ability to patch .rodata
- Improve oxenstored performance by avoiding Hashtbl.copy when processing
  packets
- Print the SPECULATIVE_HARDEN_* options which are enabled at build time

* Fri Feb 23 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.3-3
- Fix for XSA-451 CVE-2023-46841.
- Fix the migration of VMs which had previously seen the CMP_LEGACY feature.
- Retire support to customise guest memory at the 1M boundary.

* Tue Feb 13 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.3-2
- De-virtualise more function pointers, based on boot time configuration
- Improve the performance of IOMMU construction for dom0
- Fix a bug with the determination of IVMD memory regions
- Fix inefficiencies with XEN_{SYS,DOM}CTL_getdomaininfo{,list}
- Fix undefined behaviour in compat_set_timer_op()
- Fix the Raw CPU Policy rescan when CPUID Masking is active

* Fri Jan 26 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.17.3-1
- Update to Xen 4.17
  Major highlights:
    - CET-SS, CET-IBT and IOMMU Superpages used on capable hardware
    - PV32, PV_LINEAR_PT and SHADOW_PAGING now compiled out
    - NX and HAP (Intel EPT or AMD NPT) support in hardware is now mandatory

* Wed Jan 24 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.60
- Fix watchdog setup on Intel Sapphire Rapids and Emerald Rapids platforms.
- Adjust preemption during IOMMU setup to avoid triggering the watchdog.
- Extend AMD #1474 (crash after ~1044 days) workaround to Zen1 platforms.

* Tue Dec 19 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.59
- Enable AVX-512 by default for Intel IceLake and later CPUs.
- Rebuild with updated Ocaml 4.14 runtime.
- Fix possible memory leak in libxenguest cpu-policy infrastructure.

* Mon Dec 4 2023 Alejandro Vallejo <alejandro.vallejo@cloud.com> - 4.13.5-10.58
- Remove limit of 64 CPUs from hvmloader.
- Fix pygrub incompatibility with python3.
- Improve the livepatch infrastructure.

* Wed Nov 8 2023 Roger Pau Monné <roger.pau@citrix.com> - 4.13.5-10.57
- Add new x2APIC 'Mixed mode' driver, and use it by default.

* Wed Nov 1 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.56
- Fixes for
  - XSA-445 CVE-2023-46835
  - XSA-446 CVE-2023-46836

* Wed Nov 1 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.55
- Fix for AMD erratum #1485, which has been observed to cause #UD exception on
  AMD Zen4 systems.
- Allow using the platform/ovmf-override key to configure the OVMF firwmare to
  use on a per-VM basis.
- Further Python3 fixes.

* Tue Oct 17 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.54
- Increase the compile time max CPUs from 512 to 2048.

* Fri Sep 29 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.53
- Fixes for
  - XSA-438 CVE-2023-34322
  - XSA-440 CVE-2023-34323
  - XSA-442 CVE-2023-34326
  - XSA-443 CVE-2023-34325
  - XSA-444 CVE-2023-34327 CVE-2023-34328
- Pygrub extended to deprivilege itself before operating on guest disks.

* Tue Sep 19 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.52
- Fix for XSA-439 / CVE-2023-20588.
- Ignore MADT entries with invalid APIC_IDs.
- Fix the emulation of VPBLENDMW with a mask and memory operand.
- Fix a incorrect diagnostic about spurious interrupts.

* Fri Aug 25 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.51
- Further fix for XSA-433.  Extend the chicken-bit workaround to all CPUs
  which appear to be a Zen2 microarchtiecture, even those not on the published
  model list.
- Fix for AMD errata #1474.  Disable C6 after 1000 days of uptime on AMD Zen2
  systems to avoid a crash at ~1044 days.
- Fix for MSR_ARCH_CAPS boot-time calculations for PV guests.
- Remove the debug PV-shim hypervisor.  The release build is still present and
  operates as before.
- Remove TBOOT and XENOPROF support in Xen.  Both are obsolete and the latter
  leaves benign-but-alarming messages in logs.
- Remove the "pod" command line option.  This was intended as a further
  workaround for XSA-246, but wasn't effective owing to poor error handling
  elsewhere.

* Thu Aug 3 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.50
- Fixes for
  - XSA-434 CVE-2023-20569
  - XSA-435 CVE-2022-40982

* Thu Aug 3 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.49
- Fix bug in XSA-433 fix, which accidentally disabled a hardware errata
  workaround.
- Update IO-APIC IRTEs atomically.  Fixes a race condition which causes
  interrupts to be routed badly, often with "No irq handler for vector"
  errors.
- Expose MSR_ARCH_CAPS to guests on all Intel hardware by default.  On Cascade
  Lake and later hardware, guests now see the bits stating hardware immunity
  to various speculative vulnerabilities.

* Mon Jul 24 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.48
- Fix for XSA-433 CVE-2023-20593.
- Limit scheduler loadbalancing to once per millisecond.  This improves
  performance on large systems.
- Mask IO-APIC pins before enabling LVTERR/ESR.  This fixes issues booting if
  firmware leaves the IO-APIC in a bad state.

* Tue Jun 06 2023 Pau Ruiz Safont <pau.ruizsafont@cloud.com> - 4.13.5-10.47
- Backport late microcode loading changes.
- Rebuild with Ocaml 4.14.

* Fri May 19 2023 Roger Pau Monné <roger.pau@citrix.com> - 4.13.5-10.46
- Fix AMD-Vi assert.
- Remove broken not built code in pv-iommu.
- Add test_x86_emulator to XenDom0Tests.

* Thu May 11 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.45
- Ignore VCPU_SSHOTTMR_future entirely.  The only known user of this is Linux
  prior to v4.7, and the usage is buggy.  This resolves guest crashes during
  migration.
- Improve Xen's early boot checking of its own alignment.  In case of a
  bootloader error, this turns a crash with no diagnostics into a clear error
  message.
- Drop XENMEM_get_mfn_from_pfn technical debt, the use of which has been
  replaced by PV-IOMMU.
- Minor specfile improvements; branding, and a bad changelog date.

* Thu Apr 27 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.44
- Add Obsoletes following the removal of xen-installer-files.

* Mon Apr 17 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.43
- Remove the NR_IOMMUs compile time limit.  This is necessary to boot on
  4-socket Sapphire Rapids systems.
- Cope booting in x2APIC mode on AMD systems without XT mode.
- Allow creating domains with grant settings larger than dom0.
- Remove sequential microcode application support.  Only parallel application
  is supported by the HW vendors.
- Introduce an elfnote for Dom0 <-> Xen negotiation of the activation of
  PV-IOMMU.
- Increase the size of the serial transmit buffer.
- Backport python3 shebang fixes.  Drop obsolete scripts.
- Remove the xen-installer-files subpackage.  It was a vestigial remnant of an
  old build system.

* Mon Mar 6 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.42
- Fixes for
  - XSA-427 CVE-2022-42332
  - XSA-428 CVE-2022-42333 CVE-2022-42334
  - XSA-429 CVE-2022-42331
- Move partial python library from xen-tools to xen-dom0-tools.  The content
  was all specific to dom0, and ineligible to be used elsewhere.
- Reintroduce the python2 pygrub/libfsimage bindings.

* Fri Mar 3 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.41
- Load AMD microcode on all logical processors.
- Switch to using Python 3.  Retain Python 2 builds of xen.lowlevel in the
  short term until dependent packages have been updated.
- Fix libfsimage build in the presence of newer Linux headers.

* Mon Feb 6 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.40
- Fix for XSA-426 CVE-2022-27672.
- More fixes for memory corruption issues in the Ocaml bindings.
- On xenstored live update, validate the config file before launching
  into the new xenstored.

* Thu Feb 2 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.39
- Fix memory corruption issues in the Ocaml bindings.

* Mon Jan 16 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-10.38
- Update to Xen 4.13.5

* Fri Jan 13 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-10.37
- Initial support for Intel Sapphire Rapids.
- Don't mark IRQ vectors as pending when the vLAPIC is disabled.  This fixes
  an issue with Linux 5.19 and later.
- Remove an incorrect but benign warning which occurs for a UEFI VM that
  modifies the vRTC time.
- Fix overflow with high frequency TSCs.
- Fix crash on boot with invalid UEFI framebuffer configurations.
- Fix race condition releasing an IRQ which is in the process of moving
  between CPUs.
- Fix timer affinity after S3.
- Drop Introspection Extensions.

* Fri Dec 2 2022 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-10.36
- Activate AVX-512 by default on AMD platforms.
- Fixes for oxenstored live update.

* Fri Nov 4 2022  Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-10.35
- Fix for XSA-422 CVE-2022-23824

* Thu Oct 27 2022 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-10.34
- Fixes for
  - XSA-326 CVE-2022-42311 CVE-2022-42312 CVE-2022-42313 CVE-2022-42314
            CVE-2022-42315 CVE-2022-42316 CVE-2022-42317 CVE-2022-42318
  - XSA-414 CVE-2022-42309
  - XSA-415 CVE-2022-42310
  - XSA-416 CVE-2022-42319
  - XSA-417 CVE-2022-42320
  - XSA-418 CVE-2022-42321
  - XSA-419 CVE-2022-42322 CVE-2022-42323
  - XSA-420 CVE-2022-42324
  - XSA-421 CVE-2022-42325 CVE-2022-42326

* Thu Oct 6 2022 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-10.33
- Fixes for XSA-410 CVE-2022-33746, XSA-411 CVE-2022-33748.
- Activate DOITM (Data Operand Invariant Timing Mode) unilaterally on capable
  hardware (Intel IceLake/Gracemont and later) to keep properly-written crypto
  code safe from timing attacks.
- Fix compressed XSAVE size reporting.  Fixes an issue with Linux 5.19+ on
  Intel Skylake or AMD Zen1 or later hardware.
- Fix a performance issue when when using CUDA workloads (e.g. Tensorflow) on
  a passed-through GPU.

* Fri Sep 16 2022 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.13.4-10.32
- Add TPM 2.0 supporting patches

* Wed Aug 17 2022 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-10.31
- Fix CPU hotplug on AMD.
- Improve diagnostics in nmi_show_execution_state().
- Rework specfile so tools get the default RPM CFLAGS/LDFLAGS, including
  various hardening settings.

* Tue Aug 9 2022 Pau Ruiz Safont <pau.safont@citrix.com> - 4.13.4-10.30
- Bump release and rebuild with OCaml 4.13.1-3 compiler.

* Fri Aug 5 2022 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-10.29
- Improve boot speed by using WC mappings for the VGA framebuffer.
- Fix crash on boot on AMD Zen2/3 systems when x2apic is disabled by firmware.
- Correct the RPM license fields.

* Tue Jul 26 2022 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-10.28
- Fix for XSA-408 CVE-2022-33745.

* Fri Jul 8 2022 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-10.27
- Fixes for XSA-407 CVE-2022-23816 CVE-2022-23825.
- Switch to x2APIC physical destination mode by default.  Addresses problems
  with vector exhaustion on large systems.
- Address an issue where EPT superpages were unnecessarily split.

* Thu Jun 16 2022 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-10.26
- Fixes for XSA-404 CVE-2022-21123 CVE-2022-21125 CVE-2022-21166.

* Thu Jun 9 2022 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-10.25
- Fixes for XSA-401 CVE-2022-26362, XSA-402 CVE-2022-26363 CVE-2022-26364.

* Wed Apr 13 2022 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-10.24
- Rebuild using devtoolset-11.

* Wed Apr 13 2022 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-10.23
- Fixes to the XSA-400 changes.

* Fri Mar 25 2022 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-10.22
- Fixes for XSA-397 CVE-2022-26356, XSA-399 CVE-2022-26357, XSA-400
  CVE-2022-26358 CVE-2022-26359 CVE-2022-26360 CVE-2022-26361.

* Thu Mar 10 2022 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-10.21
- Fix for XSA-386 CVE-2021-26401.

* Tue Feb 15 2022 Rob Hoes <rob.hoes@citrix.com> - 4.13.4-10.20
- Rebuild with OCaml 4.13.1 compiler.
- CP-37343: Drop Ocaml/CPUID technical debt.

* Tue Feb 8 2022 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-10.19
- Fixes for XSA-394 CVE-2022-23034, XSA-395 CVE-2022-23035.
- Support for AMD MSR_SPEC_CTRL in HVM guests.
- Logic to match the Intel Feb 2022 microcode.  De-featuring TSX on more
  client parts, and retrofitting AMD's PSFD interface for guests.
- Build fix for Ocaml 4.12
- Fix and simplify runtime new CPUID feature logic.

* Wed Dec 22 2021 Igor Druzhinin <igor.druzhinin@citrix.com> - 4.13.4-10.18
- CA-361938: Fix advertisment of HLE/RTM to guests on Broadwell
- CA-360592: CVE-2021-28705 / XSA-389: issues with partially successful
  P2M updates on x86
- CA-360591: CVE-2021-28704 / XSA-388: PoD operations on misaligned GFNs

* Tue Nov 02 2021 Igor Druzhinin <igor.druzhinin@citrix.com> - 4.13.4-10.17
- CP-38201: Enable static analysis with Coverity

* Wed Oct 13 2021 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-3
- Fix ACPI table alignment in guests
- Fix compat hypercall translation
- Perf improvements at boot, for hypercalls, and for the XSM subsystem

* Wed Oct 6 2021 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-2
- Fix boot failure if a PCI Bridge is has a subordinate bus of 255.
- Reduce overhead from the trace infrastructure.
- Fix for XSA-386 CVE-2021-28702.

* Fri Sep 10 2021 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.4-1
- Update to RELEASE-4.13.4.

* Wed Sep 8 2021 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.3-10.16
- Fix for XSA-384 CVE-2021-28701.
- Bugfixes to XSA-378 fix.

* Wed Sep 1 2021 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.3-10.15
- Fixes for XSA-378 CVE-2021-28694 CVE-2021-28695 CVE-2021-28696, XSA-379
  CVE-2021-28697, XSA-380 CVE-2021-28698, XSA-382 CVE-2021-28699.
- Retain visibility of HLE/RTM CPUID bits in guests when resuming on a client
  part with TSX disabled.
- Use production hypervisor by default, rather than the debug hypervisor.

* Mon Aug 23 2021 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.3-10.14
- Disable 32bit PV guests by default.  They're not security supported at all
  and by disabling them, we can recover performance in the common case from
  the Spectre mitigations.  If necessary, 32bit PV guests can be re-enabled by
  booting Xen with `pv=32`.

* Mon Jul 26 2021 Igor Druzhinin <igor.druzhinin@citrix.com> - 4.13.3-10.13
- Correctly handle IRQ > 255 on PCI passthrough
- Reserve HyperTransport region properly on AMD Fam 17h+
- More IOMMU error path fixes
- Fix populating vbd.rd_sect in xentop

* Wed Jul 21 2021 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.3-10.12
- Remove old workaround which causes a test-tsx failure on the hardware which
  the Intel June microcode de-featured TSX on.

* Wed Jun 30 2021 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.3-10.11
- Fix migration of VMs which previously saw MPX.

* Tue Jun 22 2021 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.3-10.10
- New xen-dom0-tests subpackage with unit and low level functional tests.
- Logic to match the Intel June microcode, de-featuring TSX on client parts.
- Prep work to move CPUID handling out of xenopsd and into libxc.
- Hide MPX by default from VMs.

* Mon Jun 14 2021 Igor Druzhinin <igor.druzhinin@citrix.com> - 4.13.3-10.8
- Fix another race with vCPU timers

* Wed Jun 9 2021 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.3-10.7
- LBR and PMU fixes for Icelake Server
- Don't assume that VT-d Register based invalidation is available.  Expected
  to be necessary to boot on Sapphire Rapids Server.
- Fix the emulation of the PINSRW instruction.
- Reduce lock contention for virtual periodic timers, to fix a perf regression
  introduced by the XSA-336 fix.
- Fixes for XSA-373 CVE-2021-28692, XSA-375 CVE-2021-0089 CVE-2021-26313,
  XSA-377 CVE-2021-28690.

* Fri Apr 16 2021 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.3-10.6
- Fix booting on Intel systems with static PIT clock gating.
- Drop unnecessary build dependencies.

* Fri Mar 26 2021 Rob Hoes <rob.hoes@citrix.com> - 4.13.3-10.5
- Rebuild with OCaml 4.10 compiler.

* Tue Mar 23 2021 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.3-10.4
- Update to Xen 4.13.3.

* Mon Mar 22 2021 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.2-10.3
- Fix library packaging so that autoreqprov doesn't cause xen-libs{,-devel} to
  depend on xen-dom0-libs{,devel}.

* Fri Mar 12 2021 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.2-10.2
- Fix a failure to boot of Windows Server vNext (build 20270).  Reduces the
  upper limit of HVM vCPUs to 64, pending other bugfixes.
- Advertise Viridian vCPU hotplug to guests as Xen already implements the
  functionality.
- Fixes for XSA-360 CVE-2021-3308.
- Backport XEN_DMOP_nr_vcpus and stable library fixes.
- Backport build system fix and drop 32bit libc as a build dependency.
- Fix microcode loading on AMD Family 19h (Zen3) parts.
- Fix HVM Shadow / migrating PV guests on IceLake parts.
- Fix booting on IceLake when the IOMMU is left in a partially initialised
  state by the firmware.

* Fri Dec 18 2020 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.2-10.1
- Backport changes for Ocaml 4.10 compatibility
- Fixes for XSA-115 CVE-2020-29480, XSA-322 CVE-2020-29481, XSA-323
  CVE-2020-29482, XSA-324 CVE-2020-29484, XSA-325 CVE-2020-29483, XSA-330
  CVE-2020-29485, XSA-348 CVE-2020-29484, XSA-352 CVE-2020-29486, XSA-353
  CVE-2020-29479, XSA-359 CVE-2020-29571
- Prototype oxenstored live update support
