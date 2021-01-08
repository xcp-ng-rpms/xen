# -*- rpm-spec -*-

%{!?python_sitearch: %define python_sitearch %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib(1)")}

%define with_sysv 0
%define with_systemd 1

# Use the production hypervisor by default
%define default_debug_hypervisor 0

%define COMMON_OPTIONS DESTDIR=%{buildroot} %{?_smp_mflags}

# For 32bit dom0 userspace, we need to cross compile a 64bit Xen
%ifarch %ix86
%define HVSOR_OPTIONS %{COMMON_OPTIONS} XEN_TARGET_ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu-
%define TOOLS_OPTIONS %{COMMON_OPTIONS} XEN_TARGET_ARCH=x86_32 debug=n
%endif

# For 64bit
%ifarch x86_64
%define HVSOR_OPTIONS %{COMMON_OPTIONS} XEN_TARGET_ARCH=x86_64
%define TOOLS_OPTIONS %{COMMON_OPTIONS} XEN_TARGET_ARCH=x86_64 debug=n
%endif

%define base_cset RELEASE-%{version}
%define base_dir  %{name}-%{version}

Summary: Xen is a virtual machine monitor
Name:    xen
Version: 4.13.1
Release: 9.8.2%{?dist}
License: GPLv2 and LGPLv2+ and BSD
URL:     http://www.xenproject.org

Source0: xen.tar.gz
Source1: SOURCES/xen/sysconfig_kernel-xen
Source2: SOURCES/xen/xl.conf
Source3: SOURCES/xen/logrotate-xen-tools

Patch0: build-tweaks.patch
Patch1: autoconf-libjson.patch
Patch2: configure-build.patch
Patch3: changeset-info.patch
Patch4: xenserver-configuration.patch
Patch5: coverity-model.patch
Patch6: backport-cd7dedad8209.patch
Patch7: backport-79cf0989175c.patch
Patch8: backport-6dd95b02ea27.patch
Patch9: backport-9356f9de4162.patch
Patch10: backport-c08cbf7fb891.patch
Patch11: backport-3d05407025ed.patch
Patch12: backport-b1710040ca96.patch
Patch13: backport-31bf4f26aa17.patch
Patch14: backport-e9bd648015dd.patch
Patch15: backport-da9290639eb5.patch
Patch16: backport-7b3c5b70a323.patch
Patch17: backport-1171a93b6ca7.patch
Patch18: backport-2004db3ced18.patch
Patch19: backport-59e1f6d89710.patch
Patch20: backport-86cf92f50533.patch
Patch21: backport-0a9c44486b90.patch
Patch22: backport-270ff9a835fb.patch
Patch23: backport-dacb80f9757c.patch
Patch24: backport-1b3cec69bf30.patch
Patch25: backport-8171e0796542.patch
Patch26: backport-a798bac54fe8.patch
Patch27: backport-920d5f31883c.patch
Patch28: backport-c9495bd7dff5.patch
Patch29: backport-53ddfc80a84a.patch
Patch30: backport-a9b6dacf88fe.patch
Patch31: backport-7ff66809ccd5.patch
Patch32: backport-c301211a5111.patch
Patch33: backport-53594c7bd197.patch
Patch34: backport-540d4d60378c.patch
Patch35: backport-d92ba1aa7cf8.patch
Patch36: backport-59b087e39544.patch
Patch37: backport-78686437e949.patch
Patch38: backport-2b8079610ec5.patch
Patch39: backport-3174835ba825.patch
Patch40: backport-c2b4e23fdda4.patch
Patch41: backport-e9aca9470ed8.patch
Patch42: backport-17b997aa1edb.patch
Patch43: backport-fe36a173d110.patch
Patch44: backport-35b819c45c46.patch
Patch45: backport-9f3e9139fa6c.patch
Patch46: backport-710f62cc826b.patch
Patch47: 0001-x86-svm-do-not-try-to-handle-recalc-NPT-faults-immed.patch
Patch48: 0001-x86-spec-ctrl-CPUID-MSR-definitions-for-Special-Regi.patch
Patch49: 0002-x86-spec-ctrl-Mitigate-the-Special-Register-Buffer-D.patch
Patch50: 0003-xen-microcode-add-information-about-currently-loaded.patch
Patch51: 0004-microcode-add-sequential-application-policy.patch
Patch52: 0007-microcode-update-raw-cpuid-policy-after-a-successful.patch
Patch53: 0001-microcode-remove-panic-calls.patch
Patch54: detect-nehalem-c-state.patch
Patch55: quirk-hp-gen8-rmrr.patch
Patch56: quirk-pci-phantom-function-devices.patch
Patch57: 0001-x86-hpet-Pre-cleanup.patch
Patch58: 0002-x86-hpet-Use-singe-apic-vector-rather-than-irq_descs.patch
Patch59: 0003-x86-hpet-Post-cleanup.patch
Patch60: 0002-libxc-retry-shadow-ops-if-EBUSY-is-returned.patch
Patch61: avoid-gnt-unmap-tlb-flush-if-not-accessed.patch
Patch62: 0002-efi-Ensure-incorrectly-typed-runtime-services-get-ma.patch
Patch63: 0001-x86-time-Don-t-use-EFI-s-GetTime-call.patch
Patch64: 0001-efi-Workaround-page-fault-during-runtime-service.patch
Patch65: 0001-x86-HVM-Avoid-cache-flush-operations-during-hvm_load.patch
Patch66: 0001-libxl-Don-t-insert-PCI-device-into-xenstore-for-HVM-.patch
Patch67: 0001-x86-PoD-Command-line-option-to-prohibit-any-PoD-oper.patch
Patch68: livepatch-ignore-duplicate-new.patch
Patch69: default-log-level-info.patch
Patch70: 0001-lib-Add-a-generic-implementation-of-current_text_add.patch
Patch71: 0002-sched-Remove-dependency-on-__LINE__-for-release-buil.patch
Patch72: pygrub-Ignore-GRUB2-if-statements.patch
Patch73: libfsimage-Add-support-for-btrfs.patch
Patch74: quiet-broke-irq-affinity.patch
Patch75: 0001-x86-msr-Blacklist-various-MSRs-which-guests-definite.patch
Patch76: 0001-Hide-AVX-512-from-guests-by-default.patch
Patch77: 0001-common-page_alloc-don-t-idle-scrub-before-microcode-.patch
Patch78: 0001-xsm-hide-detailed-Xen-version-from-unprivileged-gues.patch
Patch79: xen-tweak-cmdline-defaults.patch
Patch80: xen-tweak-debug-overhead.patch
Patch81: tweak-iommu-policy.patch
Patch82: disable-core-parking.patch
Patch83: 0001-Allocate-space-in-structs-pre-emptively-to-increase-.patch
Patch84: 0001-x86-mm-partially-revert-37201c62-make-logdirty-and-i.patch
Patch85: hitachi-driver-domain-ssid.patch
Patch86: livepatch-payload-in-header.patch
Patch87: xen-define-offsets-for-kdump.patch
Patch88: xen-scheduler-auto-privdom-weight.patch
Patch89: xen-hvm-disable-tsc-ramping.patch
Patch90: xen-default-cpufreq-governor-to-performance-on-intel.patch
Patch91: xen-override-caching-cp-26562.patch
Patch92: 0001-Partially-revert-08754333892-hvmloader-limit-CPUs-ex.patch
Patch93: 0001-x86-pv-silently-discard-writes-into-MSR_AMD64_LS_CFG.patch
Patch94: revert-ca2eee92df44.patch
Patch95: libxc-stubs-hvm_check_pvdriver.patch
Patch96: libxc-cpuid-cores_per_socket.patch
Patch97: pygrub-add-default-and-extra-args.patch
Patch98: pygrub-always-boot-default.patch
Patch99: pygrub-friendly-no-fs.patch
Patch100: pygrub-image-max-size.patch
Patch101: pygrub-default-xenmobile-kernel.patch
Patch102: pygrub-blacklist-support.patch
Patch103: oem-bios-xensource.patch
Patch104: oem-bios-magic-from-xenstore.patch
Patch105: misc-log-guest-consoles.patch
Patch106: fix-ocaml-libs.patch
Patch107: 0005-x86-msr-Expose-cpu_has_tsx_ctrl-via-MSR_ARCH_CAPS.patch
Patch108: ocaml-cpuid-helpers.patch
Patch109: xentop-vbd3.patch
Patch110: mixed-domain-runstates.patch
Patch111: xenguest.patch
Patch112: xen-vmdebug.patch
Patch113: oxenstore-censor-sensitive-data.patch
Patch114: oxenstore-large-packets.patch
Patch115: pv-shim-compat-dmc.patch
Patch116: nvidia-vga.patch
Patch117: hvmloader-disable-pci-option-rom-loading.patch
Patch118: xen-force-software-vmcs-shadow.patch
Patch119: 0001-x86-vvmx-add-initial-PV-EPT-support-in-L0.patch
Patch120: use-msr-ll-instead-of-vmcs-efer.patch
Patch121: add-pv-iommu-headers.patch
Patch122: add-pv-iommu-local-domain-ops.patch
Patch123: add-pv-iommu-foreign-support.patch
Patch124: upstream-pv-iommu-tools.patch
Patch125: allow-rombios-pci-config-on-any-host-bridge.patch
Patch126: 0007-hypercall-XENMEM_get_mfn_from_pfn.patch
Patch127: gvt-g-hvmloader+rombios.patch
Patch128: xen-introduce-cmdline-to-control-introspection-extensions.patch
Patch129: xen-domctl-set-privileged-domain.patch
Patch130: xen-reexecute-instn-under-monitor-trap.patch
Patch131: revert-x86-mm-suppress-vm_events-caused-by-page-walks.patch
Patch132: xen-emulate-Bypass-the-emulator-if-emulation-fails.patch
Patch133: xen-introspection-pause.patch
Patch134: xen-always-enable-altp2m-external-mode.patch
Patch135: 0001-x86-add-XEN_SYSCTL_spec_ctrl.patch
Patch136: 0002-x86-add-xen-spec-ctrl-utility.patch
Patch137: backport-3e41b727f783.patch
Patch138: backport-7a76deb101c8.patch
Patch139: backport-56e117f504f8.patch
Patch140: backport-2b34d8cd734a.patch
Patch141: backport-1c7a98cab910.patch
Patch142: backport-005d5eaa458d.patch
Patch143: backport-f1055a202d49.patch
Patch144: backport-8b9be8f415f2.patch
Patch145: backport-493e143a8289.patch
Patch146: backport-0c8c10d12e98.patch
Patch147: backport-572e349de17e.patch
Patch148: xsa333.patch
Patch149: xsa334.patch
Patch150: xsa336.patch
Patch151: xsa337xsa337-4.13-1.patch
Patch152: xsa337xsa337-4.13-2.patch
Patch153: xsa338.patch
Patch154: xsa339.patch
Patch155: xsa340.patch
Patch156: xsa342-4.13.patch
Patch157: xsa343xsa343-1.patch
Patch158: xsa343xsa343-2.patch
Patch159: xsa343xsa343-3.patch
Patch160: xsa344xsa344-4.13-1.patch
Patch161: xsa344xsa344-4.13-2.patch
Patch162: backport-d112db32c622.patch
Patch163: backport-780d3761f117.patch
Patch164: backport-ca95985a6488.patch
Patch165: backport-7d6f52d47b3d.patch
Patch166: backport-d064b6581bbd.patch
Patch167: backport-74c5729bb33d.patch
Patch168: xsa345-4.130001-x86-mm-Refactor-map_pages_to_xen-to-have-only-a-sing.patch
Patch169: xsa345-4.130002-x86-mm-Refactor-modify_xen_mappings-to-have-one-exit.patch
Patch170: xsa345-4.130003-x86-mm-Prevent-some-races-in-hypervisor-mapping-upda.patch
Patch171: xsa346xsa346-4.13-1.patch
Patch172: xsa346xsa346-4.13-2.patch
Patch173: xsa347xsa347-4.13-1.patch
Patch174: xsa347xsa347-4.13-2.patch
Patch175: xsa347xsa347-4.13-3.patch
Patch176: xsa351-x86-4.13-1.patch
Patch177: xsa351-x86-4.13-2.patch
Patch178: backport-c10b2931bf63.patch
Patch179: backport-28b78171271d.patch
Patch180: xsa355.patch
Patch181: xsa353.patch
Patch182: xsa115-4.13-c-0001-tools-xenstore-allow-removing-child-of-a-node-exceed.patch
Patch183: xsa115-4.13-c-0002-tools-xenstore-ignore-transaction-id-for-un-watch.patch
Patch184: xsa115-4.13-c-0003-tools-xenstore-fix-node-accounting-after-failed-node.patch
Patch185: xsa115-4.13-c-0004-tools-xenstore-simplify-and-rename-check_event_node.patch
Patch186: xsa115-4.13-c-0005-tools-xenstore-check-privilege-for-XS_IS_DOMAIN_INTR.patch
Patch187: xsa115-4.13-c-0006-tools-xenstore-rework-node-removal.patch
Patch188: xsa115-4.13-c-0007-tools-xenstore-fire-watches-only-when-removing-a-spe.patch
Patch189: xsa115-4.13-c-0008-tools-xenstore-introduce-node_perms-structure.patch
Patch190: xsa115-4.13-c-0009-tools-xenstore-allow-special-watches-for-privileged-.patch
Patch191: xsa115-4.13-c-0010-tools-xenstore-avoid-watch-events-for-nodes-without-.patch
Patch192: xsa115-o-0001-tools-ocaml-xenstored-ignore-transaction-id-for-un-w.patch
Patch193: xsa115-o-0002-tools-ocaml-xenstored-check-privilege-for-XS_IS_DOMA.patch
Patch194: xsa115-o-0003-tools-ocaml-xenstored-unify-watch-firing.patch
Patch195: xsa115-o-0004-tools-ocaml-xenstored-introduce-permissions-for-spec.patch
Patch196: xsa115-o-0005-tools-ocaml-xenstored-avoid-watch-events-for-nodes-w.patch
Patch197: xsa115-o-0006-tools-ocaml-xenstored-add-xenstored.conf-flag-to-tur.patch
Patch198: xsa322-4.14-c.patch
Patch199: xsa322-o.patch
Patch200: xsa323.patch
Patch201: xsa324.patch
Patch202: xsa325-4.14.patch
Patch203: xsa330.patch
Patch204: xsa352.patch
Patch205: xsa348-4.13-1.patch
Patch206: xsa348-4.13-2.patch
Patch207: xsa348-4.13-3.patch
Patch208: xsa358.patch
Patch209: xsa359.patch
Patch210: 0019-tools-xenstore-add-live-update-command-to-xenstore-c.patch
Patch211: xenstore-control-sleep.patch
Patch212: 0001-tools-ocaml-xenstored-only-quit-on-SIGTERM-when-a-re.patch
Patch213: 0002-tools-ocaml-xenstored-Automatically-resume-when-poss.patch
Patch214: 0003-tools-ocaml-xenstored-add-cooperative-live-update-co.patch
Patch215: 0004-tools-ocaml-xenstored-start-live-update-process.patch
Patch216: 0006-tools-ocaml-xenstored-implement-socket-live-update.patch

Provides: gitsha(ssh://git@code.citrite.net/xsu/xen.git) = 6278553325a9f76d37811923221b21db3882e017
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = c9f65d58ccf70240b422b076e027b1f25d14b453


ExclusiveArch: i686 x86_64

#Cross complier
%ifarch %ix86
BuildRequires: gcc-x86_64-linux-gnu binutils-x86_64-linux-gnu
%endif

# For HVMLoader and 16/32bit firmware
BuildRequires: /usr/include/gnu/stubs-32.h
BuildRequires: dev86 iasl

# For the domain builder (decompression and hashing)
BuildRequires: zlib-devel bzip2-devel xz-devel
BuildRequires: openssl-devel

# For libxl
BuildRequires: yajl-devel libuuid-devel perl

# For python stubs
BuildRequires: python-devel

# For ocaml stubs
BuildRequires: ocaml ocaml-findlib

BuildRequires: libblkid-devel

# For xentop
BuildRequires: ncurses-devel

# For the banner
BuildRequires: figlet

# For libxenfsimage
BuildRequires: e2fsprogs-devel
BuildRequires: lzo-devel

# For xenguest
BuildRequires: json-c-devel libempserver-devel

# For manpages
BuildRequires: perl pandoc

# Misc
BuildRequires: libtool
%if %with_systemd
BuildRequires: systemd-devel
%endif

# To placate ./configure
BuildRequires: gettext-devel glib2-devel curl-devel gnutls-devel

# Need cov-analysis if coverity is enabled
%{?_cov_buildrequires}

%description
Xen Hypervisor.

%package hypervisor
Provides: gitsha(ssh://git@code.citrite.net/xsu/xen.git) = 6278553325a9f76d37811923221b21db3882e017
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = c9f65d58ccf70240b422b076e027b1f25d14b453
Summary: The Xen Hypervisor
Group: System/Hypervisor
Requires(post): coreutils grep
%description hypervisor
This package contains the Xen Project Hypervisor.

%package hypervisor-debuginfo
Provides: gitsha(ssh://git@code.citrite.net/xsu/xen.git) = 6278553325a9f76d37811923221b21db3882e017
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = c9f65d58ccf70240b422b076e027b1f25d14b453
Summary: The Xen Hypervisor debug information
Group: Development/Debug
%description hypervisor-debuginfo
This package contains the Xen Hypervisor debug information.

%package tools
Provides: gitsha(ssh://git@code.citrite.net/xsu/xen.git) = 6278553325a9f76d37811923221b21db3882e017
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = c9f65d58ccf70240b422b076e027b1f25d14b453
Summary: Xen Hypervisor general tools
Requires: xen-libs = %{version}
Group: System/Base
%description tools
This package contains the Xen Hypervisor general tools for all domains.

%package devel
Provides: gitsha(ssh://git@code.citrite.net/xsu/xen.git) = 6278553325a9f76d37811923221b21db3882e017
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = c9f65d58ccf70240b422b076e027b1f25d14b453
Summary: The Xen Hypervisor public headers
Group: Development/Libraries
%description devel
This package contains the Xen Hypervisor public header files.

%package libs
Provides: gitsha(ssh://git@code.citrite.net/xsu/xen.git) = 6278553325a9f76d37811923221b21db3882e017
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = c9f65d58ccf70240b422b076e027b1f25d14b453
Summary: Xen Hypervisor general libraries
Group: System/Libraries
%description libs
This package contains the Xen Hypervisor general libraries for all domains.

%package libs-devel
Provides: gitsha(ssh://git@code.citrite.net/xsu/xen.git) = 6278553325a9f76d37811923221b21db3882e017
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = c9f65d58ccf70240b422b076e027b1f25d14b453
Summary: Xen Hypervisor general development libraries
Requires: xen-libs = %{version}
Requires: xen-devel = %{version}
Group: Development/Libraries
%description libs-devel
This package contains the Xen Hypervisor general development for all domains.

%package dom0-tools
Provides: gitsha(ssh://git@code.citrite.net/xsu/xen.git) = 6278553325a9f76d37811923221b21db3882e017
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = c9f65d58ccf70240b422b076e027b1f25d14b453
Summary: Xen Hypervisor Domain 0 tools
Requires: xen-dom0-libs = %{version}
Requires: xen-tools = %{version}
Requires: edk2
Requires: ipxe
%if %with_systemd
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
BuildRequires: systemd
%endif
Group: System/Base
%description dom0-tools
This package contains the Xen Hypervisor control domain tools.

%package dom0-libs
Provides: gitsha(ssh://git@code.citrite.net/xsu/xen.git) = 6278553325a9f76d37811923221b21db3882e017
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = c9f65d58ccf70240b422b076e027b1f25d14b453
Summary: Xen Hypervisor Domain 0 libraries
Requires: xen-hypervisor = %{version}
Group: System/Libraries
%description dom0-libs
This package contains the Xen Hypervisor control domain libraries.

%package dom0-libs-devel
Provides: gitsha(ssh://git@code.citrite.net/xsu/xen.git) = 6278553325a9f76d37811923221b21db3882e017
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = c9f65d58ccf70240b422b076e027b1f25d14b453
Summary: Xen Hypervisor Domain 0 headers
Requires: xen-devel = %{version}
Requires: xen-dom0-libs = %{version}

# Temp until the build dependencies are properly propagated
Provides: xen-dom0-devel = %{version}
Group: Development/Libraries
%description dom0-libs-devel
This package contains the Xen Hypervisor control domain headers.

%package ocaml-libs
Provides: gitsha(ssh://git@code.citrite.net/xsu/xen.git) = 6278553325a9f76d37811923221b21db3882e017
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = c9f65d58ccf70240b422b076e027b1f25d14b453
Summary: Xen Hypervisor ocaml libraries
Requires: xen-dom0-libs = %{version}
Group: System/Libraries
%description ocaml-libs
This package contains the Xen Hypervisor ocaml libraries.

%package ocaml-devel
Provides: gitsha(ssh://git@code.citrite.net/xsu/xen.git) = 6278553325a9f76d37811923221b21db3882e017
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = c9f65d58ccf70240b422b076e027b1f25d14b453
Summary: Xen Hypervisor ocaml headers
Requires: xen-ocaml-libs = %{version}
Requires: xen-dom0-libs-devel = %{version}
Group: Development/Libraries
%description ocaml-devel
This package contains the Xen Hypervisor ocaml headers.

%package installer-files
Provides: gitsha(ssh://git@code.citrite.net/xsu/xen.git) = 6278553325a9f76d37811923221b21db3882e017
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = c9f65d58ccf70240b422b076e027b1f25d14b453
Summary: Xen files for the XenServer installer
Group: System Environment/Base
%description installer-files
This package contains the minimal subset of libraries and binaries required in
the XenServer installer environment.

%prep
%autosetup -p1
%{?_cov_prepare}
%{?_coverity:cp misc/coverity/nodefs.h %{_cov_dir}/config/user_nodefs.h}
%{?_cov_make_model:%{_cov_make_model misc/coverity/model.c}}

base_cset=$(sed -ne 's/Changeset: \(.*\)/\1/p' < .gitarchive-info)
pq_cset=$(sed -ne 's/Changeset: \(.*\)/\1/p' < .gitarchive-info-pq)
echo "${base_cset:0:12}, pq ${pq_cset:0:12}" > .scmversion

%build

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
           --with-system-ovmf=/usr/share/edk2/OVMF.fd

%install

# The existence of this directory causes ocamlfind to put things in it
mkdir -p %{buildroot}%{_libdir}/ocaml/stublibs

mkdir -p %{buildroot}/boot/

# Regular build of Xen
%{__make} %{HVSOR_OPTIONS} -C xen XEN_VENDORVERSION=-%{release} \
    KCONFIG_CONFIG=../buildconfigs/config-release olddefconfig
%{__make} %{HVSOR_OPTIONS} -C xen XEN_VENDORVERSION=-%{release} \
    KCONFIG_CONFIG=../buildconfigs/config-release build
%{__make} %{HVSOR_OPTIONS} -C xen XEN_VENDORVERSION=-%{release} \
    KCONFIG_CONFIG=../buildconfigs/config-release MAP

cp xen/xen.gz %{buildroot}/boot/%{name}-%{version}-%{release}.gz
cp xen/System.map %{buildroot}/boot/%{name}-%{version}-%{release}.map
cp xen/xen-syms %{buildroot}/boot/%{name}-syms-%{version}-%{release}
cp buildconfigs/config-release %{buildroot}/boot/%{name}-%{version}-%{release}.config

# Debug build of Xen
%{__make} %{HVSOR_OPTIONS} -C xen clean
%{__make} %{HVSOR_OPTIONS} -C xen XEN_VENDORVERSION=-%{release}-d \
    KCONFIG_CONFIG=../buildconfigs/config-debug olddefconfig
%{?_cov_wrap} %{__make} %{HVSOR_OPTIONS} -C xen XEN_VENDORVERSION=-%{release}-d \
    KCONFIG_CONFIG=../buildconfigs/config-debug build
%{__make} %{HVSOR_OPTIONS} -C xen XEN_VENDORVERSION=-%{release}-d \
    KCONFIG_CONFIG=../buildconfigs/config-debug MAP

cp xen/xen.gz %{buildroot}/boot/%{name}-%{version}-%{release}-d.gz
cp xen/System.map %{buildroot}/boot/%{name}-%{version}-%{release}-d.map
cp xen/xen-syms %{buildroot}/boot/%{name}-syms-%{version}-%{release}-d
cp buildconfigs/config-debug %{buildroot}/boot/%{name}-%{version}-%{release}-d.config

# do not strip the hypervisor-debuginfo targerts
chmod -x %{buildroot}/boot/xen-syms-*

# Regular build of PV shim
cp buildconfigs/config-pvshim-release xen/arch/x86/configs/pvshim_defconfig
%{__make} %{TOOLS_OPTIONS} -C tools/firmware/xen-dir xen-shim
%{__install} -D -m 644 tools/firmware/xen-dir/xen-shim \
    %{buildroot}/%{_libexecdir}/%{name}/boot/xen-shim-release
%{__install} -D -m 644 tools/firmware/xen-dir/xen-shim-syms \
    %{buildroot}/usr/lib/debug/%{_libexecdir}/%{name}/boot/xen-shim-syms-release

# Debug build of PV shim
%{__make} %{TOOLS_OPTIONS} -C tools/firmware/xen-dir clean
cp buildconfigs/config-pvshim-debug xen/arch/x86/configs/pvshim_defconfig
%{?_cov_wrap} %{__make} %{TOOLS_OPTIONS} -C tools/firmware/xen-dir xen-shim
%{__install} -D -m 644 tools/firmware/xen-dir/xen-shim \
    %{buildroot}/%{_libexecdir}/%{name}/boot/xen-shim-debug
%{__install} -D -m 644 tools/firmware/xen-dir/xen-shim-syms \
    %{buildroot}/usr/lib/debug/%{_libexecdir}/%{name}/boot/xen-shim-syms-debug

# choose between debug and release PV shim build
%if %{default_debug_hypervisor}
ln -sf xen-shim-debug %{buildroot}/%{_libexecdir}/%{name}/boot/xen-shim
%else
ln -sf xen-shim-release %{buildroot}/%{_libexecdir}/%{name}/boot/xen-shim
%endif

# Build tools and man pages
%{?_cov_wrap} %{__make} %{TOOLS_OPTIONS} install-tools
%{__make} %{TOOLS_OPTIONS} -C docs install-man-pages
%{?_cov_wrap} %{__make} %{TOOLS_OPTIONS} -C tools/tests/mce-test/tools install

%{__install} -D -m 644 %{SOURCE1} %{buildroot}%{_sysconfdir}/sysconfig/kernel-xen
%{__install} -D -m 644 %{SOURCE2} %{buildroot}%{_sysconfdir}/xen/xl.conf
%{__install} -D -m 644 %{SOURCE3} %{buildroot}%{_sysconfdir}/logrotate.d/xen-tools
%{?_cov_install}

%files hypervisor
/boot/%{name}-%{version}-%{release}.gz
/boot/%{name}-%{version}-%{release}.map
/boot/%{name}-%{version}-%{release}.config
/boot/%{name}-%{version}-%{release}-d.gz
/boot/%{name}-%{version}-%{release}-d.map
/boot/%{name}-%{version}-%{release}-d.config
%config %{_sysconfdir}/sysconfig/kernel-xen
%ghost %attr(0644,root,root) %{_sysconfdir}/sysconfig/kernel-xen-args

%files hypervisor-debuginfo
/boot/%{name}-syms-%{version}-%{release}
/boot/%{name}-syms-%{version}-%{release}-d

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
%{python_sitearch}/%{name}/__init__.py*
%{python_sitearch}/%{name}/lowlevel/__init__.py*
%{python_sitearch}/%{name}/lowlevel/xs.so

%files devel
%{_includedir}/%{name}/COPYING
%{_includedir}/%{name}/arch-arm.h
%{_includedir}/%{name}/arch-arm/hvm/save.h
%{_includedir}/%{name}/arch-x86/cpuid.h
%{_includedir}/%{name}/arch-x86/cpufeatureset.h
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
%{_libdir}/libxenevtchn.so.1.1
%{_libdir}/libxengnttab.so.1
%{_libdir}/libxengnttab.so.1.2
%{_libdir}/libxenstore.so.3.0
%{_libdir}/libxenstore.so.3.0.3
%{_libdir}/libxentoolcore.so.1
%{_libdir}/libxentoolcore.so.1.0
%{_libdir}/libxenvchan.so.4.13
%{_libdir}/libxenvchan.so.4.13.0

%files libs-devel
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

# Lib Xen Vchan
%{_includedir}/libxenvchan.h
%{_libdir}/libxenvchan.a
%{_libdir}/libxenvchan.so
%{_libdir}/pkgconfig/xenvchan.pc

%files dom0-tools
%{_sysconfdir}/bash_completion.d/xl.sh
%exclude %{_sysconfdir}/rc.d/init.d/xencommons
%exclude %{_sysconfdir}/rc.d/init.d/xendomains
%exclude %{_sysconfdir}/rc.d/init.d/xendriverdomain
%exclude %{_sysconfdir}/sysconfig/xendomains
%if %with_systemd
%exclude %{_sysconfdir}/rc.d/init.d/xen-watchdog
%else
%{_sysconfdir}/rc.d/init.d/xen-watchdog
%endif
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
%{_sysconfdir}/xen/scripts/vif2
%{_sysconfdir}/xen/scripts/vscsi
%{_sysconfdir}/xen/scripts/xen-hotplug-common.sh
%{_sysconfdir}/xen/scripts/xen-network-common.sh
%{_sysconfdir}/xen/scripts/xen-script-common.sh
%exclude %{_sysconfdir}/%{name}/cpupool
%exclude %{_sysconfdir}/%{name}/README
%exclude %{_sysconfdir}/%{name}/README.incompatibilities
%exclude %{_sysconfdir}/%{name}/xlexample.hvm
%exclude %{_sysconfdir}/%{name}/xlexample.pvlinux
%config %{_sysconfdir}/xen/xl.conf
%{_bindir}/pygrub
%{_bindir}/xen-cpuid
%{_bindir}/xen-detect
%{_bindir}/xenalyze
%{_bindir}/xencons
%{_bindir}/xencov_split
%{_bindir}/xentrace_format
%{python_sitearch}/xenfsimage.so
%{python_sitearch}/grub/ExtLinuxConf.py*
%{python_sitearch}/grub/GrubConf.py*
%{python_sitearch}/grub/LiloConf.py*
%{python_sitearch}/grub/__init__.py*
%{python_sitearch}/pygrub-*.egg-info
%{python_sitearch}/xen-*.egg-info
#{python_sitearch}/xen/__init__.py*           - Must not duplicate xen-tools
#{python_sitearch}/xen/lowlevel/__init__.py*  - Must not duplicate xen-tools
%{python_sitearch}/xen/lowlevel/xc.so
%{python_sitearch}/xen/migration/__init__.py*
%{python_sitearch}/xen/migration/legacy.py*
%{python_sitearch}/xen/migration/libxc.py*
%{python_sitearch}/xen/migration/libxl.py*
%{python_sitearch}/xen/migration/public.py*
%{python_sitearch}/xen/migration/tests.py*
%{python_sitearch}/xen/migration/verify.py*
%{python_sitearch}/xen/migration/xl.py*
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
%{_libexecdir}/%{name}/bin/xenpvnetboot
%{_libexecdir}/%{name}/boot/hvmloader
%{_libexecdir}/%{name}/boot/xen-shim
%{_libexecdir}/%{name}/boot/xen-shim-release
%{_libexecdir}/%{name}/boot/xen-shim-debug
%{_sbindir}/flask-get-bool
%{_sbindir}/flask-getenforce
%{_sbindir}/flask-label-pci
%{_sbindir}/flask-loadpolicy
%{_sbindir}/flask-set-bool
%{_sbindir}/flask-setenforce
%{_sbindir}/gdbsx
%{_sbindir}/oxenstored
%{_sbindir}/xen-diag
%{_sbindir}/xen-hptool
%{_sbindir}/xen-hvmcrash
%{_sbindir}/xen-hvmctx
%{_sbindir}/xen-kdd
%{_sbindir}/xen-livepatch
%{_sbindir}/xen-lowmemd
%{_sbindir}/xen-mceinj
%{_sbindir}/xen-mfndump
%{_sbindir}/xen-spec-ctrl
%{_sbindir}/xen-ucode
%{_sbindir}/xen-vmdebug
%{_sbindir}/xenbaked
%{_sbindir}/xenconsoled
%{_sbindir}/xencov
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
%{_mandir}/man5/xl.cfg.5.gz
%{_mandir}/man5/xl.conf.5.gz
%{_mandir}/man5/xlcpupool.cfg.5.gz
%{_mandir}/man7/xen-pci-device-reservations.7.gz
%{_mandir}/man7/xen-pv-channel.7.gz
%{_mandir}/man7/xen-tscmode.7.gz
%{_mandir}/man7/xen-vbd-interface.7.gz
%{_mandir}/man7/xl-numa-placement.7.gz
%exclude %{_mandir}/man7/xen-vtpm.7.gz
%exclude %{_mandir}/man7/xen-vtpmmgr.7.gz
%{_mandir}/man8/xentrace.8.gz
%dir /var/lib/xen
%dir /var/log/xen
%if %with_systemd
%{_unitdir}/proc-xen.mount
%{_unitdir}/var-lib-xenstored.mount
%{_unitdir}/xen-init-dom0.service
%{_unitdir}/xen-watchdog.service
%{_unitdir}/xenconsoled.service
%{_unitdir}/xenstored.service
%exclude %{_prefix}/lib/modules-load.d/xen.conf
%exclude %{_unitdir}/xen-qemu-dom0-disk-backend.service
%exclude %{_unitdir}/xendomains.service
%exclude %{_unitdir}/xendriverdomain.service
%endif

%files dom0-libs
%{_libdir}/libxencall.so.1
%{_libdir}/libxencall.so.1.2
%{_libdir}/libxenctrl.so.4.13
%{_libdir}/libxenctrl.so.4.13.0
%{_libdir}/libxendevicemodel.so.1
%{_libdir}/libxendevicemodel.so.1.3
%{_libdir}/libxenforeignmemory.so.1
%{_libdir}/libxenforeignmemory.so.1.3
%{_libdir}/libxenfsimage.so.4.13
%{_libdir}/libxenfsimage.so.4.13.0
%{_libdir}/libxenguest.so.4.13
%{_libdir}/libxenguest.so.4.13.0
%{_libdir}/libxenlight.so.4.13
%{_libdir}/libxenlight.so.4.13.0
%{_libdir}/libxenstat.so.4.13
%{_libdir}/libxenstat.so.4.13.0
%{_libdir}/libxentoollog.so.1
%{_libdir}/libxentoollog.so.1.0
%{_libdir}/libxlutil.so.4.13
%{_libdir}/libxlutil.so.4.13.0
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

%{_includedir}/xentoollog.h
%{_libdir}/libxentoollog.a
%{_libdir}/libxentoollog.so
%{_libdir}/pkgconfig/xentoollog.pc

%{_includedir}/_libxl_list.h
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
%{_libdir}/ocaml/stublibs/dllxenbus_stubs.so
%{_libdir}/ocaml/stublibs/dllxenbus_stubs.so.owner
%{_libdir}/ocaml/stublibs/dllxenctrl_stubs.so
%{_libdir}/ocaml/stublibs/dllxenctrl_stubs.so.owner
%{_libdir}/ocaml/stublibs/dllxeneventchn_stubs.so
%{_libdir}/ocaml/stublibs/dllxeneventchn_stubs.so.owner
%{_libdir}/ocaml/stublibs/dllxenlight_stubs.so
%{_libdir}/ocaml/stublibs/dllxenlight_stubs.so.owner
%{_libdir}/ocaml/stublibs/dllxenmmap_stubs.so
%{_libdir}/ocaml/stublibs/dllxenmmap_stubs.so.owner
%{_libdir}/ocaml/stublibs/dllxentoollog_stubs.so
%{_libdir}/ocaml/stublibs/dllxentoollog_stubs.so.owner
%{_libdir}/ocaml/xenbus/META
%{_libdir}/ocaml/xenbus/xenbus.cma
%{_libdir}/ocaml/xenbus/xenbus.cmo
%{_libdir}/ocaml/xenctrl/META
%{_libdir}/ocaml/xenctrl/xenctrl.cma
%{_libdir}/ocaml/xeneventchn/META
%{_libdir}/ocaml/xeneventchn/xeneventchn.cma
%{_libdir}/ocaml/xenlight/META
%{_libdir}/ocaml/xenlight/xenlight.cma
%{_libdir}/ocaml/xenmmap/META
%{_libdir}/ocaml/xenmmap/xenmmap.cma
%exclude %{_libdir}/ocaml/xenstore/META
%exclude %{_libdir}/ocaml/xenstore/xenstore.cma
%exclude %{_libdir}/ocaml/xenstore/xenstore.cmo
%{_libdir}/ocaml/xentoollog/META
%{_libdir}/ocaml/xentoollog/xentoollog.cma

%files ocaml-devel
%{_libdir}/ocaml/xenbus/libxenbus_stubs.a
%{_libdir}/ocaml/xenbus/xenbus.a
%{_libdir}/ocaml/xenbus/xenbus.cmi
%{_libdir}/ocaml/xenbus/xenbus.cmx
%{_libdir}/ocaml/xenbus/xenbus.cmxa
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
%{_libdir}/ocaml/xenlight/libxenlight_stubs.a
%{_libdir}/ocaml/xenlight/xenlight.a
%{_libdir}/ocaml/xenlight/xenlight.cmi
%{_libdir}/ocaml/xenlight/xenlight.cmx
%{_libdir}/ocaml/xenlight/xenlight.cmxa
%{_libdir}/ocaml/xenmmap/libxenmmap_stubs.a
%{_libdir}/ocaml/xenmmap/xenmmap.a
%{_libdir}/ocaml/xenmmap/xenmmap.cmi
%{_libdir}/ocaml/xenmmap/xenmmap.cmx
%{_libdir}/ocaml/xenmmap/xenmmap.cmxa
%exclude %{_libdir}/ocaml/xenstore/xenstore.a
%exclude %{_libdir}/ocaml/xenstore/xenstore.cmi
%exclude %{_libdir}/ocaml/xenstore/xenstore.cmx
%exclude %{_libdir}/ocaml/xenstore/xenstore.cmxa
%{_libdir}/ocaml/xentoollog/libxentoollog_stubs.a
%{_libdir}/ocaml/xentoollog/xentoollog.a
%{_libdir}/ocaml/xentoollog/xentoollog.cmi
%{_libdir}/ocaml/xentoollog/xentoollog.cmx
%{_libdir}/ocaml/xentoollog/xentoollog.cmxa

%files installer-files
%{_libdir}/libxenctrl.so.4.13
%{_libdir}/libxenctrl.so.4.13.0
%{_libdir}/libxenguest.so.4.13
%{_libdir}/libxenguest.so.4.13.0
%{python_sitearch}/xen/__init__.py*
%{python_sitearch}/xen/lowlevel/__init__.py*
%{python_sitearch}/xen/lowlevel/xc.so

%doc

%post hypervisor
# Update the debug and release symlinks
ln -sf %{name}-%{version}-%{release}-d.gz /boot/xen-debug.gz
ln -sf %{name}-%{version}-%{release}.gz /boot/xen-release.gz

# Point /boot/xen.gz appropriately
if [ ! -e /boot/xen.gz ]; then
%if %{default_debug_hypervisor}
    # Use a debug hypervisor by default
    ln -sf %{name}-%{version}-%{release}-d.gz /boot/xen.gz
%else
    # Use a production hypervisor by default
    ln -sf %{name}-%{version}-%{release}.gz /boot/xen.gz
%endif
else
    # Else look at the current link, and whether it is debug
    path="`readlink -f /boot/xen.gz`"
    if [ ${path} != ${path%%-d.gz} ]; then
        ln -sf %{name}-%{version}-%{release}-d.gz /boot/xen.gz
    else
        ln -sf %{name}-%{version}-%{release}.gz /boot/xen.gz
    fi
fi

if [ -e %{_sysconfdir}/sysconfig/kernel ] && ! grep -q '^HYPERVISOR' %{_sysconfdir}/sysconfig/kernel ; then
  cat %{_sysconfdir}/sysconfig/kernel-xen >> %{_sysconfdir}/sysconfig/kernel
fi

mkdir -p %{_rundir}/reboot-required.d/%{name}
touch %{_rundir}/reboot-required.d/%{name}/%{version}-%{release}

%if %with_systemd
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
%endif

%{?_cov_results_package}

%changelog
* Wed Dec 16 2020 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.1-9.8.2
- Security update
- Related to XSAs 115, 322, 323, 324, 325, 330, 348, 352, 353, 358, 359
- See http://xenbits.xen.org/xsa/
- Reboot required

* Tue Nov 24 2020 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.1-9.7.1
- Security update
- Related to XSA-355
- See http://xenbits.xen.org/xsa/advisory-355.html
- Reboot required

* Thu Nov 12 2020 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.1-9.6.1
- Security update
- Related to XSA-351
- See http://xenbits.xen.org/xsa/advisory-351.html
- Patch for XSA-286 rewritten for better performance.
- Reboot required

* Tue Oct 27 2020 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.1-9.5.1
- Security update
- Related to XSAs 286, 345, 346, 347
- See http://xenbits.xen.org/xsa/
- Reboot required

* Wed Sep 23 2020 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.1-9.3.1
- Security update
- Related to XSAs 333, 334, 336, 337, 338, 339, 340, 342, 343, 344
- See http://xenbits.xen.org/xsa/
- Reboot required
- Also remove xen-4.13.1-insert-Ice-Lake-and-Comet-Lake-model-numbers.backport.patch, not needed anymore

* Sun Sep 06 2020 Rushikesh Jadhav <rushikesh7@gmail.com> - 4.13.1-9.2.2
- Insert Ice Lake and Comet Lake model numbers

* Thu Jul 09 2020 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.1-9.2.1
- Security update
- Related to XSA-317, XSA-319, XSA-321, XSA-328
- See http://xenbits.xen.org/xsa/
- Reboot required

* Wed Jul 01 2020 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.1-9.1.1
- Rebase on CH 8.2

* Fri Jun 12 2020 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.0-8.5.1
- Update for new microcode related to SRBDS Intel issues
- Related to XSA-320
- See http://xenbits.xen.org/xsa/
- Reboot required

* Tue Apr 14 2020 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.0-8.4
- Security update
- Related to XSA-307, XSA-313, XSA-316, XSA-318
- See http://xenbits.xen.org/xsa/
- Reboot required

* Thu Dec 19 2019 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.0-8.3
- Rebase on CH 8.1
- Drop our changes to xenguest for max_grant_frames

* Thu Dec 12 2019 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.11.1-7.8
- Security update
- Related to XSA-308, XSA-309, XSA-310, XSA-311
- See http://xenbits.xen.org/xsa/
- Reboot required

* Wed Nov 13 2019 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.11.1-7.7
- Security update
- Related to XSA-304 and XSA-305
- See http://xenbits.xen.org/xsa/
- Reboot required

* Mon Nov 04 2019 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.11.1-7.6
- Security update
- Fix XSA-296, XSA-298, XSA-299, XSA-302
- See http://xenbits.xen.org/xsa/
- Reboot required

* Fri Oct 18 2019 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.11.1-7.5.2
- Make max_grant_frames and max_maptrack_frames configurable
- Default value of max_grant_frames is not sufficient in some cases
- VM params platform/max_grant_frames and max_maptrack_frames are now used
- Refs https://github.com/xcp-ng/xcp/issues/289

* Fri Aug 30 2019 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.11.1-7.5.1
- Fix a possible memory corruption when forcibly shutting down a VM with AMD MxGPU attached
- Fix a possible host crash when forcibly shutting a Windows VMs that is in an unclean state
- After a live migration, a Windows VM could hang for more than a minute
- Windows VMs with the viridian_reference_tsc flag enabled could crash during migration
- Patches imported from XS 8.0 hotfix XS80E004

* Thu May 16 2019 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.11.1-7.3
- Security update
- Fix XSA-297
- See http://xenbits.xen.org/xsa/advisory-297.html
- Reboot required

* Mon Apr 29 2019 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.11.1-7.2
- Update for XCP-ng 8.0

* Thu Mar 07 2019 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.7.6-6.4.1
- Security update
- Fix XSA-283, XSA-284, XSA-285, XSA-287, XSA-288, XSA-290, XSA-292, XSA-293 and XSA-294
- See http://xenbits.xen.org/xsa/
- Reboot required

* Tue Nov 20 2018 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.7.6-6.3.1.xcp
- Security update
- Fix XSA-275, XSA-279, XSA-280 and XSA-282

* Fri Oct 26 2018 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.7.6-6.2.1.xcp
- Security update
- Fix CVE-2018-TBA: Nested VT-x usable even when disabled

* Thu Sep 13 2018 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.7.6-6.1.1.xcp
- Update for XCP-ng 7.6

* Wed Aug 15 2018 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.7.5-5.5.1xcp
- Multiple security updates

* Thu Aug 02 2018 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.7.5-5.4.1xcp
- Security update
- Fix CVE-2018-12893: x86: #DB exception safety check can be triggered by a guest
- Fix CVE-2018-12891: preemption checks bypassed in x86 PV MM handling
