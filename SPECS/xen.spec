# -*- rpm-spec -*-

%define with_sysv 0
%define with_systemd 1

# Use the production hypervisor by default
%define default_debug_hypervisor 0

%define COMMON_OPTIONS DESTDIR=%{buildroot} %{?_smp_mflags}
%define HVSOR_OPTIONS %{COMMON_OPTIONS} XEN_TARGET_ARCH=x86_64
%define TOOLS_OPTIONS %{COMMON_OPTIONS} XEN_TARGET_ARCH=x86_64 debug=n

%define base_cset RELEASE-%{version}
%define base_dir  %{name}-%{version}

Summary: Xen is a virtual machine monitor
Name:    xen
Version: 4.13.4
# the xen_extra field can't hold more than 16 chars
# so instead of using %%release to define XEN_VENDORVERSION
# we create a base_release macro, that doesn't contain the dist suffix
%define base_release 9.25.1
Release: %{base_release}%{?dist}
License: GPLv2 and LGPLv2 and MIT and Public Domain
URL:     http://www.xenproject.org

Source0: https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.13.4&prefix=xen-4.13.4&format=tar.gz#/xen-4.13.4.tar.gz
Source1: SOURCES/xen/sysconfig_kernel-xen
Source2: SOURCES/xen/xl.conf
Source3: SOURCES/xen/logrotate-xen-tools

Patch0: build-tweaks.patch
Patch1: autoconf-libjson.patch
Patch2: configure-build.patch
Patch3: changeset-info.patch
Patch4: xenserver-configuration.patch
Patch5: coverity-model.patch
Patch6: backport-b4bb02d5999a.patch
Patch7: backport-0b28069aa7c2.patch
Patch8: backport-d94d006ed360.patch
Patch9: backport-d3cfb4b3a680.patch
Patch10: backport-d3c2319ea165.patch
Patch11: backport-e48c7878e54a.patch
Patch12: backport-ce49a1d6d819.patch
Patch13: backport-7b9814b250a5.patch
Patch14: backport-8ed46cc1ef14.patch
Patch15: backport-2ce2aec8c148.patch
Patch16: backport-920e93df4e16.patch
Patch17: backport-650b888c8a0a.patch
Patch18: backport-81918cead1a5.patch
Patch19: backport-33c13654cb6d.patch
Patch20: backport-235aa158e0f7.patch
Patch21: backport-73e25ecaef14.patch
Patch22: backport-92acf6b23154.patch
Patch23: backport-ab37463eec57.patch
Patch24: backport-7cfe3570b1c0.patch
Patch25: backport-e6d6b5ba030a.patch
Patch26: backport-454d5351a93d.patch
Patch27: backport-169a2834ef5d.patch
Patch28: backport-a6902a65160a.patch
Patch29: backport-d64d46685c77.patch
Patch30: backport-fe97133b5dee.patch
Patch31: backport-3826ba5f8271.patch
Patch32: backport-7669737d7da5.patch
Patch33: backport-c7da430b21e0.patch
Patch34: backport-fce392fa36c3.patch
Patch35: backport-8d9f36132afd.patch
Patch36: backport-e8c04e468312.patch
Patch37: backport-f9ae12fc103c.patch
Patch38: backport-1575075b2e3a.patch
Patch39: backport-a84bc5bde583.patch
Patch40: backport-413b08328a57.patch
Patch41: backport-87ff11354f0d.patch
Patch42: backport-14c5e0c13422.patch
Patch43: backport-8a2cc1ed1aee.patch
Patch44: backport-f614e3c51ae0.patch
Patch45: backport-4eddf132b5e0.patch
Patch46: backport-d43b47eb6a26.patch
Patch47: backport-55e4c720b269.patch
Patch48: backport-8974821f13ad.patch
Patch49: backport-bf5f5e89f040.patch
Patch50: backport-074e388fe0df.patch
Patch51: backport-b8d573a31beb.patch
Patch52: backport-159e2235d75b.patch
Patch53: backport-a7e72872e99b.patch
Patch54: backport-4b42462701f0.patch
Patch55: backport-10d8c56e93a0.patch
Patch56: backport-196b4f4d34d4.patch
Patch57: backport-ba3367292342.patch
Patch58: backport-fbf19baaaf5c.patch
Patch59: backport-5994b739453f.patch
Patch60: backport-ebe3f5d90924.patch
Patch61: backport-3c71016e68f2.patch
Patch62: backport-3feba68e15d3.patch
Patch63: backport-f8614c7153f9.patch
Patch64: backport-c946524a65f3.patch
Patch65: backport-cd7dedad8209.patch
Patch66: backport-79cf0989175c.patch
Patch67: backport-6dd95b02ea27.patch
Patch68: backport-0cd791c499bd.patch
Patch69: backport-9356f9de4162.patch
Patch70: backport-c08cbf7fb891.patch
Patch71: backport-3d05407025ed.patch
Patch72: backport-b1710040ca96.patch
Patch73: backport-31bf4f26aa17.patch
Patch74: backport-e9bd648015dd.patch
Patch75: backport-da9290639eb5.patch
Patch76: backport-7b3c5b70a323.patch
Patch77: backport-1171a93b6ca7.patch
Patch78: backport-2004db3ced18.patch
Patch79: backport-59e1f6d89710.patch
Patch80: backport-86cf92f50533.patch
Patch81: backport-0a9c44486b90.patch
Patch82: backport-270ff9a835fb.patch
Patch83: backport-dacb80f9757c.patch
Patch84: backport-1b3cec69bf30.patch
Patch85: backport-8171e0796542.patch
Patch86: backport-9649cef3b3a7.patch
Patch87: backport-a798bac54fe8.patch
Patch88: backport-920d5f31883c.patch
Patch89: backport-c9495bd7dff5.patch
Patch90: backport-53ddfc80a84a.patch
Patch91: backport-a9b6dacf88fe.patch
Patch92: backport-7ff66809ccd5.patch
Patch93: backport-53594c7bd197.patch
Patch94: backport-540d4d60378c.patch
Patch95: backport-3174835ba825.patch
Patch96: backport-c2b4e23fdda4.patch
Patch97: backport-e9aca9470ed8.patch
Patch98: backport-68d757df8dd2.patch
Patch99: backport-17b997aa1edb.patch
Patch100: backport-35b819c45c46.patch
Patch101: backport-d8a6a8b36d86.patch
Patch102: backport-4489ffdec331.patch
Patch103: backport-ab5bfc049e8e.patch
Patch104: backport-dc036ab9d506.patch
Patch105: backport-b9e9ccbb11e4.patch
Patch106: backport-b6641f28c593.patch
Patch107: backport-a85f67b2658e.patch
Patch108: backport-758fae24d7b9.patch
Patch109: backport-e373bc1bdc59.patch
Patch110: backport-b7c333016e3d.patch
Patch111: backport-7e5cffcd1e93.patch
Patch112: backport-81b2b328a26c.patch
Patch113: backport-60390ccb8b9b.patch
Patch114: backport-570da5423dbe.patch
Patch115: backport-0eae016b6e3d.patch
Patch116: backport-f40e1c52e4e0.patch
Patch117: backport-368096b9c4a2.patch
Patch118: backport-e21a6a4f966a.patch
Patch119: backport-935d501ccbf5.patch
Patch120: backport-fb23e8ba2304.patch
Patch121: backport-08693c03e00e.patch
Patch122: backport-95419adfd4b2.patch
Patch123: backport-f17d848c4caa-fix.patch
Patch124: backport-3670abcaf032.patch
Patch125: backport-9fdcf851689c.patch
Patch126: backport-3e09045991cd.patch
Patch127: backport-b672695e7488.patch
Patch128: backport-79ca512a1fa6.patch
Patch129: backport-6a9f5477637a.patch
Patch130: backport-93c9edbef51b.patch
Patch131: backport-73c932d0ea43.patch
Patch132: backport-1787cc167906.patch
Patch133: backport-afab477fba3b.patch
Patch134: backport-c76cfada1cfa.patch
Patch135: backport-f26bb285949b.patch
Patch136: backport-4624912c0b55.patch
Patch137: backport-2928c1d250b1.patch
Patch138: backport-6d45368a0a89.patch
Patch139: backport-b17546d7f33e.patch
Patch140: backport-164a0b9653f4.patch
Patch141: backport-737190abb174.patch
Patch142: backport-e083d753924b.patch
Patch143: backport-91bac8ad7c06.patch
Patch144: backport-dd6c062a7a4a.patch
Patch145: backport-9c3b9800e201.patch
Patch146: backport-b11380f6cd58.patch
Patch147: backport-b6b672e8a925.patch
Patch148: backport-834cb8761051.patch
Patch149: backport-eb7518b89be6.patch
Patch150: backport-31f3bc97f450.patch
Patch151: backport-88d3ff7ab15d.patch
Patch152: backport-6536688439db.patch
Patch153: backport-81f0eaadf84d.patch
Patch154: backport-e3662437eb43.patch
Patch155: x86-cpuid-Infrastructure-for-leaf-0x80000021.eax.patch
Patch156: backport-e1828e3032eb.patch
Patch157: backport-969a57f73f6b.patch
Patch158: backport-15b7611efd49.patch
Patch159: backport-00f2992b6c7a.patch
Patch160: backport-614cec7d79d7.patch
Patch161: backport-22b9add22b4a.patch
Patch162: backport-a7e7c7260cde.patch
Patch163: backport-39a40f3835ef.patch
Patch164: backport-4116139131e9.patch
Patch165: backport-ad9f7c3b2e0d.patch
Patch166: backport-f3709b15fc86.patch
Patch167: backport-52ce1c97844d.patch
Patch168: backport-81d195c6c0e2.patch
Patch169: backport-f627a39c5e75.patch
Patch170: backport-6ba701064227.patch
Patch171: backport-7f7e55b85fce.patch
Patch172: backport-ea140035d01a.patch
Patch173: backport-60d1adfa1879.patch
Patch174: backport-e570e8d520ab.patch
Patch175: 0001-x86-AMD-make-HT-range-dynamic-for-Fam17-and-up.patch
Patch176: 0001-tools-Fix-pkg-config-file-for-libxenstore.patch
Patch177: 0006-x86-vpt-fix-injection-to-remote-vCPU.patch
Patch178: 0003-xen-microcode-add-information-about-currently-loaded.patch
Patch179: 0004-microcode-add-sequential-application-policy.patch
Patch180: 0007-microcode-update-raw-cpuid-policy-after-a-successful.patch
Patch181: 0001-microcode-remove-panic-calls.patch
Patch182: detect-nehalem-c-state.patch
Patch183: quirk-hp-gen8-rmrr.patch
Patch184: quirk-pci-phantom-function-devices.patch
Patch185: 0001-x86-hpet-Pre-cleanup.patch
Patch186: 0002-x86-hpet-Use-singe-apic-vector-rather-than-irq_descs.patch
Patch187: 0003-x86-hpet-Post-cleanup.patch
Patch188: 0002-libxc-retry-shadow-ops-if-EBUSY-is-returned.patch
Patch189: avoid-gnt-unmap-tlb-flush-if-not-accessed.patch
Patch190: 0002-efi-Ensure-incorrectly-typed-runtime-services-get-ma.patch
Patch191: 0001-x86-time-Don-t-use-EFI-s-GetTime-call.patch
Patch192: 0001-efi-Workaround-page-fault-during-runtime-service.patch
Patch193: 0001-x86-HVM-Avoid-cache-flush-operations-during-hvm_load.patch
Patch194: 0001-libxl-Don-t-insert-PCI-device-into-xenstore-for-HVM-.patch
Patch195: 0001-x86-PoD-Command-line-option-to-prohibit-any-PoD-oper.patch
Patch196: livepatch-ignore-duplicate-new.patch
Patch197: default-log-level-info.patch
Patch198: 0001-lib-Add-a-generic-implementation-of-current_text_add.patch
Patch199: 0002-sched-Remove-dependency-on-__LINE__-for-release-buil.patch
Patch200: pygrub-Ignore-GRUB2-if-statements.patch
Patch201: libfsimage-Add-support-for-btrfs.patch
Patch202: quiet-broke-irq-affinity.patch
Patch203: 0001-x86-msr-Blacklist-various-MSRs-which-guests-definite.patch
Patch204: 0001-Hide-AVX-512-from-guests-by-default.patch
Patch205: 0001-common-page_alloc-don-t-idle-scrub-before-microcode-.patch
Patch206: 0001-xsm-hide-detailed-Xen-version-from-unprivileged-gues.patch
Patch207: xen-tweak-cmdline-defaults.patch
Patch208: xen-tweak-debug-overhead.patch
Patch209: tweak-iommu-policy.patch
Patch210: tweak-sc-policy.patch
Patch211: disable-core-parking.patch
Patch212: 0001-Allocate-space-in-structs-pre-emptively-to-increase-.patch
Patch213: 0001-x86-mm-partially-revert-37201c62-make-logdirty-and-i.patch
Patch214: hitachi-driver-domain-ssid.patch
Patch215: livepatch-payload-in-header.patch
Patch216: xen-define-offsets-for-kdump.patch
Patch217: xen-scheduler-auto-privdom-weight.patch
Patch218: xen-hvm-disable-tsc-ramping.patch
Patch219: xen-default-cpufreq-governor-to-performance-on-intel.patch
Patch220: 0001-Partially-revert-08754333892-hvmloader-limit-CPUs-ex.patch
Patch221: 0001-x86-pv-silently-discard-writes-into-MSR_AMD64_LS_CFG.patch
Patch222: i8259-timers-pick-online-vcpu.patch
Patch223: revert-ca2eee92df44.patch
Patch224: libxc-stubs-hvm_check_pvdriver.patch
Patch225: libxc-cpuid-cores_per_socket.patch
Patch226: pygrub-add-default-and-extra-args.patch
Patch227: pygrub-always-boot-default.patch
Patch228: pygrub-friendly-no-fs.patch
Patch229: pygrub-image-max-size.patch
Patch230: pygrub-default-xenmobile-kernel.patch
Patch231: pygrub-blacklist-support.patch
Patch232: oem-bios-xensource.patch
Patch233: oem-bios-magic-from-xenstore.patch
Patch234: misc-log-guest-consoles.patch
Patch235: fix-ocaml-libs.patch
Patch236: retrofit-max-featuresets.patch
Patch237: 0005-x86-msr-Expose-cpu_has_tsx_ctrl-via-MSR_ARCH_CAPS.patch
Patch238: ocaml-cpuid-helpers.patch
Patch239: xentop-vbd3.patch
Patch240: mixed-domain-runstates.patch
Patch241: xenguest.patch
Patch242: xen-vmdebug.patch
Patch243: oxenstore-censor-sensitive-data.patch
Patch244: oxenstore-large-packets.patch
Patch245: 0019-tools-xenstore-add-live-update-command-to-xenstore-c.patch
Patch246: 0001-tools-ocaml-xenstored-only-quit-on-SIGTERM-when-a-re.patch
Patch247: 0002-tools-ocaml-xenstored-Automatically-resume-when-poss.patch
Patch248: 0003-tools-ocaml-xenstored-add-cooperative-live-update-co.patch
Patch249: 0004-tools-ocaml-xenstored-start-live-update-process.patch
Patch250: 0006-tools-ocaml-xenstored-implement-socket-live-update.patch
Patch251: pv-shim-compat-dmc.patch
Patch252: nvidia-vga.patch
Patch253: hvmloader-disable-pci-option-rom-loading.patch
Patch254: xen-force-software-vmcs-shadow.patch
Patch255: 0001-x86-vvmx-add-initial-PV-EPT-support-in-L0.patch
Patch256: use-msr-ll-instead-of-vmcs-efer.patch
Patch257: add-pv-iommu-headers.patch
Patch258: add-pv-iommu-local-domain-ops.patch
Patch259: add-pv-iommu-foreign-support.patch
Patch260: upstream-pv-iommu-tools.patch
Patch261: allow-rombios-pci-config-on-any-host-bridge.patch
Patch262: 0007-hypercall-XENMEM_get_mfn_from_pfn.patch
Patch263: gvt-g-hvmloader+rombios.patch
Patch264: xen-introduce-cmdline-to-control-introspection-extensions.patch
Patch265: xen-domctl-set-privileged-domain.patch
Patch266: xen-reexecute-instn-under-monitor-trap.patch
Patch267: revert-x86-mm-suppress-vm_events-caused-by-page-walks.patch
Patch268: xen-emulate-Bypass-the-emulator-if-emulation-fails.patch
Patch269: xen-introspection-pause.patch
Patch270: xen-always-enable-altp2m-external-mode.patch
Patch271: 0001-x86-add-XEN_SYSCTL_spec_ctrl.patch
Patch272: 0002-x86-add-xen-spec-ctrl-utility.patch

Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.13.4&prefix=xen-4.13.4&format=tar.gz#/xen-4.13.4.tar.gz) = 6e2fc128eb1a7d8ff8c36123a0a03e4e60a4a44c
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = 8f56b56afc6e15e142d90d92e0b7228900f1772c


ExclusiveArch: x86_64

## Pull in the correct RPM macros for the distributon
## (Any fedora which is still in support uses python3)
%if 0%{?centos} > 7 || 0%{?rhel} > 7 || 0%{?fedora} > 0
BuildRequires: python3-devel
BuildRequires: python3-rpm-macros
%global py_sitearch %{python3_sitearch}
%global __python %{__python3}
%else
# XCP-ng: in 8.2 CU1, Citrix changed buildrequires from python-devel to python2-devel + python2-rpm-macros
# This would imply updating python both in build system and on hosts, but Citrix did not do the latter.
# So we stick to python-devel for now and will switch to the new buildrequires only when python is updated.
#BuildRequires: python2-devel
#BuildRequires: python2-rpm-macros
BuildRequires: python-devel
%global py_sitearch %{python2_sitearch}
%global __python %{__python2}
%endif

# For HVMLoader and 16/32bit firmware
BuildRequires: dev86 iasl

# For the domain builder (decompression and hashing)
BuildRequires: zlib-devel bzip2-devel xz-devel
BuildRequires: openssl-devel

# For libxl
BuildRequires: yajl-devel libuuid-devel perl

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
BuildRequires: perl-podlators

# Misc
BuildRequires: libtool
%if %with_systemd
BuildRequires: systemd-devel
%endif

# Need cov-analysis if coverity is enabled
%{?_cov_buildrequires}

%description
Xen Hypervisor.

%package hypervisor
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.13.4&prefix=xen-4.13.4&format=tar.gz#/xen-4.13.4.tar.gz) = 6e2fc128eb1a7d8ff8c36123a0a03e4e60a4a44c
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = 8f56b56afc6e15e142d90d92e0b7228900f1772c
Summary: The Xen Hypervisor
License: GPLv2
Group: System/Hypervisor
Requires(post): coreutils grep
%description hypervisor
This package contains the Xen Project Hypervisor.

%package hypervisor-debuginfo
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.13.4&prefix=xen-4.13.4&format=tar.gz#/xen-4.13.4.tar.gz) = 6e2fc128eb1a7d8ff8c36123a0a03e4e60a4a44c
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = 8f56b56afc6e15e142d90d92e0b7228900f1772c
Summary: The Xen Hypervisor debug information
License: GPLv2
Group: Development/Debug
%description hypervisor-debuginfo
This package contains the Xen Hypervisor debug information.

%package tools
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.13.4&prefix=xen-4.13.4&format=tar.gz#/xen-4.13.4.tar.gz) = 6e2fc128eb1a7d8ff8c36123a0a03e4e60a4a44c
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = 8f56b56afc6e15e142d90d92e0b7228900f1772c
Summary: Xen Hypervisor general tools
License: GPLv2 and LGPLv2
Requires: xen-libs = %{version}
Group: System/Base
%description tools
This package contains the Xen Hypervisor general tools for all domains.

%package devel
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.13.4&prefix=xen-4.13.4&format=tar.gz#/xen-4.13.4.tar.gz) = 6e2fc128eb1a7d8ff8c36123a0a03e4e60a4a44c
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = 8f56b56afc6e15e142d90d92e0b7228900f1772c
Summary: The Xen Hypervisor public headers
License: MIT and Public Domain
Group: Development/Libraries
%description devel
This package contains the Xen Hypervisor public header files.

%package libs
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.13.4&prefix=xen-4.13.4&format=tar.gz#/xen-4.13.4.tar.gz) = 6e2fc128eb1a7d8ff8c36123a0a03e4e60a4a44c
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = 8f56b56afc6e15e142d90d92e0b7228900f1772c
Summary: Xen Hypervisor general libraries
License: LGPLv2
Group: System/Libraries
%description libs
This package contains the Xen Hypervisor general libraries for all domains.

%package libs-devel
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.13.4&prefix=xen-4.13.4&format=tar.gz#/xen-4.13.4.tar.gz) = 6e2fc128eb1a7d8ff8c36123a0a03e4e60a4a44c
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = 8f56b56afc6e15e142d90d92e0b7228900f1772c
Summary: Xen Hypervisor general development libraries
License: LGPLv2
Requires: xen-libs = %{version}
Requires: xen-devel = %{version}
Group: Development/Libraries
%description libs-devel
This package contains the Xen Hypervisor general development for all domains.

%package dom0-tools
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.13.4&prefix=xen-4.13.4&format=tar.gz#/xen-4.13.4.tar.gz) = 6e2fc128eb1a7d8ff8c36123a0a03e4e60a4a44c
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = 8f56b56afc6e15e142d90d92e0b7228900f1772c
Summary: Xen Hypervisor Domain 0 tools
License: GPLv2 and LGPLv2 and MIT
Requires: xen-dom0-libs = %{version}
Requires: xen-tools = %{version}
Requires: edk2
Requires: ipxe
%if %with_systemd
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
%endif
Group: System/Base
%description dom0-tools
This package contains the Xen Hypervisor control domain tools.

%package dom0-libs
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.13.4&prefix=xen-4.13.4&format=tar.gz#/xen-4.13.4.tar.gz) = 6e2fc128eb1a7d8ff8c36123a0a03e4e60a4a44c
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = 8f56b56afc6e15e142d90d92e0b7228900f1772c
Summary: Xen Hypervisor Domain 0 libraries
License: GPLv2 and LGPLv2 and MIT
Requires: xen-hypervisor = %{version}
Group: System/Libraries
%description dom0-libs
This package contains the Xen Hypervisor control domain libraries.

%package dom0-libs-devel
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.13.4&prefix=xen-4.13.4&format=tar.gz#/xen-4.13.4.tar.gz) = 6e2fc128eb1a7d8ff8c36123a0a03e4e60a4a44c
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = 8f56b56afc6e15e142d90d92e0b7228900f1772c
Summary: Xen Hypervisor Domain 0 headers
License: GPLv2 and LGPLv2 and MIT
Requires: xen-devel = %{version}
Requires: xen-dom0-libs = %{version}

# Temp until the build dependencies are properly propagated
Provides: xen-dom0-devel = %{version}
Group: Development/Libraries
%description dom0-libs-devel
This package contains the Xen Hypervisor control domain headers.

%package ocaml-libs
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.13.4&prefix=xen-4.13.4&format=tar.gz#/xen-4.13.4.tar.gz) = 6e2fc128eb1a7d8ff8c36123a0a03e4e60a4a44c
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = 8f56b56afc6e15e142d90d92e0b7228900f1772c
Summary: Xen Hypervisor ocaml libraries
License: LGPLv2
Requires: xen-dom0-libs = %{version}
Group: System/Libraries
%description ocaml-libs
This package contains the Xen Hypervisor ocaml libraries.

%package ocaml-devel
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.13.4&prefix=xen-4.13.4&format=tar.gz#/xen-4.13.4.tar.gz) = 6e2fc128eb1a7d8ff8c36123a0a03e4e60a4a44c
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = 8f56b56afc6e15e142d90d92e0b7228900f1772c
Summary: Xen Hypervisor ocaml headers
License: LGPLv2
Requires: xen-ocaml-libs = %{version}
Requires: xen-dom0-libs-devel = %{version}
Group: Development/Libraries
%description ocaml-devel
This package contains the Xen Hypervisor ocaml headers.

%package installer-files
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.13.4&prefix=xen-4.13.4&format=tar.gz#/xen-4.13.4.tar.gz) = 6e2fc128eb1a7d8ff8c36123a0a03e4e60a4a44c
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = 8f56b56afc6e15e142d90d92e0b7228900f1772c
Summary: Xen files for the XenServer installer
License: LGPLv2
Group: System Environment/Base
%description installer-files
This package contains the minimal subset of libraries and binaries required in
the XenServer installer environment.

%package dom0-tests
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.13.4&prefix=xen-4.13.4&format=tar.gz#/xen-4.13.4.tar.gz) = 6e2fc128eb1a7d8ff8c36123a0a03e4e60a4a44c
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = 8f56b56afc6e15e142d90d92e0b7228900f1772c
Summary: Xen Hypervisor tests
License: GPLv2
Group: System/Libraries
%description dom0-tests
This package contains test cases for the Xen Hypervisor.

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
%{__make} %{HVSOR_OPTIONS} -C xen XEN_VENDORVERSION=-%{base_release} \
    KCONFIG_CONFIG=../buildconfigs/config-release olddefconfig
%{__make} %{HVSOR_OPTIONS} -C xen XEN_VENDORVERSION=-%{base_release} \
    KCONFIG_CONFIG=../buildconfigs/config-release build
%{__make} %{HVSOR_OPTIONS} -C xen XEN_VENDORVERSION=-%{base_release} \
    KCONFIG_CONFIG=../buildconfigs/config-release MAP

cp xen/xen.gz %{buildroot}/boot/%{name}-%{version}-%{base_release}.gz
cp xen/System.map %{buildroot}/boot/%{name}-%{version}-%{base_release}.map
cp xen/xen-syms %{buildroot}/boot/%{name}-syms-%{version}-%{base_release}
cp buildconfigs/config-release %{buildroot}/boot/%{name}-%{version}-%{base_release}.config

# Debug build of Xen
%{__make} %{HVSOR_OPTIONS} -C xen clean
%{__make} %{HVSOR_OPTIONS} -C xen XEN_VENDORVERSION=-%{base_release}-d \
    KCONFIG_CONFIG=../buildconfigs/config-debug olddefconfig
%{?_cov_wrap} %{__make} %{HVSOR_OPTIONS} -C xen XEN_VENDORVERSION=-%{base_release}-d \
    KCONFIG_CONFIG=../buildconfigs/config-debug build
%{__make} %{HVSOR_OPTIONS} -C xen XEN_VENDORVERSION=-%{base_release}-d \
    KCONFIG_CONFIG=../buildconfigs/config-debug MAP

cp xen/xen.gz %{buildroot}/boot/%{name}-%{version}-%{base_release}-d.gz
cp xen/System.map %{buildroot}/boot/%{name}-%{version}-%{base_release}-d.map
cp xen/xen-syms %{buildroot}/boot/%{name}-syms-%{version}-%{base_release}-d
cp buildconfigs/config-debug %{buildroot}/boot/%{name}-%{version}-%{base_release}-d.config

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

%{__install} -D -m 644 %{SOURCE1} %{buildroot}%{_sysconfdir}/sysconfig/kernel-xen
%{__install} -D -m 644 %{SOURCE2} %{buildroot}%{_sysconfdir}/xen/xl.conf
%{__install} -D -m 644 %{SOURCE3} %{buildroot}%{_sysconfdir}/logrotate.d/xen-tools
%{?_cov_install}

%files hypervisor
/boot/%{name}-%{version}-%{base_release}.gz
/boot/%{name}-%{version}-%{base_release}.map
/boot/%{name}-%{version}-%{base_release}.config
/boot/%{name}-%{version}-%{base_release}-d.gz
/boot/%{name}-%{version}-%{base_release}-d.map
/boot/%{name}-%{version}-%{base_release}-d.config
%config %{_sysconfdir}/sysconfig/kernel-xen
%license COPYING
%ghost %attr(0644,root,root) %{_sysconfdir}/sysconfig/kernel-xen-args

%files hypervisor-debuginfo
/boot/%{name}-syms-%{version}-%{base_release}
/boot/%{name}-syms-%{version}-%{base_release}-d

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
%{py_sitearch}/%{name}/__init__.py*
%{py_sitearch}/%{name}/lowlevel/__init__.py*
%{py_sitearch}/%{name}/lowlevel/xs.so

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
%{_libdir}/libxentoollog.so.1
%{_libdir}/libxentoollog.so.1.0
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
%{py_sitearch}/xenfsimage.so
%{py_sitearch}/grub/ExtLinuxConf.py*
%{py_sitearch}/grub/GrubConf.py*
%{py_sitearch}/grub/LiloConf.py*
%{py_sitearch}/grub/__init__.py*
%{py_sitearch}/pygrub-*.egg-info
%{py_sitearch}/xen-*.egg-info
#{py_sitearch}/xen/__init__.py*           - Must not duplicate xen-tools
#{py_sitearch}/xen/lowlevel/__init__.py*  - Must not duplicate xen-tools
%{py_sitearch}/xen/lowlevel/xc.so
%{py_sitearch}/xen/migration/__init__.py*
%{py_sitearch}/xen/migration/legacy.py*
%{py_sitearch}/xen/migration/libxc.py*
%{py_sitearch}/xen/migration/libxl.py*
%{py_sitearch}/xen/migration/public.py*
%{py_sitearch}/xen/migration/tests.py*
%{py_sitearch}/xen/migration/verify.py*
%{py_sitearch}/xen/migration/xl.py*
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
%{py_sitearch}/xen/__init__.py*
%{py_sitearch}/xen/lowlevel/__init__.py*
%{py_sitearch}/xen/lowlevel/xc.so

%files dom0-tests
%{_libexecdir}/%{name}/bin/depriv-fd-checker
%{_libexecdir}/%{name}/bin/test-cpu-policy
%{_libexecdir}/%{name}/bin/test-xenstore

%doc

%post hypervisor
# Update the debug and release symlinks
ln -sf %{name}-%{version}-%{base_release}-d.gz /boot/xen-debug.gz
ln -sf %{name}-%{version}-%{base_release}.gz /boot/xen-release.gz

# Point /boot/xen.gz appropriately
if [ ! -e /boot/xen.gz ]; then
%if %{default_debug_hypervisor}
    # Use a debug hypervisor by default
    ln -sf %{name}-%{version}-%{base_release}-d.gz /boot/xen.gz
%else
    # Use a production hypervisor by default
    ln -sf %{name}-%{version}-%{base_release}.gz /boot/xen.gz
%endif
else
    # Else look at the current link, and whether it is debug
    path="`readlink -f /boot/xen.gz`"
    if [ ${path} != ${path%%-d.gz} ]; then
        ln -sf %{name}-%{version}-%{base_release}-d.gz /boot/xen.gz
    else
        ln -sf %{name}-%{version}-%{base_release}.gz /boot/xen.gz
    fi
fi

if [ -e %{_sysconfdir}/sysconfig/kernel ] && ! grep -q '^HYPERVISOR' %{_sysconfdir}/sysconfig/kernel ; then
  cat %{_sysconfdir}/sysconfig/kernel-xen >> %{_sysconfdir}/sysconfig/kernel
fi

mkdir -p %{_rundir}/reboot-required.d/%{name}
touch %{_rundir}/reboot-required.d/%{name}/%{version}-%{base_release}

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
* Wed Aug 10 2022 Gael Duperrey <gduperrey@vates.fr> - 4.13.4-9.25.1
- Synced from hotfix XS82ECU1015
- Remove amd-iommu-correct-xt-handling.patch, it's already in XS82ECU1015
- Reboot required

* Fri Jul 29 2022 Andrei Semenov <andrei.semenov@vates.fr> - 4.13.4-9.24.2
- Add amd-iommu-correct-xt-handling.patch

* Tue Jul 12 2022 Gael Duperrey <gduperrey@vates.fr> - 4.13.4-9.24.1
- Security update, synced from hotfix XS82ECU1014
- XSA 407
- See http://xenbits.xen.org/xsa/
- Reboot required

* Thu Jun 23 2022 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.4-9.23.1
- Security update, synced from hotfix XS82ECU1012
- Fix XSA 404
- Replaced our XSA 401 and 402 patches with those from the XS hotfix
- See http://xenbits.xen.org/xsa/
- Reboot required

* Fri Jun 10 2022 Andrei Semenov <andrei.semenov@vates.fr> - 4.13.4-9.22.2
- Security update
- Related to XSA 401 and XSA 402
- See http://xenbits.xen.org/xsa/
- Reboot required

* Wed May 11 2022 Gaël Duperrey <gduperrey@vates.fr> - 4.13.4-9.22.1
- Sync with hotfix XS82ECU1010
- Integrated upstream patches related to XSA 400 to replace our patches
- See http://xenbits.xen.org/xsa/
- Reboot required

* Tue Apr 05 2022 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.4-9.21.2
- Security update, synced from hotfix XS82ECU1007
- Related to XSAs 397, 399 and 400
- See http://xenbits.xen.org/xsa/
- Additional patches added from upstream xen to fix fallouts of XSA-400 patches
- Reboot required

* Wed Mar 09 2022 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.4-9.20.1
- Security update, synced from hotfix XS82ECU1006
- Related to XSA 398
- See http://xenbits.xen.org/xsa/
- Reboot required

* Wed Feb 09 2022 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.4-9.19.1
- Security update, synced from hotfix XS82E037
- Adapt to new microcode released to fix security vulnerabilities in Intel CPUs
- Also fixes XSAs 394 and 395
- Reboot required

* Thu Jan 13 2022 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.4-9.18.1
- Security update, synced from hotfix XS82E035
- Related to XSAs 388, 389
- See http://xenbits.xen.org/xsa/
- Reboot required

* Mon Jan 10 2022 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.4-9.17.1
- Sync with CH 8.2.1
- Keep using python-devel as build dependency until python is updated

* Thu Sep 09 2021 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.1-9.12.1
- Security update, synced from hotfix XS82E032
- Related to XSAs 378, 379, 380, 382, 384
- See http://xenbits.xen.org/xsa/
- Reboot required

* Thu Jun 10 2021 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.1-9.11.1
- Security update, synced from hotfix XS82E026
- Related to XSAs 373, 375, 377
- See http://xenbits.xen.org/xsa/
- Reboot required

* Thu Feb 04 2021 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.1-9.9.1
- Sync with hotfix XS82E016
- Bugfix update (we already had applied the security patch for XSA-360)
- Reboot required

* Mon Jan 25 2021 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.1-9.8.4
- Remove dist tag from XEN_VENDORVERSION
- Avoids hitting the 16 char limit in xen_extra
- Related to https://github.com/xcp-ng/xcp/issues/476

* Thu Jan 21 2021 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.1-9.8.3
- Security update
- Related to XSA 360
- See http://xenbits.xen.org/xsa/advisory-360.html
- Reboot required

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
