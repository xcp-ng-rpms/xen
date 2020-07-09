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
Version: 4.11.1
Release: 7.11%{?dist}
License: GPLv2 and LGPLv2+ and BSD
URL:     http://www.xenproject.org

Source0: https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.11.1&prefix=xen-4.11.1&format=tar.gz#/xen-4.11.1.tar.gz
Source1: SOURCES/xen/sysconfig_kernel-xen
Source2: SOURCES/xen/xl.conf
Source3: SOURCES/xen/logrotate-xen-tools

Patch0: build-disable-qemu-trad.patch
Patch1: build-tweaks.patch
Patch2: autoconf-libjson.patch
Patch3: configure-build.patch
Patch4: builder-makefiles.patch
Patch5: changeset-info.patch
Patch6: xenserver-configuration.patch
Patch7: coverity-model.patch
Patch8: backport-c21aba8b9d5c.patch
Patch9: backport-d8b2418573fb.patch
Patch10: backport-7d1bd985ebd4.patch
Patch11: backport-0b2be0bd82b8.patch
Patch12: backport-91f2ad76aa82.patch
Patch13: backport-af25f52a06a8.patch
Patch14: backport-63d71138a4d3.patch
Patch15: backport-dd914e4c6fc9.patch
Patch16: backport-de094111f462.patch
Patch17: backport-2cd833de4dae.patch
Patch18: backport-198672807ec6.patch
Patch19: backport-e202feb7131e.patch
Patch20: backport-514dccd049f8.patch
Patch21: backport-850ca94004e3.patch
Patch22: backport-1028304d4244.patch
Patch23: backport-4f785ea01cf2.patch
Patch24: backport-4298abd32733.patch
Patch25: backport-be58f861234c.patch
Patch26: backport-4835974065cc.patch
Patch27: backport-92227e25092c.patch
Patch28: backport-7bbd3a5ecd71.patch
Patch29: backport-6c197f96bdac.patch
Patch30: backport-c567b053e807.patch
Patch31: backport-4f9ab5f75c12.patch
Patch32: backport-e984846dad81.patch
Patch33: backport-fc46e159a6b1.patch
Patch34: backport-c3f6eeeb8891.patch
Patch35: backport-cf7900b51eb9.patch
Patch36: backport-53a26ef563ab.patch
Patch37: backport-2cae31dd472a.patch
Patch38: backport-e4506f404cb7.patch
Patch39: backport-01d631028a02.patch
Patch40: backport-6f28c09aa96b.patch
Patch41: backport-205134148981.patch
Patch42: backport-61bdddb82151.patch
Patch43: backport-7757cce0ab39.patch
Patch44: backport-499a76634d74.patch
Patch45: backport-4c9a6546e4c3.patch
Patch46: backport-1dddfff4c39d.patch
Patch47: backport-4be26bd61efd.patch
Patch48: backport-ada9a4d904f8.patch
Patch49: backport-4991a46130dc.patch
Patch50: backport-725cc2edce3d.patch
Patch51: backport-19dc9448099e.patch
Patch52: backport-f99b99ed6381.patch
Patch53: backport-2ec5339ec921.patch
Patch54: backport-2c257bd69a3e.patch
Patch55: backport-eea4ec2b66da.patch
Patch56: backport-e4405e0799ba.patch
Patch57: backport-8f29f3ead253.patch
Patch58: backport-3e828f882a6b.patch
Patch59: backport-a2eb46491e28.patch
Patch60: backport-0348184dd2ee.patch
Patch61: backport-89faccfd35dd.patch
Patch62: backport-c88397db5c3f.patch
Patch63: backport-146bb7e1934a.patch
Patch64: backport-129025fe3093.patch
Patch65: backport-81946a73dc97.patch
Patch66: backport-02ede7dc0390.patch
Patch67: backport-7b20a865bc10.patch
Patch68: backport-7559ab7830c3.patch
Patch69: backport-761de0b8920c.patch
Patch70: backport-3486f398a3dd.patch
Patch71: backport-d5d30b394975.patch
Patch72: backport-ffb60a58df48.patch
Patch73: backport-6230dde2ed4f.patch
Patch74: backport-87e89bd112e1.patch
Patch75: backport-78b1225ea52e.patch
Patch76: backport-137dc7e657f4.patch
Patch77: backport-01a2fd6878a2.patch
Patch78: backport-0b24ef785379.patch
Patch79: backport-6889ae02b63d.patch
Patch80: backport-36aec6100f85.patch
Patch81: backport-07ded9a515eb.patch
Patch82: backport-b8f0767b438b.patch
Patch83: backport-303cee10a677.patch
Patch84: backport-0a1eb2b43879.patch
Patch85: backport-725bf00a87fb.patch
Patch86: backport-b81b9b9bdbda.patch
Patch87: backport-1698309f3e5e.patch
Patch88: backport-c861674f3bae.patch
Patch89: backport-dc80c4248445.patch
Patch90: backport-c3acf04dbd70.patch
Patch91: backport-c393b64dcee6.patch
Patch92: backport-82855aba5bf9.patch
Patch93: backport-5c08550ff4f3.patch
Patch94: backport-1fea389864bd.patch
Patch95: backport-95ba8404d45d.patch
Patch96: backport-6e23f46ea9bb.patch
Patch97: backport-0fb4b58c8b9c.patch
Patch98: backport-b5acd075aabc.patch
Patch99: backport-7f28661f6a7c.patch
Patch100: backport-9b97818c3d58.patch
Patch101: backport-cbe21fd047c5.patch
Patch102: backport-d40029c844cf.patch
Patch103: backport-e8afe1124cc1.patch
Patch104: backport-a5b0eb363694.patch
Patch105: backport-2bad3829a59a.patch
Patch106: backport-ff9b9d540f1b.patch
Patch107: backport-73e1fb1aec43.patch
Patch108: backport-448787e16e14.patch
Patch109: backport-365aabb6e502.patch
Patch110: backport-29d28b29190b.patch
Patch111: backport-24d5282527f4.patch
Patch112: backport-0dfffe01d568.patch
Patch113: backport-e72ecc761541.patch
Patch114: backport-0ec9b4ef3148.patch
Patch115: backport-69f7643df68e.patch
Patch116: backport-677e64dbe315.patch
Patch117: backport-1c8ca185e3c6.patch
Patch118: backport-0452d02b6e78.patch
Patch119: backport-40a4a9d72d16.patch
Patch120: backport-e7a9b5e72f26.patch
Patch121: backport-d27a69a29a4f.patch
Patch122: backport-a204e6f8e744.patch
Patch123: backport-80aaa19e0307.patch
Patch124: backport-9203661ebb3c.patch
Patch125: backport-386b3365221d.patch
Patch126: backport-aeaa5d8b7a7c.patch
Patch127: backport-a85089d0ef57.patch
Patch128: backport-26fba3c85571.patch
Patch129: backport-fda96b7382ea.patch
Patch130: backport-48dab9767d2e.patch
Patch131: backport-860d6e158dbb.patch
Patch132: backport-56ad626532eb.patch
Patch133: 0001-x86-spec-ctrl-Reposition-the-XPTI-command-line-parsi.patch
Patch134: 0002-x86-msr-Definitions-for-MSR_INTEL_CORE_THREAD_COUNT.patch
Patch135: 0003-x86-boot-Detect-the-firmware-SMT-setting-correctly-o.patch
Patch136: detect-nehalem-c-state.patch
Patch137: quirk-hp-gen8-rmrr.patch
Patch138: quirk-pci-phantom-function-devices.patch
Patch139: 0001-x86-hpet-Pre-cleanup.patch
Patch140: 0002-x86-hpet-Use-singe-apic-vector-rather-than-irq_descs.patch
Patch141: 0003-x86-hpet-Post-cleanup.patch
Patch142: 0002-libxc-retry-shadow-ops-if-EBUSY-is-returned.patch
Patch143: avoid-gnt-unmap-tlb-flush-if-not-accessed.patch
Patch144: 0002-efi-Ensure-incorrectly-typed-runtime-services-get-ma.patch
Patch145: 0001-x86-time-Don-t-use-EFI-s-GetTime-call.patch
Patch146: 0001-efi-Workaround-page-fault-during-runtime-service.patch
Patch147: 0001-x86-HVM-Avoid-cache-flush-operations-during-hvm_load.patch
Patch148: 0001-libxl-Don-t-insert-PCI-device-into-xenstore-for-HVM-.patch
Patch149: 0001-x86-PoD-Command-line-option-to-prohibit-any-PoD-oper.patch
Patch150: fail-on-duplicate-symbol.patch
Patch151: livepatch-ignore-duplicate-new.patch
Patch152: default-log-level-info.patch
Patch153: 0001-lib-Add-a-generic-implementation-of-current_text_add.patch
Patch154: 0002-sched-Remove-dependency-on-__LINE__-for-release-buil.patch
Patch155: pygrub-Ignore-GRUB2-if-statements.patch
Patch156: libfsimage-Add-support-for-btrfs.patch
Patch157: 0001-xen-domctl-Implement-a-way-to-retrieve-a-domains-nom.patch
Patch158: quiet-broke-irq-affinity.patch
Patch159: 0001-x86-vvmx-set-CR4-before-CR0.patch
Patch160: 0001-x86-msr-Blacklist-various-MSRs-which-guests-definite.patch
Patch161: 0004-x86-cpuid-Enable-new-SSE-AVX-AVX512-cpu-features.patch
Patch162: 0001-Hide-AVX-512-from-guests-by-default.patch
Patch163: 0003-xen-xsm-Introduce-new-boot-parameter-xsm.patch
Patch164: 0004-xen-xsm-Add-new-SILO-mode-for-XSM.patch
Patch165: 0001-common-page_alloc-don-t-idle-scrub-before-microcode-.patch
Patch166: 0001-iommu-leave-IOMMU-enabled-by-default-during-kexec-cr.patch
Patch167: 0001-x86-hvm-hpet-avoid-small-time-diff-test-on-resume.patch
Patch168: xen-tweak-cmdline-defaults.patch
Patch169: xen-tweak-debug-overhead.patch
Patch170: tweak-iommu-policy.patch
Patch171: disable-core-parking.patch
Patch172: disable-runtime-microcode.patch
Patch173: remove-iommu-alignment-assertions.patch
Patch174: 0001-Allocate-space-in-structs-pre-emptively-to-increase-.patch
Patch175: livepatch-payload-in-header.patch
Patch176: xen-define-offsets-for-kdump.patch
Patch177: xen-scheduler-auto-privdom-weight.patch
Patch178: xen-hvm-disable-tsc-ramping.patch
Patch179: xen-default-cpufreq-governor-to-performance-on-intel.patch
Patch180: xen-override-caching-cp-26562.patch
Patch181: 0001-Partially-revert-08754333892-hvmloader-limit-CPUs-ex.patch
Patch182: 0001-x86-pv-silently-discard-writes-into-MSR_AMD64_LS_CFG.patch
Patch183: revert-ca2eee92df44.patch
Patch184: libxc-stubs-hvm_check_pvdriver.patch
Patch185: pygrub-add-default-and-extra-args.patch
Patch186: pygrub-always-boot-default.patch
Patch187: pygrub-friendly-no-fs.patch
Patch188: pygrub-image-max-size.patch
Patch189: pygrub-default-xenmobile-kernel.patch
Patch190: pygrub-blacklist-support.patch
Patch191: oem-bios-xensource.patch
Patch192: oem-bios-magic-from-xenstore.patch
Patch193: misc-log-guest-consoles.patch
Patch194: fix-ocaml-libs.patch
Patch195: ocaml-cpuid-helpers.patch
Patch196: ocaml-xc_domain_create-compat.patch
Patch197: xentop-display-correct-stats.patch
Patch198: xentop-vbd3.patch
Patch199: mixed-domain-runstates.patch
Patch200: mixed-xc-sockets-per-core.patch
Patch201: xenguest.patch
Patch202: xen-vmdebug.patch
Patch203: local-xen-vmdebug.patch
Patch204: oxenstore-censor-sensitive-data.patch
Patch205: oxenstore-large-packets.patch
Patch206: nvidia-vga.patch
Patch207: hvmloader-disable-pci-option-rom-loading.patch
Patch208: xen-force-software-vmcs-shadow.patch
Patch209: 0001-x86-vvmx-add-initial-PV-EPT-support-in-L0.patch
Patch210: add-pv-iommu-headers.patch
Patch211: add-iommu-lookup-core.patch
Patch212: add-iommu-lookup-intel.patch
Patch213: add-pv-iommu-local-domain-ops.patch
Patch214: add-pv-iommu-foreign-support.patch
Patch215: add-pv-iommu-premap-m2b-support.patch
Patch216: add-pv-iommu-to-spec.patch
Patch217: upstream-pv-iommu-tools.patch
Patch218: allow-rombios-pci-config-on-any-host-bridge.patch
Patch219: 0007-hypercall-XENMEM_get_mfn_from_pfn.patch
Patch220: gvt-g-hvmloader+rombios.patch
Patch221: 0001-CA-298922-Add-support-for-p2m_ioreq_server-to-RMW-em.patch
Patch222: xen-introduce-cmdline-to-control-introspection-extensions.patch
Patch223: xen-domctl-set-privileged-domain.patch
Patch224: x86-domctl-Don-t-pause-the-whole-domain-if-only-gett.patch
Patch225: xen-reexecute-instn-under-monitor-trap.patch
Patch226: xen-emulate-Bypass-the-emulator-if-emulation-fails.patch
Patch227: xen-introspection-pause.patch
Patch228: xen-always-enable-altp2m-external-mode.patch
Patch229: 0001-cc-memory-scrubbing.patch
Patch230: xsa297-4.11-1.patch
Patch231: xsa297-4.11-2.patch
Patch232: xsa297-4.11-3.patch
Patch233: xsa297-4.11-4.patch
Patch234: backport-5a82d598d2d2.patch
Patch235: backport-40f6da82800d.patch
Patch236: 0001-IOMMU-add-missing-HVM-check.patch
Patch237: 0002-passthrough-quarantine-PCI-devices.patch
Patch238: backport-f28c4c4c10bd.patch
Patch239: xsa296.patch
Patch240: xsa298-4.11.patch
Patch241: xsa299-4.110001-x86-mm-L1TF-checks-don-t-leave-a-partial-entry.patch
Patch242: xsa299-4.110002-x86-mm-Don-t-re-set-PGT_pinned-on-a-partially-de-val.patch
Patch243: xsa299-4.110003-x86-mm-Separate-out-partial_pte-tristate-into-indivi.patch
Patch244: xsa299-4.110004-x86-mm-Use-flags-for-_put_page_type-rather-than-a-bo.patch
Patch245: xsa299-4.110005-x86-mm-Rework-get_page_and_type_from_mfn-conditional.patch
Patch246: xsa299-4.110006-x86-mm-Have-alloc_l-23-_table-clear-partial_flags-wh.patch
Patch247: xsa299-4.110007-x86-mm-Always-retain-a-general-ref-on-partial.patch
Patch248: xsa299-4.110008-x86-mm-Collapse-PTF_partial_set-and-PTF_partial_gene.patch
Patch249: xsa299-4.110009-x86-mm-Properly-handle-linear-pagetable-promotion-fa.patch
Patch250: xsa299-4.110010-x86-mm-Fix-nested-de-validation-on-error.patch
Patch251: xsa299-4.110011-x86-mm-Don-t-drop-a-type-ref-unless-you-held-a-ref-t.patch
Patch252: xsa304-4.11-1.patch
Patch253: xsa304-4.11-2.patch
Patch254: xsa304-4.11-3.patch
Patch255: xsa304-fast-by-default.patch
Patch256: xsa305-4.11-1.patch
Patch257: xsa305-4.11-2.patch
Patch258: toolstack-tsx-ctrl.patch
Patch259: xsa305-leave-tsx-visible.patch
Patch260: xsa308.patch
Patch261: backport-77beba7c921a.patch
Patch262: xsa309.patch
Patch263: xsa310-0001-x86-mm-Set-old_guest_table-when-destroying-vcpu-page.patch
Patch264: xsa310-0002-x86-mm-alloc-free_lN_table-Retain-partial_flags-on-E.patch
Patch265: xsa310-0003-x86-mm-relinquish_memory-Grab-an-extra-type-ref-when.patch
Patch266: xsa311-4.11.patch
Patch267: backport-5e08f5f56c99.patch
Patch268: xsa313-1.patch
Patch269: xsa313-2.patch
Patch270: backport-7442006b9f09.patch
Patch271: xsa316-2.patch
Patch272: 0001-x86-spec-ctrl-CPUID-MSR-definitions-for-Special-Regi.patch
Patch273: 0002-x86-spec-ctrl-Mitigate-the-Special-Register-Buffer-D.patch
Patch274: xsa317.patch
Patch275: xsa319.patch
Patch276: xsa328-xsa328-4.11-1.patch
Patch277: xsa328-xsa328-4.11-2.patch
Patch278: xsa321-xsa321-4.11-1.patch
Patch279: xsa321-xsa321-4.11-2.patch
Patch280: xsa321-xsa321-4.11-3.patch
Patch281: xsa321-xsa321-4.11-4.patch
Patch282: xsa321-xsa321-4.11-5.patch
Patch283: xsa321-xsa321-4.11-6.patch
Patch284: xsa321-xsa321-4.11-7.patch

Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.11.1&prefix=xen-4.11.1&format=tar.gz#/xen-4.11.1.tar.gz) = 96cbd0893f783997caaf117e897d5fa8f2dc7b5f
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = a680986b805c28229fed895f424fa87df67506a6


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

# For libfsimage
BuildRequires: e2fsprogs-devel
%if 0%{?centos}%{!?centos:5} < 6 && 0%{?rhel}%{!?rhel:5} < 6
#libext4fs
BuildRequires: e4fsprogs-devel
%endif
BuildRequires: lzo-devel

# For xenguest
BuildRequires: json-c-devel libempserver-devel

# For manpages
BuildRequires: perl pandoc python-markdown

# Misc
BuildRequires: libtool
%if %with_systemd
BuildRequires: systemd-devel
%endif

# To placate ./configure
BuildRequires: gettext-devel glib2-devel curl-devel gnutls-devel

%description
Xen Hypervisor.

%package hypervisor
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.11.1&prefix=xen-4.11.1&format=tar.gz#/xen-4.11.1.tar.gz) = 96cbd0893f783997caaf117e897d5fa8f2dc7b5f
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = a680986b805c28229fed895f424fa87df67506a6
Summary: The Xen Hypervisor
Group: System/Hypervisor
Requires(post): coreutils grep
%description hypervisor
This package contains the Xen Project Hypervisor.

%package hypervisor-debuginfo
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.11.1&prefix=xen-4.11.1&format=tar.gz#/xen-4.11.1.tar.gz) = 96cbd0893f783997caaf117e897d5fa8f2dc7b5f
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = a680986b805c28229fed895f424fa87df67506a6
Summary: The Xen Hypervisor debug information
Group: Development/Debug
%description hypervisor-debuginfo
This package contains the Xen Hypervisor debug information.

%package tools
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.11.1&prefix=xen-4.11.1&format=tar.gz#/xen-4.11.1.tar.gz) = 96cbd0893f783997caaf117e897d5fa8f2dc7b5f
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = a680986b805c28229fed895f424fa87df67506a6
Summary: Xen Hypervisor general tools
Requires: xen-libs = %{version}
Group: System/Base
%description tools
This package contains the Xen Hypervisor general tools for all domains.

%package devel
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.11.1&prefix=xen-4.11.1&format=tar.gz#/xen-4.11.1.tar.gz) = 96cbd0893f783997caaf117e897d5fa8f2dc7b5f
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = a680986b805c28229fed895f424fa87df67506a6
Summary: The Xen Hypervisor public headers
Group: Development/Libraries
%description devel
This package contains the Xen Hypervisor public header files.

%package libs
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.11.1&prefix=xen-4.11.1&format=tar.gz#/xen-4.11.1.tar.gz) = 96cbd0893f783997caaf117e897d5fa8f2dc7b5f
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = a680986b805c28229fed895f424fa87df67506a6
Summary: Xen Hypervisor general libraries
Group: System/Libraries
%description libs
This package contains the Xen Hypervisor general libraries for all domains.

%package libs-devel
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.11.1&prefix=xen-4.11.1&format=tar.gz#/xen-4.11.1.tar.gz) = 96cbd0893f783997caaf117e897d5fa8f2dc7b5f
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = a680986b805c28229fed895f424fa87df67506a6
Summary: Xen Hypervisor general development libraries
Requires: xen-libs = %{version}
Requires: xen-devel = %{version}
Group: Development/Libraries
%description libs-devel
This package contains the Xen Hypervisor general development for all domains.

%package dom0-tools
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.11.1&prefix=xen-4.11.1&format=tar.gz#/xen-4.11.1.tar.gz) = 96cbd0893f783997caaf117e897d5fa8f2dc7b5f
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = a680986b805c28229fed895f424fa87df67506a6
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
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.11.1&prefix=xen-4.11.1&format=tar.gz#/xen-4.11.1.tar.gz) = 96cbd0893f783997caaf117e897d5fa8f2dc7b5f
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = a680986b805c28229fed895f424fa87df67506a6
Summary: Xen Hypervisor Domain 0 libraries
Requires: xen-hypervisor = %{version}
Group: System/Libraries
%description dom0-libs
This package contains the Xen Hypervisor control domain libraries.

%package dom0-libs-devel
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.11.1&prefix=xen-4.11.1&format=tar.gz#/xen-4.11.1.tar.gz) = 96cbd0893f783997caaf117e897d5fa8f2dc7b5f
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = a680986b805c28229fed895f424fa87df67506a6
Summary: Xen Hypervisor Domain 0 headers
Requires: xen-devel = %{version}
Requires: xen-dom0-libs = %{version}

# Temp until the build dependencies are properly propagated
Provides: xen-dom0-devel = %{version}
Group: Development/Libraries
%description dom0-libs-devel
This package contains the Xen Hypervisor control domain headers.

%package ocaml-libs
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.11.1&prefix=xen-4.11.1&format=tar.gz#/xen-4.11.1.tar.gz) = 96cbd0893f783997caaf117e897d5fa8f2dc7b5f
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = a680986b805c28229fed895f424fa87df67506a6
Summary: Xen Hypervisor ocaml libraries
Requires: xen-dom0-libs = %{version}
Group: System/Libraries
%description ocaml-libs
This package contains the Xen Hypervisor ocaml libraries.

%package ocaml-devel
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.11.1&prefix=xen-4.11.1&format=tar.gz#/xen-4.11.1.tar.gz) = 96cbd0893f783997caaf117e897d5fa8f2dc7b5f
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = a680986b805c28229fed895f424fa87df67506a6
Summary: Xen Hypervisor ocaml headers
Requires: xen-ocaml-libs = %{version}
Requires: xen-dom0-libs-devel = %{version}
Group: Development/Libraries
%description ocaml-devel
This package contains the Xen Hypervisor ocaml headers.

%package installer-files
Provides: gitsha(https://code.citrite.net/rest/archive/latest/projects/XSU/repos/xen/archive?at=RELEASE-4.11.1&prefix=xen-4.11.1&format=tar.gz#/xen-4.11.1.tar.gz) = 96cbd0893f783997caaf117e897d5fa8f2dc7b5f
Provides: gitsha(ssh://git@code.citrite.net/xs/xen.pg.git) = a680986b805c28229fed895f424fa87df67506a6
Summary: Xen files for the XenServer installer
Group: System Environment/Base
%description installer-files
This package contains the minimal subset of libraries and binaries required in
the XenServer installer environment.

%prep
%autosetup -p1

base_cset=$(sed -ne 's/Changeset: \(.*\)/\1/p' < .gitarchive-info)
pq_cset=$(sed -ne 's/Changeset: \(.*\)/\1/p' < .gitarchive-info-pq)
echo "${base_cset:0:12}, pq ${pq_cset:0:12}" > .scmversion

%build

# Placate ./configure, but don't pull in external content.
export WGET=/bin/false FETCHER=/bin/false

%configure --disable-seabios \
           --disable-stubdom \
           --disable-xsmpolicy \
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
%{?cov_wrap} %{__make} %{HVSOR_OPTIONS} -C xen XEN_VENDORVERSION=-%{release}-d \
    KCONFIG_CONFIG=../buildconfigs/config-debug build
%{__make} %{HVSOR_OPTIONS} -C xen XEN_VENDORVERSION=-%{release}-d \
    KCONFIG_CONFIG=../buildconfigs/config-debug MAP

cp xen/xen.gz %{buildroot}/boot/%{name}-%{version}-%{release}-d.gz
cp xen/System.map %{buildroot}/boot/%{name}-%{version}-%{release}-d.map
cp xen/xen-syms %{buildroot}/boot/%{name}-syms-%{version}-%{release}-d
cp buildconfigs/config-debug %{buildroot}/boot/%{name}-%{version}-%{release}-d.config

# do not strip the hypervisor-debuginfo targerts
chmod -x %{buildroot}/boot/xen-syms-*

# Build tools and man pages
%{?cov_wrap} %{__make} %{TOOLS_OPTIONS} install-tools
%{__make} %{TOOLS_OPTIONS} -C docs install-man-pages
%{?cov_wrap} %{__make} %{TOOLS_OPTIONS} -C tools/tests/mce-test/tools install

%{__install} -D -m 644 %{SOURCE1} %{buildroot}%{_sysconfdir}/sysconfig/kernel-xen
%{__install} -D -m 644 %{SOURCE2} %{buildroot}%{_sysconfdir}/xen/xl.conf
%{__install} -D -m 644 %{SOURCE3} %{buildroot}%{_sysconfdir}/logrotate.d/xen-tools

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
%{_includedir}/%{name}/callback.h
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
%{_libdir}/libxengnttab.so.1.1
%{_libdir}/libxenstore.so.3.0
%{_libdir}/libxenstore.so.3.0.3
%{_libdir}/libxentoolcore.so.1
%{_libdir}/libxentoolcore.so.1.0
%{_libdir}/libxenvchan.so.4.11
%{_libdir}/libxenvchan.so.4.11.0

%files libs-devel
# Lib Xen Evtchn
%{_includedir}/xenevtchn.h
%{_libdir}/libxenevtchn.a
%{_libdir}/libxenevtchn.so
/usr/share/pkgconfig/xenevtchn.pc

# Lib Xen Gnttab
%{_includedir}/xengnttab.h
%{_libdir}/libxengnttab.a
%{_libdir}/libxengnttab.so
/usr/share/pkgconfig/xengnttab.pc

# Lib XenStore
%{_includedir}/xenstore.h
%{_includedir}/xenstore_lib.h
%{_libdir}/libxenstore.a
%{_libdir}/libxenstore.so
/usr/share/pkgconfig/xenstore.pc
# Legacy XenStore header files, excluded to discourage their use
%exclude %{_includedir}/xs.h
%exclude %{_includedir}/xenstore-compat/xs.h
%exclude %{_includedir}/xs_lib.h
%exclude %{_includedir}/xenstore-compat/xs_lib.h

%{_includedir}/xentoolcore.h
%{_libdir}/libxentoolcore.a
%{_libdir}/libxentoolcore.so
/usr/share/pkgconfig/xentoolcore.pc

# Lib Xen Vchan
%{_includedir}/libxenvchan.h
%{_libdir}/libxenvchan.a
%{_libdir}/libxenvchan.so
/usr/share/pkgconfig/xenvchan.pc

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
%{_sysconfdir}/xen/scripts/xen-hotplug-cleanup
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
%{python_sitearch}/fsimage.so
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
%{_sbindir}/flask-get-bool
%{_sbindir}/flask-getenforce
%{_sbindir}/flask-label-pci
%{_sbindir}/flask-loadpolicy
%{_sbindir}/flask-set-bool
%{_sbindir}/flask-setenforce
%{_sbindir}/gdbsx
%{_sbindir}/kdd
%{_sbindir}/oxenstored
%{_sbindir}/xen-diag
%{_sbindir}/xen-hptool
%{_sbindir}/xen-hvmcrash
%{_sbindir}/xen-hvmctx
%{_sbindir}/xen-livepatch
%{_sbindir}/xen-lowmemd
%{_sbindir}/xen-mceinj
%{_sbindir}/xen-mfndump
%exclude %{_sbindir}/xen-ringwatch
%{_sbindir}/xen-vmdebug
%{_sbindir}/xenbaked
%{_sbindir}/xenconsoled
%{_sbindir}/xencov
%{_sbindir}/xenmon.py
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
%exclude %{_sbindir}/xen-bugtool
%exclude %{_sbindir}/xen-tmem-list-parse
%exclude %{_sbindir}/xenlockprof
%{_mandir}/man1/xentop.1.gz
%{_mandir}/man1/xentrace_format.1.gz
%{_mandir}/man1/xenstore-chmod.1.gz
%{_mandir}/man1/xenstore-ls.1.gz
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
%{_libdir}/fs/btrfs/fsimage.so
%{_libdir}/fs/ext2fs-lib/fsimage.so
%{_libdir}/fs/fat/fsimage.so
%{_libdir}/fs/iso9660/fsimage.so
%{_libdir}/fs/reiserfs/fsimage.so
%{_libdir}/fs/ufs/fsimage.so
%{_libdir}/fs/xfs/fsimage.so
%{_libdir}/fs/zfs/fsimage.so
%{_libdir}/libfsimage.so.1.0
%{_libdir}/libfsimage.so.1.0.0
%{_libdir}/libxencall.so.1
%{_libdir}/libxencall.so.1.1
%{_libdir}/libxenctrl.so.4.11
%{_libdir}/libxenctrl.so.4.11.0
%{_libdir}/libxendevicemodel.so.1
%{_libdir}/libxendevicemodel.so.1.3
%{_libdir}/libxenforeignmemory.so.1
%{_libdir}/libxenforeignmemory.so.1.3
%{_libdir}/libxenguest.so.4.11
%{_libdir}/libxenguest.so.4.11.0
%{_libdir}/libxenlight.so.4.11
%{_libdir}/libxenlight.so.4.11.0
%{_libdir}/libxenstat.so.0
%{_libdir}/libxenstat.so.0.0
%{_libdir}/libxentoollog.so.1
%{_libdir}/libxentoollog.so.1.0
%{_libdir}/libxlutil.so.4.11
%{_libdir}/libxlutil.so.4.11.0

%files dom0-libs-devel
%{_includedir}/fsimage.h
%{_includedir}/fsimage_grub.h
%{_includedir}/fsimage_plugin.h
%{_libdir}/libfsimage.so

%{_includedir}/xencall.h
%{_libdir}/libxencall.a
%{_libdir}/libxencall.so
/usr/share/pkgconfig/xencall.pc

%{_includedir}/xenctrl.h
%{_includedir}/xenctrl_compat.h
%{_libdir}/libxenctrl.a
%{_libdir}/libxenctrl.so
/usr/share/pkgconfig/xencontrol.pc

%{_includedir}/xendevicemodel.h
%{_libdir}/libxendevicemodel.a
%{_libdir}/libxendevicemodel.so
/usr/share/pkgconfig/xendevicemodel.pc

%{_includedir}/xenforeignmemory.h
%{_libdir}/libxenforeignmemory.a
%{_libdir}/libxenforeignmemory.so
/usr/share/pkgconfig/xenforeignmemory.pc

%{_includedir}/xenguest.h
%{_libdir}/libxenguest.a
%{_libdir}/libxenguest.so
/usr/share/pkgconfig/xenguest.pc

%{_includedir}/xentoollog.h
%{_libdir}/libxentoollog.a
%{_libdir}/libxentoollog.so
/usr/share/pkgconfig/xentoollog.pc

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
/usr/share/pkgconfig/xenlight.pc
/usr/share/pkgconfig/xlutil.pc

%{_includedir}/xenstat.h
%{_libdir}/libxenstat.a
%{_libdir}/libxenstat.so
/usr/share/pkgconfig/xenstat.pc

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
%{_libdir}/libxenctrl.so.4.11
%{_libdir}/libxenctrl.so.4.11.0
%{_libdir}/libxenguest.so.4.11
%{_libdir}/libxenguest.so.4.11.0
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

%changelog
* Thu Jul 09 2020 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.11.1-7.10
- Security update
- Related to XSA-317, XSA-319, XSA-321, XSA-328
- See http://xenbits.xen.org/xsa/
- Reboot required

* Tue Apr 14 2020 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.11.1-7.9
- Security update
- Related to XSA-307, XSA-313, XSA-318
- See http://xenbits.xen.org/xsa/
- Reboot required

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
