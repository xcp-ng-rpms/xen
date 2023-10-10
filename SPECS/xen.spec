%global package_speccommit d3d6570f8d2edc18d3d51d16723034a39f9a8b8f
%global usver 4.13.5
%global xsver 9.36
%global xsrel %{xsver}%{?xscount}%{?xshash}
# -*- rpm-spec -*-

# Commitish for Source0, required by tooling.
%global package_srccommit RELEASE-4.13.5

# Hypervisor release.  Should match the tag in the repository and would be in
# the Release field if it weren't for the %%{xsrel} automagic.
%global hv_rel 9.36

# Full hash from the HEAD commit of this repo during processing, usually
# provided by the environment.  Default to ??? if not set.

# Normally derived from the tag and provided by the environment.  May be a
# `git describe` when not building an from a tagged changeset.

%define with_sysv 0
%define with_systemd 1

# Use the production hypervisor by default
%define default_debug_hypervisor 0

%define base_dir  %{name}-%{version}

%define lp_devel_dir %{_usrsrc}/xen-%{version}-%{release}

# Prevent RPM adding Provides/Requires to lp-devel package
%global __provides_exclude_from ^%{lp_devel_dir}/.*$
%global __requires_exclude_from ^%{lp_devel_dir}/.*$

Summary: Xen is a virtual machine monitor
Name:    xen
Version: 4.13.5
Release: %{?xsrel}.3%{?dist}
License: GPLv2 and LGPLv2 and MIT and Public Domain
URL:     https://www.xenproject.org
Source0: xen-4.13.5.tar.gz
Source1: sysconfig_kernel-xen
Source2: xl.conf
Source3: logrotate-xen-tools
Source5: gen_test_metadata.py
Patch0: build-tweaks.patch
Patch1: autoconf-libjson.patch
Patch2: configure-build.patch
Patch3: xenserver-configuration.patch
Patch4: coverity-model.patch
Patch5: backport-680d18763aef.patch
Patch6: backport-cd7dedad8209.patch
Patch7: backport-79cf0989175c.patch
Patch8: backport-6dd95b02ea27.patch
Patch9: backport-0cd791c499bd.patch
Patch10: backport-9356f9de4162.patch
Patch11: backport-c08cbf7fb891.patch
Patch12: backport-3d05407025ed.patch
Patch13: backport-b1710040ca96.patch
Patch14: backport-31bf4f26aa17.patch
Patch15: backport-e9bd648015dd.patch
Patch16: backport-da9290639eb5.patch
Patch17: backport-7b3c5b70a323.patch
Patch18: backport-1171a93b6ca7.patch
Patch19: backport-2004db3ced18.patch
Patch20: backport-59e1f6d89710.patch
Patch21: backport-86cf92f50533.patch
Patch22: backport-0a9c44486b90.patch
Patch23: backport-270ff9a835fb.patch
Patch24: backport-dacb80f9757c.patch
Patch25: backport-1b3cec69bf30.patch
Patch26: backport-8171e0796542.patch
Patch27: backport-6094a3c4fee1.patch
Patch28: backport-96dc77b4b182.patch
Patch29: backport-dca31274846c.patch
Patch30: backport-625a95cc17d5.patch
Patch31: backport-fd0ec12c3a41.patch
Patch32: backport-885d2d20425d.patch
Patch33: backport-9649cef3b3a7.patch
Patch34: backport-a798bac54fe8.patch
Patch35: backport-920d5f31883c.patch
Patch36: backport-c9495bd7dff5.patch
Patch37: backport-53ddfc80a84a.patch
Patch38: backport-a9b6dacf88fe.patch
Patch39: backport-7ff66809ccd5.patch
Patch40: backport-53594c7bd197.patch
Patch41: backport-540d4d60378c.patch
Patch42: backport-3174835ba825.patch
Patch43: backport-c2b4e23fdda4.patch
Patch44: backport-e9aca9470ed8.patch
Patch45: backport-68d757df8dd2.patch
Patch46: backport-17b997aa1edb.patch
Patch47: backport-35b819c45c46.patch
Patch48: backport-d8a6a8b36d86.patch
Patch49: backport-54463aa79dac.patch
Patch50: backport-25636ed707cf.patch
Patch51: backport-4489ffdec331.patch
Patch52: backport-ab5bfc049e8e.patch
Patch53: backport-dc036ab9d506.patch
Patch54: backport-b9e9ccbb11e4.patch
Patch55: backport-b6641f28c593.patch
Patch56: backport-a85f67b2658e.patch
Patch57: backport-80a868f0f6cc.patch
Patch58: backport-a06d3feea3b7.patch
Patch59: backport-758fae24d7b9.patch
Patch60: backport-e373bc1bdc59.patch
Patch61: backport-b7c333016e3d.patch
Patch62: backport-1997d379dc64.patch
Patch63: backport-f7918dc8f94c.patch
Patch64: backport-935e5fb0d570.patch
Patch65: backport-29a6082f21f2.patch
Patch66: backport-7f97193e6aa8.patch
Patch67: backport-e663158bca89.patch
Patch68: backport-4387b4c771fe.patch
Patch69: backport-401c67e9bc8b.patch
Patch70: backport-00c48f57ab36.patch
Patch71: backport-42f0581a91d4.patch
Patch72: backport-5e115dcf76f6.patch
Patch73: backport-faf02c345ec0.patch
Patch74: backport-3068dfd6415a.patch
Patch75: backport-b1278939db0b.patch
Patch76: backport-7e5cffcd1e93.patch
Patch77: backport-81b2b328a26c.patch
Patch78: backport-60390ccb8b9b.patch
Patch79: backport-570da5423dbe.patch
Patch80: backport-0eae016b6e3d.patch
Patch81: backport-f40e1c52e4e0.patch
Patch82: backport-368096b9c4a2.patch
Patch83: backport-e21a6a4f966a.patch
Patch84: backport-935d501ccbf5.patch
Patch85: backport-27713fa2aa21.patch
Patch86: backport-3e9460ec9334.patch
Patch87: backport-e9b4fe263649.patch
Patch88: backport-fb23e8ba2304.patch
Patch89: backport-08693c03e00e.patch
Patch90: backport-95419adfd4b2.patch
Patch91: backport-f17d848c4caa-fix.patch
Patch92: backport-3670abcaf032.patch
Patch93: backport-9fdcf851689c.patch
Patch94: backport-2d1a35f1e6c2.patch
Patch95: backport-3e09045991cd.patch
Patch96: backport-b672695e7488.patch
Patch97: backport-79ca512a1fa6.patch
Patch98: backport-6a9f5477637a.patch
Patch99: backport-93c9edbef51b.patch
Patch100: backport-73c932d0ea43.patch
Patch101: backport-1787cc167906.patch
Patch102: backport-afab477fba3b.patch
Patch103: backport-c76cfada1cfa.patch
Patch104: backport-f26bb285949b.patch
Patch105: backport-4624912c0b55.patch
Patch106: backport-2928c1d250b1.patch
Patch107: backport-6d45368a0a89.patch
Patch108: backport-b17546d7f33e.patch
Patch109: backport-164a0b9653f4.patch
Patch110: backport-737190abb174.patch
Patch111: backport-e083d753924b.patch
Patch112: backport-91bac8ad7c06.patch
Patch113: backport-dd6c062a7a4a.patch
Patch114: backport-9c3b9800e201.patch
Patch115: backport-b11380f6cd58.patch
Patch116: backport-b6b672e8a925.patch
Patch117: backport-834cb8761051.patch
Patch118: backport-eb7518b89be6.patch
Patch119: backport-f282182af329.patch
Patch120: backport-9cfeb83cbe23.patch
Patch121: backport-6809998c5f8f.patch
Patch122: backport-c17072fc164a.patch
Patch123: backport-94c3df9188d6.patch
Patch124: backport-5bd2b82df28c.patch
Patch125: backport-31f3bc97f450.patch
Patch126: backport-b07050e1e8f7.patch
Patch127: backport-88d3ff7ab15d.patch
Patch128: backport-6536688439db.patch
Patch129: backport-81f0eaadf84d.patch
Patch130: backport-e3662437eb43.patch
Patch131: backport-e1828e3032eb.patch
Patch132: backport-969a57f73f6b.patch
Patch133: backport-15b7611efd49.patch
Patch134: backport-00f2992b6c7a.patch
Patch135: backport-614cec7d79d7.patch
Patch136: backport-22b9add22b4a.patch
Patch137: backport-a7e7c7260cde.patch
Patch138: backport-f97c1abf2934.patch
Patch139: backport-39a40f3835ef.patch
Patch140: backport-4116139131e9.patch
Patch141: backport-ad9f7c3b2e0d.patch
Patch142: backport-f3709b15fc86.patch
Patch143: backport-52ce1c97844d.patch
Patch144: backport-81d195c6c0e2.patch
Patch145: backport-f627a39c5e75.patch
Patch146: backport-6ba701064227.patch
Patch147: backport-7f7e55b85fce.patch
Patch148: backport-ea140035d01a.patch
Patch149: backport-e270af94280e.patch
Patch150: backport-ae49ee66cfda.patch
Patch151: backport-cea9ae062295.patch
Patch152: backport-d4012d50082c.patch
Patch153: backport-69e1472d21cf.patch
Patch154: backport-60d1adfa1879.patch
Patch155: backport-e570e8d520ab.patch
Patch156: backport-a0aeab27ee0e.patch
Patch157: backport-e83cd54611fe.patch
Patch158: backport-b874e47eb13f.patch
Patch159: backport-0f2611c52438.patch
Patch160: backport-c3bd0b83ea5b.patch
Patch161: backport-c4e5cc2ccc5b.patch
Patch162: backport-7110192b1df6.patch
Patch163: backport-f838b956779f.patch
Patch164: backport-9272225ca728.patch
Patch165: backport-a0bfdd201ea1.patch
Patch166: backport-1d7fbc535d1d.patch
Patch167: backport-37f82facd62f.patch
Patch168: backport-57f07cca8252.patch
Patch169: backport-c3b6be714c64.patch
Patch170: backport-95db09b1b154.patch
Patch171: backport-ee36179371fd.patch
Patch172: backport-22d5affdf0ce.patch
Patch173: backport-7ba68a6c558e.patch
Patch174: backport-9bafe4a53306.patch
Patch175: backport-b45bfaf359e4.patch
Patch176: backport-9804a5db435f.patch
Patch177: backport-31fbee749a75.patch
Patch178: backport-aecdc28d9538.patch
Patch179: backport-df2db174b36e.patch
Patch180: backport-9b224c25293a.patch
Patch181: backport-3f02e0a70fe9.patch
Patch182: backport-ee7815f49faf.patch
Patch183: backport-acd3fb6d6590.patch
Patch184: backport-f1d7aac1e3c3.patch
Patch185: backport-e267d11969a4.patch
Patch186: backport-831419f82913.patch
Patch187: backport-d2162d884cba.patch
Patch188: backport-ff95dae53e5e.patch
Patch189: backport-10acd21795a9.patch
Patch190: backport-f5d0279839b5.patch
Patch191: backport-a44734df6c24.patch
Patch192: backport-f7d07619d2ae.patch
Patch193: backport-d329b37d1213.patch
Patch194: backport-573279cde1c4.patch
Patch195: backport-ad15a0a8ca25.patch
Patch196: backport-e94af0d58f86.patch
Patch197: backport-3edca52ce736.patch
Patch198: backport-5f08bc9404c7.patch
Patch199: backport-e6f07052ce4a.patch
Patch200: backport-ff8b560be80b.patch
Patch201: backport-36eb2de31b6e.patch
Patch202: backport-2636d8ff7a67.patch
Patch203: backport-425068384210.patch
Patch204: backport-9e7c74e6f9fd.patch
Patch205: backport-d69ccf52ad46.patch
Patch206: backport-b4a23bf6293a.patch
Patch207: backport-63305e5392ec.patch
Patch208: backport-f4ef8a41b808.patch
Patch209: backport-f1315e48a03a.patch
Patch210: backport-1ba66a870eba.patch
Patch211: backport-9276e832aef6.patch
Patch212: backport-d04ae78c34e7.patch
Patch213: backport-4a5577940240.patch
Patch214: backport-ec3474e1dd42.patch
Patch215: backport-433d012c6c27-partial.patch
Patch216: backport-33fb3a661223.patch
Patch217: backport-d484dcca7972.patch
Patch218: backport-ab2d47eb1353.patch
Patch219: backport-245d030f4aa7.patch
Patch220: backport-fc2e1f3aad60.patch
Patch221: backport-c2ec94c370f2.patch
Patch222: backport-21e3ef57e040.patch
Patch223: backport-743e530380a0.patch
Patch224: backport-03812da3754d.patch
Patch225: backport-6bc33366795d.patch
Patch226: backport-bd13dae34809.patch
Patch227: backport-c9985233ca66.patch
Patch228: backport-66c5c9965631.patch
Patch229: backport-1027df4c0082.patch
Patch230: backport-4f20f596ce9b.patch
Patch231: backport-8eb56eb959a5.patch
Patch232: backport-441b1b2a50ea.patch
Patch233: backport-a16dcd48c2db.patch
Patch234: backport-1b67fccf3b02.patch
Patch235: backport-994c1553a158.patch
Patch236: backport-19c6cbd90965.patch
Patch237: backport-0946068e7fae.patch
Patch238: backport-eaa324bfebcf.patch
Patch239: backport-f1e574fa6dea.patch
Patch240: backport-161c37d020a7.patch
Patch241: backport-b95a72bb5b2d.patch
Patch242: backport-8b1ac353b4db.patch
Patch243: backport-694d79ed5aac.patch
Patch244: backport-4c507d8a6b6e.patch
Patch245: backport-56e2c8e58600.patch
Patch246: backport-ef1987fcb0fd.patch
Patch247: backport-43912f8dbb18.patch
Patch248: backport-d9fe459ffad8.patch
Patch249: backport-ce8c930851a5.patch
Patch250: backport-70553000d6b4.patch
Patch251: backport-bbb289f3d5bd.patch
Patch252: backport-8f6bc7f9b72e.patch
Patch253: backport-205a9f970378.patch
Patch254: backport-511b9f286c3d.patch
Patch255: backport-94200e1bae07.patch
Patch256: backport-921afcbae843.patch
Patch257: backport-724c0d94ff79.patch
Patch258: backport-36525a964fb6.patch
Patch259: backport-e0586a4ff514.patch
Patch260: backport-aab4b38b5d77.patch
Patch261: backport-c81b287e00b1.patch
Patch262: backport-f91c5ea97067.patch
Patch263: backport-4b2cdbfe766e.patch
Patch264: backport-c0dd53b8cbd1.patch
Patch265: xsa-434-1-x86-spec-ctrl-Rework-ibpb_calculations.patch
Patch266: xsa-434-2-x86-spec-ctrl-Enumerations-for-Speculative-Return-St.patch
Patch267: xsa-434-3-x86-spec-ctrl-Mitigate-Speculative-Return-Stack-Over.patch
Patch268: xsa-435-1-x86-cpu-policy-Hide-CLWB-by-default-on-SKX-CLX-CPX.patch
Patch269: xsa-435-2-x86-spec-ctrl-Enumerations-for-Gather-Data-Sampling.patch
Patch270: xsa-435-3-x86-spec-ctrl-Mitigate-Gather-Data-Sampling.patch
Patch271: x86-Activate-Data-Operand-Invariant-Timing-Mode-by-d.patch
Patch272: 0001-x86-AMD-make-HT-range-dynamic-for-Fam17-and-up.patch
Patch273: 0001-tools-Fix-pkg-config-file-for-libxenstore.patch
Patch274: 0006-x86-vpt-fix-injection-to-remote-vCPU.patch
Patch275: detect-nehalem-c-state.patch
Patch276: quirk-hp-gen8-rmrr.patch
Patch277: quirk-pci-phantom-function-devices.patch
Patch278: 0001-x86-hpet-Pre-cleanup.patch
Patch279: 0002-x86-hpet-Use-singe-apic-vector-rather-than-irq_descs.patch
Patch280: 0003-x86-hpet-Post-cleanup.patch
Patch281: 0002-libxc-retry-shadow-ops-if-EBUSY-is-returned.patch
Patch282: avoid-gnt-unmap-tlb-flush-if-not-accessed.patch
Patch283: 0002-efi-Ensure-incorrectly-typed-runtime-services-get-ma.patch
Patch284: 0001-x86-time-Don-t-use-EFI-s-GetTime-call.patch
Patch285: 0001-efi-Workaround-page-fault-during-runtime-service.patch
Patch286: 0001-x86-HVM-Avoid-cache-flush-operations-during-hvm_load.patch
Patch287: 0001-libxl-Don-t-insert-PCI-device-into-xenstore-for-HVM-.patch
Patch288: 0001-x86-PoD-Command-line-option-to-prohibit-any-PoD-oper.patch
Patch289: livepatch-ignore-duplicate-new.patch
Patch290: default-log-level-info.patch
Patch291: 0001-lib-Add-a-generic-implementation-of-current_text_add.patch
Patch292: 0002-sched-Remove-dependency-on-__LINE__-for-release-buil.patch
Patch293: pygrub-Ignore-GRUB2-if-statements.patch
Patch294: libfsimage-Add-support-for-btrfs.patch
Patch295: quiet-broke-irq-affinity.patch
Patch296: 0001-x86-msr-Blacklist-various-MSRs-which-guests-definite.patch
Patch297: 0001-Hide-AVX-512-from-guests-by-default.patch
Patch298: 0001-common-page_alloc-don-t-idle-scrub-before-microcode-.patch
Patch299: 0001-xsm-hide-detailed-Xen-version-from-unprivileged-gues.patch
Patch300: 0003-credit-Limit-load-balancing-to-once-per-millisecond.patch
Patch301: xen-tweak-cmdline-defaults.patch
Patch302: xen-tweak-debug-overhead.patch
Patch303: tweak-iommu-policy.patch
Patch304: tweak-sc-policy.patch
Patch305: disable-core-parking.patch
Patch306: 0001-Allocate-space-in-structs-pre-emptively-to-increase-.patch
Patch307: 0001-x86-mm-partially-revert-37201c62-make-logdirty-and-i.patch
Patch308: hitachi-driver-domain-ssid.patch
Patch309: livepatch-payload-in-header.patch
Patch310: xen-define-offsets-for-kdump.patch
Patch311: xen-scheduler-auto-privdom-weight.patch
Patch312: xen-hvm-disable-tsc-ramping.patch
Patch313: xen-default-cpufreq-governor-to-performance-on-intel.patch
Patch314: 0001-Partially-revert-08754333892-hvmloader-limit-CPUs-ex.patch
Patch315: 0001-x86-pv-silently-discard-writes-into-MSR_AMD64_LS_CFG.patch
Patch316: i8259-timers-pick-online-vcpu.patch
Patch317: revert-ca2eee92df44.patch
Patch318: libxc-stubs-hvm_check_pvdriver.patch
Patch319: libxc-cpuid-cores_per_socket.patch
Patch320: libxc-cpu-policies.patch
Patch321: max-featureset-compat.patch
Patch322: pygrub-add-default-and-extra-args.patch
Patch323: pygrub-always-boot-default.patch
Patch324: pygrub-friendly-no-fs.patch
Patch325: pygrub-image-max-size.patch
Patch326: pygrub-default-xenmobile-kernel.patch
Patch327: pygrub-blacklist-support.patch
Patch328: ucode-compat.patch
Patch329: oem-bios-xensource.patch
Patch330: oem-bios-magic-from-xenstore.patch
Patch331: misc-log-guest-consoles.patch
Patch332: fix-ocaml-libs.patch
Patch333: ocaml-cpuid-helpers.patch
Patch334: xentop-vbd3.patch
Patch335: mixed-domain-runstates.patch
Patch336: xenguest.patch
Patch337: xen-vmdebug.patch
Patch338: oxenstore-extra-debug.patch
Patch339: oxenstore-censor-sensitive-data.patch
Patch340: oxenstore-large-packets.patch
Patch341: nvidia-vga.patch
Patch342: hvmloader-disable-pci-option-rom-loading.patch
Patch343: xen-force-software-vmcs-shadow.patch
Patch344: 0001-x86-vvmx-add-initial-PV-EPT-support-in-L0.patch
Patch345: use-msr-ll-instead-of-vmcs-efer.patch
Patch346: add-pv-iommu-headers.patch
Patch347: add-pv-iommu-local-domain-ops.patch
Patch348: add-pv-iommu-foreign-support.patch
Patch349: upstream-pv-iommu-tools.patch
Patch350: allow-rombios-pci-config-on-any-host-bridge.patch
Patch351: 0007-hypercall-XENMEM_get_mfn_from_pfn.patch
Patch352: gvt-g-hvmloader+rombios.patch
Patch353: xen-introduce-cmdline-to-control-introspection-extensions.patch
Patch354: xen-domctl-set-privileged-domain.patch
Patch355: xen-reexecute-instn-under-monitor-trap.patch
Patch356: revert-x86-mm-suppress-vm_events-caused-by-page-walks.patch
Patch357: xen-emulate-Bypass-the-emulator-if-emulation-fails.patch
Patch358: xen-introspection-pause.patch
Patch359: xen-always-enable-altp2m-external-mode.patch
Patch360: xen-spec-ctrl-utility.patch

#XCP-ng patches
Patch1001: backport-f7065b24f4fb.patch
Patch1002: backport-145a69c0944a.patch
Patch1003: backport-1c18d7377453.patch
Patch1004: backport-694bb0f280fd.patch
Patch1005: backport-7125429aafb9.patch
Patch1006: backport-45f00557350d.patch
Patch1007: backport-7aa28849a115.patch
Patch1008: backport-21bdc25b05a0.patch
Patch1009: backport-3ee6066bcd73.patch
Patch1010: backport-de1d26500139.patch
Patch1011: backport-b5926c6ecf05.patch
Patch1012: xsa440-4.13.patch
Patch1013: xsa442-4.13.patch
Patch1014: xsa443_xsa443-4.13-01.patch
Patch1015: xsa443_xsa443-4.13-02.patch
Patch1016: xsa443_xsa443-4.13-03.patch
Patch1017: xsa443_xsa443-4.13-04.patch
Patch1018: xsa444-4.13-1.patch
Patch1019: xsa444-4.13-2.patch

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
Requires: edk2
Requires: ipxe
%if %with_systemd
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
%endif
%description dom0-tools
This package contains the Xen Hypervisor control domain tools.

%package dom0-libs
Summary: Xen Hypervisor Domain 0 libraries
License: GPLv2 and LGPLv2 and MIT
Requires: xen-hypervisor = %{version}
%description dom0-libs
This package contains the Xen Hypervisor control domain libraries.

%package dom0-libs-devel
Summary: Xen Hypervisor Domain 0 headers
License: GPLv2 and LGPLv2 and MIT
Requires: xen-devel = %{version}
Requires: xen-dom0-libs = %{version}

# XCP-ng: Provides kept for 8.2 for repo consistency, due to vhostmd requiring it
Provides: xen-dom0-devel = %{version}
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

%package installer-files
Summary: Xen files for the XenServer installer
License: LGPLv2
%description installer-files
This package contains the minimal subset of libraries and binaries required in
the XenServer installer environment.

%package dom0-tests
Summary: Xen Hypervisor tests
License: GPLv2
%description dom0-tests
This package contains test cases for the Xen Hypervisor.

%package lp-devel_%{version}_%{xsrel}
License: GPLv2
Summary: Development package for building livepatches
%description lp-devel_%{version}_%{xsrel}
Contains the prepared source files, config, and xen-syms for building live
patches against base version %{version}-%{xsrel}.

%prep
%autosetup -p1
%{?_cov_prepare}
%{?_coverity:cp misc/coverity/nodefs.h %{_cov_dir}/config/user_nodefs.h}
%{?_cov_make_model:%{_cov_make_model misc/coverity/model.c}}

base_cset=$(sed -ne 's/Changeset: \(.*\)/\1/p' < .gitarchive-info)
pq_cset="%{package_speccommit}"
echo "${base_cset:0:12}, pq ${pq_cset:0:12}" > .scmversion

%build

export XEN_TARGET_ARCH=%{_arch}

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

# Take a snapshot of the configured source tree for livepatches
mkdir ../livepatch-src
cp -a . ../livepatch-src/

# Build tools and man pages
%{?_cov_wrap} %{make_build} build-tools
%{make_build} -C docs man-pages

# The hypervisor build system can't cope with RPM's {C,LD}FLAGS
unset CFLAGS
unset LDFLAGS

build_xen () { # $1=vendorversion $2=buildconfig $3=outdir $4=cov
    local mk ver cov

    [ -n "$1" ] && ver="XEN_VENDORVERSION=$1"
    [ -n "$4" ] && cov="%{?_cov_wrap}"

    mk="$cov %{make_build} -C xen $ver"

    cp -a buildconfigs/$2 xen/.config
    $mk olddefconfig
    $mk build
    $mk MAP

    mkdir -p xen/$3
    cp -a xen/xen xen/xen.gz xen/System.map xen/xen-syms xen/.config xen/$3
}

# Builds of Xen
build_xen -%{hv_rel}   config-release         build-xen-release

%{make_build} -C xen clean
build_xen -%{hv_rel}-d config-debug           build-xen-debug      cov

%{make_build} -C xen clean
build_xen ""           config-pvshim-release  build-shim-release

%{make_build} -C xen clean
build_xen ""           config-pvshim-debug    build-shim-debug


%install

export XEN_TARGET_ARCH=%{_arch}

# The existence of this directory causes ocamlfind to put things in it
mkdir -p %{buildroot}%{_libdir}/ocaml/stublibs

# Install tools and man pages
%{make_build} DESTDIR=%{buildroot} install-tools
%{make_build} DESTDIR=%{buildroot} -C docs install-man-pages

# Install artefacts for livepatches
%{__install} -p -D -m 644 xen/build-xen-release/xen-syms %{buildroot}%{lp_devel_dir}/xen-syms
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

# Install release & debug shims
install_shim () { # $1=outdir $2=suffix
    %{__install} -p -D -m 644 xen/$1/xen      %{buildroot}%{_libexecdir}/%{name}/boot/xen-shim-$2
    %{__install} -p -D -m 644 xen/$1/xen-syms %{buildroot}/usr/lib/debug%{_libexecdir}/%{name}/boot/xen-shim-syms-$2
}
install_shim build-shim-release release
install_shim build-shim-debug   debug

# choose between debug and release PV shim build
%if %{default_debug_hypervisor}
ln -sf xen-shim-debug %{buildroot}%{_libexecdir}/%{name}/boot/xen-shim
%else
ln -sf xen-shim-release %{buildroot}%{_libexecdir}/%{name}/boot/xen-shim
%endif

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
%{_libdir}/libxenevtchn.so.1.2
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
%exclude %{_libexecdir}/%{name}/bin/depriv-fd-checker
%{_libexecdir}/%{name}/bin/test-cpu-policy
%{_libexecdir}/%{name}/bin/test-xenstore
%{_datadir}/xen-dom0-tests-metadata.json

%files lp-devel_%{version}_%{xsrel}
%{lp_devel_dir}

%doc

%post hypervisor
# Update the debug and release symlinks
ln -sf %{name}-%{version}-%{hv_rel}-d.gz /boot/xen-debug.gz
ln -sf %{name}-%{version}-%{hv_rel}.gz /boot/xen-release.gz

# Point /boot/xen.gz appropriately
if [ ! -e /boot/xen.gz ]; then
%if %{default_debug_hypervisor}
    # Use a debug hypervisor by default
    ln -sf %{name}-%{version}-%{hv_rel}-d.gz /boot/xen.gz
%else
    # Use a production hypervisor by default
    ln -sf %{name}-%{version}-%{hv_rel}.gz /boot/xen.gz
%endif
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

mkdir -p %{_rundir}/reboot-required.d/%{name}
touch %{_rundir}/reboot-required.d/%{name}/%{version}-%{hv_rel}

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
* Tue Oct 03 2023 Andrei Semenov <andrei.semenov@vates.tech> - 4.13.5-9.36.3
- Security update
- Fixes for XSA-440, XSA-442, XSA-443 and XSA-444

* Tue Sep 26 2023 Andrei Semenov <andrei.semenov@vates.tech> - 4.13.5-9.36.2
- More fixes to Zenbleed (XenServer backport from Xen Project)
- Fix for AMD errata #1474 (XenServer backport from Xen Project)
- Fix for XSA-429 (XenServer backport from Xen Project)

* Tue Aug 08 2023 Gael Duperrey <gduperrey@vates.fr> - 4.13.5-9.36.1
- Security update, synced from hotfix XS82ECU1045
- *** Upstream changelog ***
- * Thu Aug 3 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-9.36
- - Fixes for
-   - XSA-434 CVE-2023-20569
-   - XSA-435 CVE-2022-40982
- - Expose MSR_ARCH_CAPS to guests on all Intel hardware by default.  On Cascade
-   Lake and later hardware, guests now see the bits stating hardware immunity
-   to various speculative vulnerabilities.

* Thu Aug 03 2023 Gael Duperrey <gduperrey@vates.fr> - 4.13.5-9.35.1
- Synced from hotfix XS82ECU1044
- *** Upstream changelog ***
- * Tue Aug 1 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-9.35
- - Fix bug in XSA-433 fix, which accidentally disabled a hardware errata workaround.

* Mon Jul 24 2023 Gael Duperrey <gduperrey@vates.fr> - 4.13.5-9.34.1
- Security update, synced from hotfix XS82ECU1041
- *** Upstream changelog ***
- * Sat Jul 22 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-9.34
- - Fix for XSA-433 CVE-2023-20593.
- * Tue Jul 4 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-9.33
- - Hide MPX by default from guests.  This simplifies cross-pool upgrade scenarios.
- - Limit scheduler loadbalancing to once per millisecond.  This improves performance on large systems.

* Thu May 25 2023 Gael Duperrey <gduperrey@vates.fr> - 4.13.5-9.32.1
- Synced from hotfix XS82ECU1034
- *** Upstream changelog ***
- * Tue May 16 2023 Roger Pau Monné <roger.pau@citrix.com> - 4.13.5-9.32
- - Mitigate performance degradation with logdirty by disabling VCPU_SSHOTTMR_future.
- - Adjust bogus assert in AMD-Vi code.
- - Early boot improvements.

* Thu May 11 2023 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.5-9.31.1
- Synced from hotfix XS82ECU1030
- Dropped our XSA-427 to 429 patches, now applied upstream
- *** Upstream changelog ***
- * Mon Apr 17 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-9.31
- - Remove the NR_IOMMUs compile time limit.  This is necessary to boot on
-   4-socket Sapphire Rapids systems.
- - Cope booting in x2APIC mode on AMD systems without XT mode.
- - Load AMD microcode on all logical processors.
- - Fixes for
-   - XSA-427 CVE-2022-42332
-   - XSA-428 CVE-2022-42333 CVE-2022-42334
-   - XSA-429 CVE-2022-42331
- - Increase the size of the serial transmit buffer.

* Thu Mar 16 2023 Andrei Semenov <andrei.semenov@vates.fr>  - 4.13.5-9.30.3
- Fix for XSA-427 (applied as is from Xen Project).
- Fix for XSA-428 (applied as is from Xen Project). part 1
- Fix for XSA-428 (applied as is from Xen Project). part 2
- Fix for XSA-429 (adapted from Xen Project)

* Mon Mar 13 2023 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.5-9.30.2
- Restore xen-dom0-devel Provides for xen-dom0-libs-devel

* Thu Feb 23 2023 Gael Duperrey <gduperrey@vates.fr> 4.13.5-9.30.1
* Synced from hotfix XS82ECU1026
- *** Upstream changelog ***
- * Mon Feb 6 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-9.30
- - Fix for XSA-426 CVE-2022-27672.
- - Fix memory corruption issues in the Ocaml bindings.
- - On xenstored live update, validate the config file before launching into the new xenstored.
- * Mon Feb 6 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-9.29
- - Update to Xen 4.13.5
- The upstream commit history before this point also mentions "Initial Sapphire Rapids support" and other changes

* Thu Feb 16 2023 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.13.4-9.29.2
- Fix XSA-426
- Reboot required

* Mon Jan 02 2023 Gael Duperrey <gduperrey@vates.fr> - 4.13.4-9.29.1
- Synced from hotfix XS82ECU1023
- Enable AVX-512 by default for EPYC Zen4 (Genoa)
- Reboot required

* Wed Nov 09 2022 Gael Duperrey <gduperrey@vates.fr> - 4.13.4-9.28.1
- Synced from hotfix XS82ECU1021
- Fix XSA-422 and other issues
- See http://xenbits.xen.org/xsa/
- Reboot required

* Wed Nov 02 2022 Gael Duperrey <gduperrey@vates.fr> - 4.13.4-9.27.1
- Security update, synced from hotfix XS82ECU1020
- Fix XSA-326 XSA-414 XSA-415 XSA-416 XSA-417 XSA-418 XSA-419 XSA-420 XSA-421
- Reboot required

* Tue Oct 11 2022 Gael Duperrey <gduperrey@vates.fr> - 4.13.4-9.26.1
- Security update, synced from hotfix XS82ECU1016
- Fix XSA-410, XSA-411, and other issues
- Reboot required

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
