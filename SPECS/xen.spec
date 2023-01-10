%global package_speccommit 13b055d71c84777f8cd2e03ebe8041674cbd9e5d
%global usver 4.13.4
%global xsver 10.36
%global xsrel %{xsver}%{?xscount}%{?xshash}
# -*- rpm-spec -*-

# Commitish for Source0, required by tooling.
%global package_srccommit RELEASE-4.13.4

# Hypervisor release.  Should match the tag in the repository and would be in
# the Release field if it weren't for the %%{xsrel} automagic.
%global hv_rel 10.36

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
Version: 4.13.4
Release: %{?xsrel}%{?dist}
License: GPLv2 and LGPLv2 and MIT and Public Domain
URL:     http://www.xenproject.org
Source0: xen-4.13.4.tar.gz
Source1: sysconfig_kernel-xen
Source2: xl.conf
Source3: logrotate-xen-tools
Source5: gen_test_metadata.py
Patch0: build-tweaks.patch
Patch1: autoconf-libjson.patch
Patch2: configure-build.patch
Patch3: xenserver-configuration.patch
Patch4: coverity-model.patch
Patch5: backport-b4bb02d5999a.patch
Patch6: backport-d94d006ed360.patch
Patch7: backport-d3cfb4b3a680.patch
Patch8: backport-d3c2319ea165.patch
Patch9: backport-e48c7878e54a.patch
Patch10: backport-ce49a1d6d819.patch
Patch11: backport-7b9814b250a5.patch
Patch12: backport-8ed46cc1ef14.patch
Patch13: backport-2ce2aec8c148.patch
Patch14: backport-920e93df4e16.patch
Patch15: backport-650b888c8a0a.patch
Patch16: backport-81918cead1a5.patch
Patch17: backport-33c13654cb6d.patch
Patch18: backport-235aa158e0f7.patch
Patch19: backport-73e25ecaef14.patch
Patch20: backport-92acf6b23154.patch
Patch21: backport-ab37463eec57.patch
Patch22: backport-7cfe3570b1c0.patch
Patch23: backport-e6d6b5ba030a.patch
Patch24: backport-454d5351a93d.patch
Patch25: backport-169a2834ef5d.patch
Patch26: backport-a6902a65160a.patch
Patch27: backport-d64d46685c77.patch
Patch28: backport-fe97133b5dee.patch
Patch29: backport-3826ba5f8271.patch
Patch30: backport-7669737d7da5.patch
Patch31: backport-c7da430b21e0.patch
Patch32: backport-fce392fa36c3.patch
Patch33: backport-8d9f36132afd.patch
Patch34: backport-e8c04e468312.patch
Patch35: backport-f9ae12fc103c.patch
Patch36: backport-c2095ac76be0.patch
Patch37: backport-a84bc5bde583.patch
Patch38: backport-413b08328a57.patch
Patch39: backport-87ff11354f0d.patch
Patch40: backport-14c5e0c13422.patch
Patch41: backport-8a2cc1ed1aee.patch
Patch42: backport-f614e3c51ae0.patch
Patch43: backport-4eddf132b5e0.patch
Patch44: backport-d43b47eb6a26.patch
Patch45: backport-55e4c720b269.patch
Patch46: backport-8974821f13ad.patch
Patch47: backport-bf5f5e89f040.patch
Patch48: backport-074e388fe0df.patch
Patch49: backport-b8d573a31beb.patch
Patch50: backport-159e2235d75b.patch
Patch51: backport-a7e72872e99b.patch
Patch52: backport-4b42462701f0.patch
Patch53: backport-10d8c56e93a0.patch
Patch54: backport-196b4f4d34d4.patch
Patch55: backport-ba3367292342.patch
Patch56: backport-fbf19baaaf5c.patch
Patch57: backport-5994b739453f.patch
Patch58: backport-ebe3f5d90924.patch
Patch59: backport-3c71016e68f2.patch
Patch60: backport-3feba68e15d3.patch
Patch61: backport-f8614c7153f9.patch
Patch62: backport-c946524a65f3.patch
Patch63: backport-5475195ec490.patch
Patch64: backport-4e38cc1baea0.patch
Patch65: backport-763f965d04c5.patch
Patch66: backport-0021c269786e.patch
Patch67: backport-aa7891098cc4.patch
Patch68: backport-181ff7aced0e.patch
Patch69: backport-08eec20dc055.patch
Patch70: backport-6e537d36943e.patch
Patch71: backport-3e7aa35a56f9.patch
Patch72: backport-eed4ef4177b8.patch
Patch73: backport-042de0843936.patch
Patch74: backport-149ebf0e0228.patch
Patch75: backport-fcba6c74e149.patch
Patch76: backport-95fe444988f0.patch
Patch77: backport-6f311278e9f8.patch
Patch78: backport-1761828e6d00.patch
Patch79: backport-cde36e0c369d.patch
Patch80: backport-538b61b90393.patch
Patch81: backport-2963ee5d065e.patch
Patch82: backport-e84ef3b0810c.patch
Patch83: backport-5fa4f2c6c8db.patch
Patch84: backport-f859218309f0.patch
Patch85: backport-8cd25aecce59.patch
Patch86: backport-b917d57d46c3.patch
Patch87: backport-115156c416ad.patch
Patch88: backport-c17d49134aef.patch
Patch89: backport-7dc06ed1f2ab.patch
Patch90: backport-146b9544fbef.patch
Patch91: backport-63dc2a18f8ff.patch
Patch92: backport-d71e4eca23e1.patch
Patch93: backport-c084ee8e5834.patch
Patch94: backport-bc93157f7b3b.patch
Patch95: backport-013530016062.patch
Patch96: backport-c3c5f0aa4684.patch
Patch97: backport-723e24871833.patch
Patch98: backport-0252d044fcd4.patch
Patch99: backport-e30f7c6b6b8e.patch
Patch100: backport-2fdf8740b9f4.patch
Patch101: backport-e6655e8f25e4.patch
Patch102: backport-b97e59f10d6f.patch
Patch103: backport-e2b7fa7508d7.patch
Patch104: backport-d816b470e022.patch
Patch105: backport-ba1cff4b1be9.patch
Patch106: backport-1cfbd2567b68.patch
Patch107: backport-8c8a5b3905d4.patch
Patch108: backport-a8922c661c2e.patch
Patch109: backport-145871612f70.patch
Patch110: backport-3545d0f15efc.patch
Patch111: backport-94b2f97eaae1.patch
Patch112: backport-29506319c6ce.patch
Patch113: backport-30a293fba36b.patch
Patch114: backport-377dbf9cea55.patch
Patch115: backport-4d753ccf9ddf.patch
Patch116: backport-c0de5d3b482d.patch
Patch117: backport-1151d260d7a0.patch
Patch118: backport-680d18763aef.patch
Patch119: backport-cd7dedad8209.patch
Patch120: backport-79cf0989175c.patch
Patch121: backport-6dd95b02ea27.patch
Patch122: backport-0cd791c499bd.patch
Patch123: backport-9356f9de4162.patch
Patch124: backport-c08cbf7fb891.patch
Patch125: backport-3d05407025ed.patch
Patch126: backport-b1710040ca96.patch
Patch127: backport-31bf4f26aa17.patch
Patch128: backport-e9bd648015dd.patch
Patch129: backport-da9290639eb5.patch
Patch130: backport-7b3c5b70a323.patch
Patch131: backport-1171a93b6ca7.patch
Patch132: backport-2004db3ced18.patch
Patch133: backport-59e1f6d89710.patch
Patch134: backport-86cf92f50533.patch
Patch135: backport-0a9c44486b90.patch
Patch136: backport-270ff9a835fb.patch
Patch137: backport-dacb80f9757c.patch
Patch138: backport-1b3cec69bf30.patch
Patch139: backport-8171e0796542.patch
Patch140: backport-9649cef3b3a7.patch
Patch141: backport-a798bac54fe8.patch
Patch142: backport-920d5f31883c.patch
Patch143: backport-c9495bd7dff5.patch
Patch144: backport-53ddfc80a84a.patch
Patch145: backport-a9b6dacf88fe.patch
Patch146: backport-7ff66809ccd5.patch
Patch147: backport-53594c7bd197.patch
Patch148: backport-540d4d60378c.patch
Patch149: backport-3174835ba825.patch
Patch150: backport-c2b4e23fdda4.patch
Patch151: backport-e9aca9470ed8.patch
Patch152: backport-68d757df8dd2.patch
Patch153: backport-17b997aa1edb.patch
Patch154: backport-35b819c45c46.patch
Patch155: backport-d8a6a8b36d86.patch
Patch156: backport-54463aa79dac.patch
Patch157: backport-4489ffdec331.patch
Patch158: backport-ab5bfc049e8e.patch
Patch159: backport-dc036ab9d506.patch
Patch160: backport-b9e9ccbb11e4.patch
Patch161: backport-b6641f28c593.patch
Patch162: backport-a85f67b2658e.patch
Patch163: backport-80a868f0f6cc.patch
Patch164: backport-a06d3feea3b7.patch
Patch165: backport-758fae24d7b9.patch
Patch166: backport-e373bc1bdc59.patch
Patch167: backport-b7c333016e3d.patch
Patch168: backport-1997d379dc64.patch
Patch169: backport-f7918dc8f94c.patch
Patch170: backport-935e5fb0d570.patch
Patch171: backport-29a6082f21f2.patch
Patch172: backport-7f97193e6aa8.patch
Patch173: backport-e663158bca89.patch
Patch174: backport-4387b4c771fe.patch
Patch175: backport-401c67e9bc8b.patch
Patch176: backport-00c48f57ab36.patch
Patch177: backport-42f0581a91d4.patch
Patch178: backport-5e115dcf76f6.patch
Patch179: backport-faf02c345ec0.patch
Patch180: backport-3068dfd6415a.patch
Patch181: backport-b1278939db0b.patch
Patch182: backport-7e5cffcd1e93.patch
Patch183: backport-5d752df85f2c.patch
Patch184: backport-e8af54084586.patch
Patch185: backport-81b2b328a26c.patch
Patch186: backport-60390ccb8b9b.patch
Patch187: backport-c4441ab1f1d5.patch
Patch188: backport-570da5423dbe.patch
Patch189: backport-0eae016b6e3d.patch
Patch190: backport-6b0ac9a4e239.patch
Patch191: backport-f40e1c52e4e0.patch
Patch192: backport-368096b9c4a2.patch
Patch193: backport-e21a6a4f966a.patch
Patch194: backport-935d501ccbf5.patch
Patch195: backport-fb23e8ba2304.patch
Patch196: backport-08693c03e00e.patch
Patch197: backport-95419adfd4b2.patch
Patch198: backport-f17d848c4caa-fix.patch
Patch199: backport-3670abcaf032.patch
Patch200: backport-9fdcf851689c.patch
Patch201: backport-2d1a35f1e6c2.patch
Patch202: backport-3e09045991cd.patch
Patch203: backport-b672695e7488.patch
Patch204: backport-79ca512a1fa6.patch
Patch205: backport-6a9f5477637a.patch
Patch206: backport-93c9edbef51b.patch
Patch207: backport-73c932d0ea43.patch
Patch208: backport-1787cc167906.patch
Patch209: backport-afab477fba3b.patch
Patch210: backport-c76cfada1cfa.patch
Patch211: backport-f26bb285949b.patch
Patch212: backport-4624912c0b55.patch
Patch213: backport-2928c1d250b1.patch
Patch214: backport-6d45368a0a89.patch
Patch215: backport-b17546d7f33e.patch
Patch216: backport-164a0b9653f4.patch
Patch217: backport-737190abb174.patch
Patch218: backport-e083d753924b.patch
Patch219: backport-91bac8ad7c06.patch
Patch220: backport-dd6c062a7a4a.patch
Patch221: backport-9c3b9800e201.patch
Patch222: backport-b11380f6cd58.patch
Patch223: backport-b6b672e8a925.patch
Patch224: backport-834cb8761051.patch
Patch225: backport-eb7518b89be6.patch
Patch226: backport-f282182af329.patch
Patch227: backport-9cfeb83cbe23.patch
Patch228: backport-6809998c5f8f.patch
Patch229: backport-31f3bc97f450.patch
Patch230: backport-b07050e1e8f7.patch
Patch231: backport-88d3ff7ab15d.patch
Patch232: backport-6536688439db.patch
Patch233: backport-81f0eaadf84d.patch
Patch234: backport-e3662437eb43.patch
Patch235: x86-cpuid-Infrastructure-for-leaf-0x80000021.eax.patch
Patch236: backport-e1828e3032eb.patch
Patch237: backport-969a57f73f6b.patch
Patch238: backport-15b7611efd49.patch
Patch239: backport-00f2992b6c7a.patch
Patch240: backport-614cec7d79d7.patch
Patch241: backport-22b9add22b4a.patch
Patch242: backport-a7e7c7260cde.patch
Patch243: backport-f97c1abf2934.patch
Patch244: backport-39a40f3835ef.patch
Patch245: backport-4116139131e9.patch
Patch246: backport-ad9f7c3b2e0d.patch
Patch247: backport-f3709b15fc86.patch
Patch248: backport-52ce1c97844d.patch
Patch249: backport-81d195c6c0e2.patch
Patch250: backport-f627a39c5e75.patch
Patch251: backport-6ba701064227.patch
Patch252: backport-7f7e55b85fce.patch
Patch253: backport-ea140035d01a.patch
Patch254: backport-e270af94280e.patch
Patch255: backport-60d1adfa1879.patch
Patch256: backport-e570e8d520ab.patch
Patch257: backport-a0aeab27ee0e.patch
Patch258: backport-31b41ce858c8.patch
Patch259: backport-0f2611c52438.patch
Patch260: backport-c3bd0b83ea5b.patch
Patch261: backport-c4e5cc2ccc5b.patch
Patch262: backport-7110192b1df6.patch
Patch263: backport-f838b956779f.patch
Patch264: backport-9272225ca728.patch
Patch265: backport-a0bfdd201ea1.patch
Patch266: backport-1d7fbc535d1d.patch
Patch267: backport-c3b6be714c64.patch
Patch268: backport-95db09b1b154.patch
Patch269: backport-ee36179371fd.patch
Patch270: backport-22d5affdf0ce.patch
Patch271: backport-7ba68a6c558e.patch
Patch272: backport-9bafe4a53306.patch
Patch273: backport-b45bfaf359e4.patch
Patch274: backport-9804a5db435f.patch
Patch275: backport-31fbee749a75.patch
Patch276: backport-aecdc28d9538.patch
Patch277: backport-df2db174b36e.patch
Patch278: backport-9b224c25293a.patch
Patch279: backport-3f02e0a70fe9.patch
Patch280: backport-ee7815f49faf.patch
Patch281: backport-acd3fb6d6590.patch
Patch282: backport-d2162d884cba.patch
Patch283: backport-ff95dae53e5e.patch
Patch284: backport-10acd21795a9.patch
Patch285: 0001-x86-cpuid-Infrastructure-to-support-pseudo-feature-i.patch
Patch286: 0002-x86-Activate-Data-Operand-Invariant-Timing-Mode-by-d.patch
Patch287: 0001-x86-AMD-make-HT-range-dynamic-for-Fam17-and-up.patch
Patch288: 0001-tools-Fix-pkg-config-file-for-libxenstore.patch
Patch289: 0006-x86-vpt-fix-injection-to-remote-vCPU.patch
Patch290: 0003-xen-microcode-add-information-about-currently-loaded.patch
Patch291: 0004-microcode-add-sequential-application-policy.patch
Patch292: 0007-microcode-update-raw-cpuid-policy-after-a-successful.patch
Patch293: 0001-microcode-remove-panic-calls.patch
Patch294: detect-nehalem-c-state.patch
Patch295: quirk-hp-gen8-rmrr.patch
Patch296: quirk-pci-phantom-function-devices.patch
Patch297: 0001-x86-hpet-Pre-cleanup.patch
Patch298: 0002-x86-hpet-Use-singe-apic-vector-rather-than-irq_descs.patch
Patch299: 0003-x86-hpet-Post-cleanup.patch
Patch300: 0002-libxc-retry-shadow-ops-if-EBUSY-is-returned.patch
Patch301: avoid-gnt-unmap-tlb-flush-if-not-accessed.patch
Patch302: 0002-efi-Ensure-incorrectly-typed-runtime-services-get-ma.patch
Patch303: 0001-x86-time-Don-t-use-EFI-s-GetTime-call.patch
Patch304: 0001-efi-Workaround-page-fault-during-runtime-service.patch
Patch305: 0001-x86-HVM-Avoid-cache-flush-operations-during-hvm_load.patch
Patch306: 0001-libxl-Don-t-insert-PCI-device-into-xenstore-for-HVM-.patch
Patch307: 0001-x86-PoD-Command-line-option-to-prohibit-any-PoD-oper.patch
Patch308: livepatch-ignore-duplicate-new.patch
Patch309: default-log-level-info.patch
Patch310: 0001-lib-Add-a-generic-implementation-of-current_text_add.patch
Patch311: 0002-sched-Remove-dependency-on-__LINE__-for-release-buil.patch
Patch312: pygrub-Ignore-GRUB2-if-statements.patch
Patch313: libfsimage-Add-support-for-btrfs.patch
Patch314: quiet-broke-irq-affinity.patch
Patch315: 0001-x86-msr-Blacklist-various-MSRs-which-guests-definite.patch
Patch316: 0001-Hide-AVX-512-from-guests-by-default.patch
Patch317: 0001-common-page_alloc-don-t-idle-scrub-before-microcode-.patch
Patch318: 0001-xsm-hide-detailed-Xen-version-from-unprivileged-gues.patch
Patch319: xen-tweak-cmdline-defaults.patch
Patch320: xen-tweak-debug-overhead.patch
Patch321: tweak-iommu-policy.patch
Patch322: tweak-sc-policy.patch
Patch323: disable-core-parking.patch
Patch324: 0001-Allocate-space-in-structs-pre-emptively-to-increase-.patch
Patch325: 0001-x86-mm-partially-revert-37201c62-make-logdirty-and-i.patch
Patch326: hitachi-driver-domain-ssid.patch
Patch327: livepatch-payload-in-header.patch
Patch328: xen-define-offsets-for-kdump.patch
Patch329: xen-scheduler-auto-privdom-weight.patch
Patch330: xen-hvm-disable-tsc-ramping.patch
Patch331: xen-default-cpufreq-governor-to-performance-on-intel.patch
Patch332: 0001-Partially-revert-08754333892-hvmloader-limit-CPUs-ex.patch
Patch333: 0001-x86-pv-silently-discard-writes-into-MSR_AMD64_LS_CFG.patch
Patch334: i8259-timers-pick-online-vcpu.patch
Patch335: revert-ca2eee92df44.patch
Patch336: libxc-stubs-hvm_check_pvdriver.patch
Patch337: libxc-cpuid-cores_per_socket.patch
Patch338: pygrub-add-default-and-extra-args.patch
Patch339: pygrub-always-boot-default.patch
Patch340: pygrub-friendly-no-fs.patch
Patch341: pygrub-image-max-size.patch
Patch342: pygrub-default-xenmobile-kernel.patch
Patch343: pygrub-blacklist-support.patch
Patch344: oem-bios-xensource.patch
Patch345: oem-bios-magic-from-xenstore.patch
Patch346: misc-log-guest-consoles.patch
Patch347: fix-ocaml-libs.patch
Patch348: retrofit-max-featuresets.patch
Patch349: xentop-vbd3.patch
Patch350: mixed-domain-runstates.patch
Patch351: xenguest.patch
Patch352: xen-vmdebug.patch
Patch353: oxenstore-extra-debug.patch
Patch354: oxenstore-censor-sensitive-data.patch
Patch355: oxenstore-large-packets.patch
Patch356: nvidia-vga.patch
Patch357: hvmloader-disable-pci-option-rom-loading.patch
Patch358: xen-force-software-vmcs-shadow.patch
Patch359: 0001-x86-vvmx-add-initial-PV-EPT-support-in-L0.patch
Patch360: use-msr-ll-instead-of-vmcs-efer.patch
Patch361: add-pv-iommu-headers.patch
Patch362: add-pv-iommu-local-domain-ops.patch
Patch363: add-pv-iommu-foreign-support.patch
Patch364: upstream-pv-iommu-tools.patch
Patch365: allow-rombios-pci-config-on-any-host-bridge.patch
Patch366: 0007-hypercall-XENMEM_get_mfn_from_pfn.patch
Patch367: gvt-g-hvmloader+rombios.patch
Patch368: xen-introduce-cmdline-to-control-introspection-extensions.patch
Patch369: xen-domctl-set-privileged-domain.patch
Patch370: xen-reexecute-instn-under-monitor-trap.patch
Patch371: revert-x86-mm-suppress-vm_events-caused-by-page-walks.patch
Patch372: xen-emulate-Bypass-the-emulator-if-emulation-fails.patch
Patch373: xen-introspection-pause.patch
Patch374: xen-always-enable-altp2m-external-mode.patch
Patch375: xen-spec-ctrl-utility.patch
Patch376: 0001-hvmloader-acpi-add-TPM-version-option.patch
Patch377: 0002-hvmloader-acpi-add-TPM2.patch
Patch378: vtpm-ppi-acpi-dsm.patch

ExclusiveArch: x86_64

## Pull in the correct RPM macros for the distributon
## (Any fedora which is still in support uses python3)
%if 0%{?centos} > 7 || 0%{?rhel} > 7 || 0%{?fedora} > 0
BuildRequires: python3-devel
BuildRequires: python3-rpm-macros
%global py_sitearch %{python3_sitearch}
%global __python %{__python3}
%else
BuildRequires: python2-devel
BuildRequires: python2-rpm-macros
%global py_sitearch %{python2_sitearch}
%global __python %{__python2}
%endif

BuildRequires: devtoolset-11-gcc devtoolset-11-binutils

# For HVMLoader and 16/32bit firmware
BuildRequires: dev86 iasl

# For the domain builder (decompression and hashing)
BuildRequires: zlib-devel bzip2-devel xz-devel
BuildRequires: openssl-devel

# For libxl
BuildRequires: yajl-devel libuuid-devel perl

# For ocaml stubs
BuildRequires: ocaml >= 4.13.1-3
BuildRequires: ocaml-findlib

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
This package contains the Xen Project Hypervisor.

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

%package lp-devel_%{version}_%{release}
License: GPLv2
Summary: Development package for building livepatches
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

source /opt/rh/devtoolset-11/enable
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

source /opt/rh/devtoolset-11/enable
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
%{_libdir}/libxendevicemodel.so.1.4
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

%files lp-devel_%{version}_%{release}
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
