%global package_speccommit 8e58b4872724eaca580e89a371acf4fffc15ec9f
%global usver 4.13.5
%global xsver 10.58
%global xsrel %{xsver}%{?xscount}%{?xshash}
# -*- rpm-spec -*-

# Commitish for Source0, required by tooling.
%global package_srccommit RELEASE-4.13.5

# Hypervisor release.  Should match the tag in the repository and would be in
# the Release field if it weren't for the %%{xsrel} automagic.
%global hv_rel 10.58

# Full hash from the HEAD commit of this repo during processing, usually
# provided by the environment.  Default to ??? if not set.

# Normally derived from the tag and provided by the environment.  May be a
# `git describe` when not building an from a tagged changeset.

%define with_sysv 0
%define with_systemd 1

%define base_dir  %{name}-%{version}

%define lp_devel_dir %{_usrsrc}/xen-%{version}-%{release}

# Prevent RPM adding Provides/Requires to lp-devel package, or mangling shebangs
%global __provides_exclude_from ^%{lp_devel_dir}/.*$
%global __requires_exclude_from ^%{lp_devel_dir}/.*$
%global __brp_mangle_shebangs_exclude_from ^%{lp_devel_dir}/.*$

Summary: Xen is a virtual machine monitor
Name:    xen
Version: 4.13.5
Release: %{?xsrel}%{?dist}
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
Patch10: backport-1430c5a8cad4.patch
Patch11: backport-9356f9de4162.patch
Patch12: backport-c08cbf7fb891.patch
Patch13: backport-3d05407025ed.patch
Patch14: backport-b1710040ca96.patch
Patch15: backport-31bf4f26aa17.patch
Patch16: backport-e9bd648015dd.patch
Patch17: backport-da9290639eb5.patch
Patch18: backport-7b3c5b70a323.patch
Patch19: backport-1171a93b6ca7.patch
Patch20: backport-2004db3ced18.patch
Patch21: backport-59e1f6d89710.patch
Patch22: backport-86cf92f50533.patch
Patch23: backport-0a9c44486b90.patch
Patch24: backport-270ff9a835fb.patch
Patch25: backport-dacb80f9757c.patch
Patch26: backport-1b3cec69bf30.patch
Patch27: backport-8171e0796542.patch
Patch28: backport-6094a3c4fee1.patch
Patch29: backport-96dc77b4b182.patch
Patch30: backport-dca31274846c.patch
Patch31: backport-625a95cc17d5.patch
Patch32: backport-fd0ec12c3a41.patch
Patch33: backport-885d2d20425d.patch
Patch34: backport-9649cef3b3a7.patch
Patch35: backport-a798bac54fe8.patch
Patch36: backport-920d5f31883c.patch
Patch37: backport-c9495bd7dff5.patch
Patch38: backport-53ddfc80a84a.patch
Patch39: backport-a9b6dacf88fe.patch
Patch40: backport-7ff66809ccd5.patch
Patch41: backport-53594c7bd197.patch
Patch42: backport-540d4d60378c.patch
Patch43: backport-3174835ba825.patch
Patch44: backport-c2b4e23fdda4.patch
Patch45: backport-e9aca9470ed8.patch
Patch46: backport-68d757df8dd2.patch
Patch47: backport-17b997aa1edb.patch
Patch48: backport-35b819c45c46.patch
Patch49: backport-d8a6a8b36d86.patch
Patch50: backport-78f81c6870de.patch
Patch51: backport-271ade5a6210.patch
Patch52: backport-ba7b169c9f09.patch
Patch53: backport-54463aa79dac.patch
Patch54: backport-25636ed707cf.patch
Patch55: backport-4489ffdec331.patch
Patch56: backport-ab5bfc049e8e.patch
Patch57: backport-dc036ab9d506.patch
Patch58: backport-b9e9ccbb11e4.patch
Patch59: backport-b6641f28c593.patch
Patch60: backport-a85f67b2658e.patch
Patch61: backport-a8ee9c4d3fb8.patch
Patch62: backport-80a868f0f6cc.patch
Patch63: backport-a06d3feea3b7.patch
Patch64: backport-e006b2e3be72.patch
Patch65: backport-758fae24d7b9.patch
Patch66: backport-e373bc1bdc59.patch
Patch67: backport-b7c333016e3d.patch
Patch68: backport-01d411fd2d2e.patch
Patch69: backport-1997d379dc64.patch
Patch70: backport-f7918dc8f94c.patch
Patch71: backport-935e5fb0d570.patch
Patch72: backport-29a6082f21f2.patch
Patch73: backport-7f97193e6aa8.patch
Patch74: backport-e663158bca89.patch
Patch75: backport-4387b4c771fe.patch
Patch76: backport-401c67e9bc8b.patch
Patch77: backport-00c48f57ab36.patch
Patch78: backport-42f0581a91d4.patch
Patch79: backport-5e115dcf76f6.patch
Patch80: backport-faf02c345ec0.patch
Patch81: backport-3068dfd6415a.patch
Patch82: backport-b1278939db0b.patch
Patch83: backport-7e5cffcd1e93.patch
Patch84: backport-5d752df85f2c.patch
Patch85: backport-e8af54084586.patch
Patch86: backport-81b2b328a26c.patch
Patch87: backport-60390ccb8b9b.patch
Patch88: backport-c4441ab1f1d5.patch
Patch89: backport-570da5423dbe.patch
Patch90: backport-0eae016b6e3d.patch
Patch91: backport-6b0ac9a4e239.patch
Patch92: backport-f40e1c52e4e0.patch
Patch93: backport-368096b9c4a2.patch
Patch94: backport-e21a6a4f966a.patch
Patch95: backport-935d501ccbf5.patch
Patch96: backport-27713fa2aa21.patch
Patch97: backport-3e9460ec9334.patch
Patch98: backport-e9b4fe263649.patch
Patch99: backport-fb23e8ba2304.patch
Patch100: backport-08693c03e00e.patch
Patch101: backport-95419adfd4b2.patch
Patch102: backport-f17d848c4caa-fix.patch
Patch103: backport-3670abcaf032.patch
Patch104: backport-9fdcf851689c.patch
Patch105: backport-2d1a35f1e6c2.patch
Patch106: backport-3e09045991cd.patch
Patch107: backport-b672695e7488.patch
Patch108: backport-74d044d51b19.patch
Patch109: backport-c8f88810db2a.patch
Patch110: backport-a27976a1080d.patch
Patch111: backport-79ca512a1fa6.patch
Patch112: backport-6a9f5477637a.patch
Patch113: backport-93c9edbef51b.patch
Patch114: backport-73c932d0ea43.patch
Patch115: backport-274c5e79c792.patch
Patch116: backport-1787cc167906.patch
Patch117: backport-afab477fba3b.patch
Patch118: backport-c76cfada1cfa.patch
Patch119: backport-f26bb285949b.patch
Patch120: backport-4624912c0b55.patch
Patch121: backport-2928c1d250b1.patch
Patch122: backport-6d45368a0a89.patch
Patch123: backport-0a7ebb186106.patch
Patch124: backport-b17546d7f33e.patch
Patch125: backport-164a0b9653f4.patch
Patch126: backport-737190abb174.patch
Patch127: backport-e083d753924b.patch
Patch128: backport-91bac8ad7c06.patch
Patch129: backport-dd6c062a7a4a.patch
Patch130: backport-9c3b9800e201.patch
Patch131: backport-b11380f6cd58.patch
Patch132: backport-b6b672e8a925.patch
Patch133: backport-834cb8761051.patch
Patch134: backport-eb7518b89be6.patch
Patch135: backport-f282182af329.patch
Patch136: backport-9cfeb83cbe23.patch
Patch137: backport-6809998c5f8f.patch
Patch138: backport-56829b6ff985.patch
Patch139: backport-245a320ce227.patch
Patch140: backport-5a8b28bfd431.patch
Patch141: backport-c17072fc164a.patch
Patch142: backport-94c3df9188d6.patch
Patch143: backport-5bd2b82df28c.patch
Patch144: backport-31f3bc97f450.patch
Patch145: backport-b07050e1e8f7.patch
Patch146: backport-88d3ff7ab15d.patch
Patch147: backport-6536688439db.patch
Patch148: backport-81f0eaadf84d.patch
Patch149: backport-2d5fc9120d55.patch
Patch150: backport-e3662437eb43.patch
Patch151: backport-e1828e3032eb.patch
Patch152: backport-969a57f73f6b.patch
Patch153: backport-15b7611efd49.patch
Patch154: backport-00f2992b6c7a.patch
Patch155: backport-614cec7d79d7.patch
Patch156: backport-22b9add22b4a.patch
Patch157: backport-a7e7c7260cde.patch
Patch158: backport-f97c1abf2934.patch
Patch159: backport-39a40f3835ef.patch
Patch160: backport-4116139131e9.patch
Patch161: backport-ad9f7c3b2e0d.patch
Patch162: backport-f3709b15fc86.patch
Patch163: backport-52ce1c97844d.patch
Patch164: backport-81d195c6c0e2.patch
Patch165: backport-f627a39c5e75.patch
Patch166: backport-6ba701064227.patch
Patch167: backport-7f7e55b85fce.patch
Patch168: backport-ea140035d01a.patch
Patch169: backport-e270af94280e.patch
Patch170: backport-ae49ee66cfda.patch
Patch171: backport-cea9ae062295.patch
Patch172: backport-d4012d50082c.patch
Patch173: backport-69e1472d21cf.patch
Patch174: backport-80ad8db8a4d9.patch
Patch175: backport-60d1adfa1879.patch
Patch176: backport-9723507daf21.patch
Patch177: backport-e570e8d520ab.patch
Patch178: backport-a0aeab27ee0e.patch
Patch179: backport-e83cd54611fe.patch
Patch180: backport-b874e47eb13f.patch
Patch181: backport-0f2611c52438.patch
Patch182: backport-c3bd0b83ea5b.patch
Patch183: backport-c4e5cc2ccc5b.patch
Patch184: backport-7110192b1df6.patch
Patch185: backport-f838b956779f.patch
Patch186: backport-9272225ca728.patch
Patch187: backport-a0bfdd201ea1.patch
Patch188: backport-1d7fbc535d1d.patch
Patch189: backport-37f82facd62f.patch
Patch190: backport-57f07cca8252.patch
Patch191: backport-c3b6be714c64.patch
Patch192: backport-95db09b1b154.patch
Patch193: backport-ee36179371fd.patch
Patch194: backport-22d5affdf0ce.patch
Patch195: backport-7ba68a6c558e.patch
Patch196: backport-9bafe4a53306.patch
Patch197: backport-b45bfaf359e4.patch
Patch198: backport-9804a5db435f.patch
Patch199: backport-31fbee749a75.patch
Patch200: backport-aecdc28d9538.patch
Patch201: backport-df2db174b36e.patch
Patch202: backport-9b224c25293a.patch
Patch203: backport-3f02e0a70fe9.patch
Patch204: backport-ee7815f49faf.patch
Patch205: backport-acd3fb6d6590.patch
Patch206: backport-f1d7aac1e3c3.patch
Patch207: backport-e267d11969a4.patch
Patch208: backport-831419f82913.patch
Patch209: backport-d2162d884cba.patch
Patch210: backport-ff95dae53e5e.patch
Patch211: backport-10acd21795a9.patch
Patch212: backport-f5d0279839b5.patch
Patch213: backport-a44734df6c24.patch
Patch214: backport-f7d07619d2ae.patch
Patch215: backport-d329b37d1213.patch
Patch216: backport-573279cde1c4.patch
Patch217: backport-ad15a0a8ca25.patch
Patch218: backport-4e0b4ccfc504.patch
Patch219: backport-e94af0d58f86.patch
Patch220: backport-3edca52ce736.patch
Patch221: backport-5f08bc9404c7.patch
Patch222: backport-897257ba49d0.patch
Patch223: backport-e6f07052ce4a.patch
Patch224: backport-ff8b560be80b.patch
Patch225: backport-36eb2de31b6e.patch
Patch226: backport-2636d8ff7a67.patch
Patch227: backport-425068384210.patch
Patch228: backport-9e7c74e6f9fd.patch
Patch229: backport-d69ccf52ad46.patch
Patch230: backport-3a59443c1d5a.patch
Patch231: backport-b4a23bf6293a.patch
Patch232: backport-eddf13b5e940.patch
Patch233: backport-63305e5392ec.patch
Patch234: backport-f4ef8a41b808.patch
Patch235: backport-f1315e48a03a.patch
Patch236: backport-1ba66a870eba.patch
Patch237: backport-9276e832aef6.patch
Patch238: backport-d04ae78c34e7.patch
Patch239: backport-4a5577940240.patch
Patch240: backport-ec3474e1dd42.patch
Patch241: backport-433d012c6c27-partial.patch
Patch242: backport-b2ea81d2b935.patch
Patch243: backport-c82aff87f118.patch
Patch244: backport-9c0061825143.patch
Patch245: backport-33fb3a661223.patch
Patch246: backport-d484dcca7972.patch
Patch247: backport-ab2d47eb1353.patch
Patch248: backport-245d030f4aa7.patch
Patch249: backport-fc2e1f3aad60.patch
Patch250: backport-c2ec94c370f2.patch
Patch251: backport-21e3ef57e040.patch
Patch252: backport-743e530380a0.patch
Patch253: backport-03812da3754d.patch
Patch254: backport-6bc33366795d.patch
Patch255: backport-bd13dae34809.patch
Patch256: backport-c9985233ca66.patch
Patch257: backport-66c5c9965631.patch
Patch258: backport-1027df4c0082.patch
Patch259: backport-4f20f596ce9b.patch
Patch260: backport-8eb56eb959a5.patch
Patch261: backport-441b1b2a50ea.patch
Patch262: backport-a16dcd48c2db.patch
Patch263: backport-1b67fccf3b02.patch
Patch264: backport-994c1553a158.patch
Patch265: backport-19c6cbd90965.patch
Patch266: backport-0946068e7fae.patch
Patch267: backport-eaa324bfebcf.patch
Patch268: backport-f1e574fa6dea.patch
Patch269: backport-161c37d020a7.patch
Patch270: backport-b95a72bb5b2d.patch
Patch271: backport-5828b94b252c.patch
Patch272: backport-fb751d9a2431.patch
Patch273: backport-8b1ac353b4db.patch
Patch274: backport-694d79ed5aac.patch
Patch275: backport-4c507d8a6b6e.patch
Patch276: backport-56e2c8e58600.patch
Patch277: backport-ef1987fcb0fd.patch
Patch278: backport-43912f8dbb18.patch
Patch279: backport-d9fe459ffad8.patch
Patch280: backport-ce8c930851a5.patch
Patch281: backport-70553000d6b4.patch
Patch282: backport-bbb289f3d5bd.patch
Patch283: backport-8f6bc7f9b72e.patch
Patch284: backport-205a9f970378.patch
Patch285: backport-511b9f286c3d.patch
Patch286: backport-94200e1bae07.patch
Patch287: backport-921afcbae843.patch
Patch288: backport-724c0d94ff79.patch
Patch289: backport-36525a964fb6.patch
Patch290: backport-e0586a4ff514.patch
Patch291: backport-aab4b38b5d77.patch
Patch292: backport-c81b287e00b1.patch
Patch293: backport-813da5f0e73b.patch
Patch294: backport-f91c5ea97067.patch
Patch295: backport-4b2cdbfe766e.patch
Patch296: backport-cdc48cb5a74b.patch
Patch297: backport-ef7995ed1bcd.patch
Patch298: backport-a478b38c01b6.patch
Patch299: backport-f7065b24f4fb.patch
Patch300: backport-c0dd53b8cbd1.patch
Patch301: backport-0c594c1b57ee.patch
Patch302: backport-a07414d989cf.patch
Patch303: backport-3e033172b025.patch
Patch304: backport-292f68fb7719.patch
Patch305: backport-2280b0ee2aed.patch
Patch306: backport-220c06e6fefe.patch
Patch307: backport-2dd06b4ea108.patch
Patch308: backport-9f585f59d90c.patch
Patch309: backport-56d690efd3ca.patch
Patch310: backport-6fba45ca3be1.patch
Patch311: backport-e35138a2ffbe.patch
Patch312: backport-a562afa5679d.patch
Patch313: backport-5ddac3c2852e.patch
Patch314: backport-145a69c0944a.patch
Patch315: backport-0742b0a081c2.patch
Patch316: backport-47342d8f490c.patch
Patch317: backport-8c01f267eff3.patch
Patch318: backport-709f6c8ce642.patch
Patch319: backport-1c18d7377453.patch
Patch320: backport-694bb0f280fd.patch
Patch321: backport-7125429aafb9.patch
Patch322: backport-45f00557350d.patch
Patch323: backport-7aa28849a115.patch
Patch324: backport-21bdc25b05a0.patch
Patch325: backport-3ee6066bcd73.patch
Patch326: backport-de1d26500139.patch
Patch327: backport-b5926c6ecf05.patch
Patch328: backport-fb0ff49fe9f7.patch
Patch329: backport-c4e05c97f57d.patch
Patch330: backport-5fc98b97084a.patch
Patch331: backport-37fc1e6c1c5c.patch
Patch332: backport-ddc45e4eea94.patch
Patch333: backport-620500dd1baf.patch
Patch334: backport-7d85c7043159.patch
Patch335: backport-f4b504c6170c.patch
Patch336: backport-9f2ff9a7c9b3.patch
Patch337: backport-0710d7d44586.patch
Patch338: backport-990e65c3ad9a.patch
Patch339: backport-e0342ae5556f.patch
Patch340: backport-1f762642d2ca.patch
Patch341: backport-9c114178ffd7.patch
Patch342: backport-5d54282f984b.patch
Patch343: backport-dc9d9aa62dde.patch
Patch344: backport-26ea12d940b4.patch
Patch345: backport-40387f62061c.patch
Patch346: backport-4bb882fe6e44.patch
Patch347: backport-bad1ac345b19.patch
Patch348: backport-e3c409d59ac8.patch
Patch349: backport-fe1e4668b373.patch
Patch350: backport-a48bb129f1b9.patch
Patch351: 0001-x86-AMD-make-HT-range-dynamic-for-Fam17-and-up.patch
Patch352: 0001-tools-Fix-pkg-config-file-for-libxenstore.patch
Patch353: 0006-x86-vpt-fix-injection-to-remote-vCPU.patch
Patch354: detect-nehalem-c-state.patch
Patch355: quirk-hp-gen8-rmrr.patch
Patch356: quirk-pci-phantom-function-devices.patch
Patch357: 0001-x86-hpet-Pre-cleanup.patch
Patch358: 0002-x86-hpet-Use-singe-apic-vector-rather-than-irq_descs.patch
Patch359: 0003-x86-hpet-Post-cleanup.patch
Patch360: 0002-libxc-retry-shadow-ops-if-EBUSY-is-returned.patch
Patch361: avoid-gnt-unmap-tlb-flush-if-not-accessed.patch
Patch362: 0002-efi-Ensure-incorrectly-typed-runtime-services-get-ma.patch
Patch363: 0001-x86-time-Don-t-use-EFI-s-GetTime-call.patch
Patch364: 0001-efi-Workaround-page-fault-during-runtime-service.patch
Patch365: 0001-x86-HVM-Avoid-cache-flush-operations-during-hvm_load.patch
Patch366: 0001-libxl-Don-t-insert-PCI-device-into-xenstore-for-HVM-.patch
Patch367: livepatch-ignore-duplicate-new.patch
Patch368: 0001-lib-Add-a-generic-implementation-of-current_text_add.patch
Patch369: 0002-sched-Remove-dependency-on-__LINE__-for-release-buil.patch
Patch370: pygrub-Ignore-GRUB2-if-statements.patch
Patch371: libfsimage-Add-support-for-btrfs.patch
Patch372: quiet-broke-irq-affinity.patch
Patch373: 0001-x86-msr-Blacklist-various-MSRs-which-guests-definite.patch
Patch374: 0001-Hide-AVX-512-from-guests-by-default.patch
Patch375: 0001-common-page_alloc-don-t-idle-scrub-before-microcode-.patch
Patch376: 0003-credit-Limit-load-balancing-to-once-per-millisecond.patch
Patch377: xen-tweak-cmdline-defaults.patch
Patch378: xen-tweak-debug-overhead.patch
Patch379: tweak-iommu-policy.patch
Patch380: tweak-sc-policy.patch
Patch381: disable-core-parking.patch
Patch382: remove-info-leak.patch
Patch383: 0001-Allocate-space-in-structs-pre-emptively-to-increase-.patch
Patch384: 0001-x86-mm-partially-revert-37201c62-make-logdirty-and-i.patch
Patch385: hitachi-driver-domain-ssid.patch
Patch386: install_targets_for_test_x86_emulator.patch
Patch387: livepatch-payload-in-header.patch
Patch388: xen-define-offsets-for-kdump.patch
Patch389: xen-scheduler-auto-privdom-weight.patch
Patch390: xen-hvm-disable-tsc-ramping.patch
Patch391: xen-default-cpufreq-governor-to-performance-on-intel.patch
Patch392: 0001-x86-pv-silently-discard-writes-into-MSR_AMD64_LS_CFG.patch
Patch393: i8259-timers-pick-online-vcpu.patch
Patch394: revert-ca2eee92df44.patch
Patch395: libxc-cpuid-cores_per_socket.patch
Patch396: libxc-cpu-policies.patch
Patch397: max-featureset-compat.patch
Patch398: pygrub-add-disk-as-extra-group.patch
Patch399: pygrub-add-default-and-extra-args.patch
Patch400: pygrub-always-boot-default.patch
Patch401: pygrub-friendly-no-fs.patch
Patch402: pygrub-default-xenmobile-kernel.patch
Patch403: pygrub-blacklist-support.patch
Patch404: oem-bios-xensource.patch
Patch405: oem-bios-magic-from-xenstore.patch
Patch406: misc-log-guest-consoles.patch
Patch407: fix-ocaml-libs.patch
Patch408: xentop-vbd3.patch
Patch409: mixed-domain-runstates.patch
Patch410: xenguest.patch
Patch411: xen-vmdebug.patch
Patch412: oxenstore-censor-sensitive-data.patch
Patch413: oxenstore-large-packets.patch
Patch414: nvidia-vga.patch
Patch415: hvmloader-disable-pci-option-rom-loading.patch
Patch416: xen-force-software-vmcs-shadow.patch
Patch417: 0001-x86-vvmx-add-initial-PV-EPT-support-in-L0.patch
Patch418: use-msr-ll-instead-of-vmcs-efer.patch
Patch419: add-pv-iommu-headers.patch
Patch420: add-pv-iommu-local-domain-ops.patch
Patch421: add-pv-iommu-foreign-support.patch
Patch422: upstream-pv-iommu-tools.patch
Patch423: Add-PV-IOMMU-elf-note.patch
Patch424: allow-rombios-pci-config-on-any-host-bridge.patch
Patch425: gvt-g-hvmloader+rombios.patch
Patch426: xen-spec-ctrl-utility.patch
Patch427: vtpm-ppi-acpi-dsm.patch

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

    for _, dep in ipairs(deps) do
        print(rpm.expand("%1") .. ': ' .. dep .. '\\n')
    end
}

%if 0%{?xenserver} < 9
%global _devtoolset_enable source /opt/rh/devtoolset-11/enable
%endif

%{core_builddeps BuildRequires}

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

%files dom0-tests
%exclude %{_libexecdir}/%{name}/bin/depriv-fd-checker
%{_libexecdir}/%{name}/bin/test-cpu-policy
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
