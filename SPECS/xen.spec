%global package_speccommit 13adf241459dcc3cde9e7c6f19ec674286ab6592
%global usver 4.13.5
%global xsver 9.45
%global xsrel %{xsver}%{?xscount}%{?xshash}
# -*- rpm-spec -*-

# Commitish for Source0, required by tooling.
%global package_srccommit RELEASE-4.13.5

# Hypervisor release.  Should match the tag in the repository and would be in
# the Release field if it weren't for the %%{xsrel} automagic.
%global hv_rel 9.45

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
Patch57: backport-a8ee9c4d3fb8.patch
Patch58: backport-80a868f0f6cc.patch
Patch59: backport-a06d3feea3b7.patch
Patch60: backport-758fae24d7b9.patch
Patch61: backport-e373bc1bdc59.patch
Patch62: backport-b7c333016e3d.patch
Patch63: backport-1997d379dc64.patch
Patch64: backport-f7918dc8f94c.patch
Patch65: backport-935e5fb0d570.patch
Patch66: backport-29a6082f21f2.patch
Patch67: backport-7f97193e6aa8.patch
Patch68: backport-e663158bca89.patch
Patch69: backport-4387b4c771fe.patch
Patch70: backport-401c67e9bc8b.patch
Patch71: backport-00c48f57ab36.patch
Patch72: backport-42f0581a91d4.patch
Patch73: backport-5e115dcf76f6.patch
Patch74: backport-faf02c345ec0.patch
Patch75: backport-3068dfd6415a.patch
Patch76: backport-b1278939db0b.patch
Patch77: backport-7e5cffcd1e93.patch
Patch78: backport-81b2b328a26c.patch
Patch79: backport-60390ccb8b9b.patch
Patch80: backport-570da5423dbe.patch
Patch81: backport-0eae016b6e3d.patch
Patch82: backport-f40e1c52e4e0.patch
Patch83: backport-368096b9c4a2.patch
Patch84: backport-e21a6a4f966a.patch
Patch85: backport-935d501ccbf5.patch
Patch86: backport-27713fa2aa21.patch
Patch87: backport-3e9460ec9334.patch
Patch88: backport-e9b4fe263649.patch
Patch89: backport-fb23e8ba2304.patch
Patch90: backport-08693c03e00e.patch
Patch91: backport-95419adfd4b2.patch
Patch92: backport-f17d848c4caa-fix.patch
Patch93: backport-3670abcaf032.patch
Patch94: backport-9fdcf851689c.patch
Patch95: backport-2d1a35f1e6c2.patch
Patch96: backport-3e09045991cd.patch
Patch97: backport-b672695e7488.patch
Patch98: backport-79ca512a1fa6.patch
Patch99: backport-6a9f5477637a.patch
Patch100: backport-93c9edbef51b.patch
Patch101: backport-73c932d0ea43.patch
Patch102: backport-274c5e79c792.patch
Patch103: backport-1787cc167906.patch
Patch104: backport-afab477fba3b.patch
Patch105: backport-c76cfada1cfa.patch
Patch106: backport-f26bb285949b.patch
Patch107: backport-4624912c0b55.patch
Patch108: backport-2928c1d250b1.patch
Patch109: backport-6d45368a0a89.patch
Patch110: backport-0a7ebb186106.patch
Patch111: backport-b17546d7f33e.patch
Patch112: backport-164a0b9653f4.patch
Patch113: backport-737190abb174.patch
Patch114: backport-e083d753924b.patch
Patch115: backport-91bac8ad7c06.patch
Patch116: backport-dd6c062a7a4a.patch
Patch117: backport-9c3b9800e201.patch
Patch118: backport-b11380f6cd58.patch
Patch119: backport-b6b672e8a925.patch
Patch120: backport-834cb8761051.patch
Patch121: backport-eb7518b89be6.patch
Patch122: backport-f282182af329.patch
Patch123: backport-9cfeb83cbe23.patch
Patch124: backport-6809998c5f8f.patch
Patch125: backport-245a320ce227.patch
Patch126: backport-f03567bd7e8e.patch
Patch127: backport-c17072fc164a.patch
Patch128: backport-94c3df9188d6.patch
Patch129: backport-5bd2b82df28c.patch
Patch130: backport-31f3bc97f450.patch
Patch131: backport-b07050e1e8f7.patch
Patch132: backport-88d3ff7ab15d.patch
Patch133: backport-6536688439db.patch
Patch134: backport-81f0eaadf84d.patch
Patch135: backport-e3662437eb43.patch
Patch136: backport-e1828e3032eb.patch
Patch137: backport-969a57f73f6b.patch
Patch138: backport-15b7611efd49.patch
Patch139: backport-00f2992b6c7a.patch
Patch140: backport-614cec7d79d7.patch
Patch141: backport-22b9add22b4a.patch
Patch142: backport-a7e7c7260cde.patch
Patch143: backport-f97c1abf2934.patch
Patch144: backport-39a40f3835ef.patch
Patch145: backport-4116139131e9.patch
Patch146: backport-ad9f7c3b2e0d.patch
Patch147: backport-f3709b15fc86.patch
Patch148: backport-52ce1c97844d.patch
Patch149: backport-81d195c6c0e2.patch
Patch150: backport-f627a39c5e75.patch
Patch151: backport-6ba701064227.patch
Patch152: backport-7f7e55b85fce.patch
Patch153: backport-ea140035d01a.patch
Patch154: backport-e270af94280e.patch
Patch155: backport-ae49ee66cfda.patch
Patch156: backport-cea9ae062295.patch
Patch157: backport-d4012d50082c.patch
Patch158: backport-69e1472d21cf.patch
Patch159: backport-60d1adfa1879.patch
Patch160: backport-c16a9eda77b2.patch
Patch161: backport-e570e8d520ab.patch
Patch162: backport-a0aeab27ee0e.patch
Patch163: backport-e83cd54611fe.patch
Patch164: backport-b874e47eb13f.patch
Patch165: backport-0f2611c52438.patch
Patch166: backport-c3bd0b83ea5b.patch
Patch167: backport-c4e5cc2ccc5b.patch
Patch168: backport-7110192b1df6.patch
Patch169: backport-f838b956779f.patch
Patch170: backport-9272225ca728.patch
Patch171: backport-a0bfdd201ea1.patch
Patch172: backport-1d7fbc535d1d.patch
Patch173: backport-37f82facd62f.patch
Patch174: backport-57f07cca8252.patch
Patch175: backport-c3b6be714c64.patch
Patch176: backport-95db09b1b154.patch
Patch177: backport-ee36179371fd.patch
Patch178: backport-22d5affdf0ce.patch
Patch179: backport-7ba68a6c558e.patch
Patch180: backport-9bafe4a53306.patch
Patch181: backport-b45bfaf359e4.patch
Patch182: backport-9804a5db435f.patch
Patch183: backport-31fbee749a75.patch
Patch184: backport-aecdc28d9538.patch
Patch185: backport-df2db174b36e.patch
Patch186: backport-9b224c25293a.patch
Patch187: backport-3f02e0a70fe9.patch
Patch188: backport-ee7815f49faf.patch
Patch189: backport-acd3fb6d6590.patch
Patch190: backport-f1d7aac1e3c3.patch
Patch191: backport-e267d11969a4.patch
Patch192: backport-831419f82913.patch
Patch193: backport-d2162d884cba.patch
Patch194: backport-ff95dae53e5e.patch
Patch195: backport-10acd21795a9.patch
Patch196: backport-f5d0279839b5.patch
Patch197: backport-a44734df6c24.patch
Patch198: backport-f7d07619d2ae.patch
Patch199: backport-d329b37d1213.patch
Patch200: backport-573279cde1c4.patch
Patch201: backport-ad15a0a8ca25.patch
Patch202: backport-4e0b4ccfc504.patch
Patch203: backport-e94af0d58f86.patch
Patch204: backport-3edca52ce736.patch
Patch205: backport-5f08bc9404c7.patch
Patch206: backport-e6f07052ce4a.patch
Patch207: backport-ff8b560be80b.patch
Patch208: backport-36eb2de31b6e.patch
Patch209: backport-2636d8ff7a67.patch
Patch210: backport-425068384210.patch
Patch211: backport-9e7c74e6f9fd.patch
Patch212: backport-d69ccf52ad46.patch
Patch213: backport-b4a23bf6293a.patch
Patch214: backport-eddf13b5e940.patch
Patch215: backport-63305e5392ec.patch
Patch216: backport-f4ef8a41b808.patch
Patch217: backport-f1315e48a03a.patch
Patch218: backport-1ba66a870eba.patch
Patch219: backport-9276e832aef6.patch
Patch220: backport-d04ae78c34e7.patch
Patch221: backport-4a5577940240.patch
Patch222: backport-ec3474e1dd42.patch
Patch223: backport-433d012c6c27-partial.patch
Patch224: backport-33fb3a661223.patch
Patch225: backport-d484dcca7972.patch
Patch226: backport-ab2d47eb1353.patch
Patch227: backport-245d030f4aa7.patch
Patch228: backport-fc2e1f3aad60.patch
Patch229: backport-c2ec94c370f2.patch
Patch230: backport-21e3ef57e040.patch
Patch231: backport-743e530380a0.patch
Patch232: backport-03812da3754d.patch
Patch233: backport-6bc33366795d.patch
Patch234: backport-bd13dae34809.patch
Patch235: backport-c9985233ca66.patch
Patch236: backport-66c5c9965631.patch
Patch237: backport-1027df4c0082.patch
Patch238: backport-4f20f596ce9b.patch
Patch239: backport-8eb56eb959a5.patch
Patch240: backport-441b1b2a50ea.patch
Patch241: backport-a16dcd48c2db.patch
Patch242: backport-1b67fccf3b02.patch
Patch243: backport-994c1553a158.patch
Patch244: backport-19c6cbd90965.patch
Patch245: backport-0946068e7fae.patch
Patch246: backport-eaa324bfebcf.patch
Patch247: backport-f1e574fa6dea.patch
Patch248: backport-161c37d020a7.patch
Patch249: backport-b95a72bb5b2d.patch
Patch250: backport-8b1ac353b4db.patch
Patch251: backport-694d79ed5aac.patch
Patch252: backport-4c507d8a6b6e.patch
Patch253: backport-56e2c8e58600.patch
Patch254: backport-ef1987fcb0fd.patch
Patch255: backport-43912f8dbb18.patch
Patch256: backport-d9fe459ffad8.patch
Patch257: backport-ce8c930851a5.patch
Patch258: backport-70553000d6b4.patch
Patch259: backport-bbb289f3d5bd.patch
Patch260: backport-8f6bc7f9b72e.patch
Patch261: backport-205a9f970378.patch
Patch262: backport-511b9f286c3d.patch
Patch263: backport-94200e1bae07.patch
Patch264: backport-921afcbae843.patch
Patch265: backport-724c0d94ff79.patch
Patch266: backport-36525a964fb6.patch
Patch267: backport-e0586a4ff514.patch
Patch268: backport-aab4b38b5d77.patch
Patch269: backport-c81b287e00b1.patch
Patch270: backport-813da5f0e73b.patch
Patch271: backport-f91c5ea97067.patch
Patch272: backport-4b2cdbfe766e.patch
Patch273: backport-cdc48cb5a74b.patch
Patch274: backport-ef7995ed1bcd.patch
Patch275: backport-a478b38c01b6.patch
Patch276: backport-f7065b24f4fb.patch
Patch277: backport-c0dd53b8cbd1.patch
Patch278: backport-3e033172b025.patch
Patch279: backport-292f68fb7719.patch
Patch280: backport-2280b0ee2aed.patch
Patch281: backport-220c06e6fefe.patch
Patch282: backport-2dd06b4ea108.patch
Patch283: backport-9f585f59d90c.patch
Patch284: backport-56d690efd3ca.patch
Patch285: backport-145a69c0944a.patch
Patch286: backport-0742b0a081c2.patch
Patch287: backport-47342d8f490c.patch
Patch288: backport-8c01f267eff3.patch
Patch289: backport-709f6c8ce642.patch
Patch290: backport-1c18d7377453.patch
Patch291: backport-694bb0f280fd.patch
Patch292: backport-7125429aafb9.patch
Patch293: backport-45f00557350d.patch
Patch294: backport-7aa28849a115.patch
Patch295: backport-21bdc25b05a0.patch
Patch296: backport-3ee6066bcd73.patch
Patch297: backport-de1d26500139.patch
Patch298: backport-b5926c6ecf05.patch
Patch299: backport-fb0ff49fe9f7.patch
Patch300: backport-e71157d1ac2a.patch
Patch301: backport-c4e05c97f57d.patch
Patch302: backport-5fc98b97084a.patch
Patch303: backport-37fc1e6c1c5c.patch
Patch304: backport-ddc45e4eea94.patch
Patch305: backport-620500dd1baf.patch
Patch306: backport-7d85c7043159.patch
Patch307: backport-f4b504c6170c.patch
Patch308: backport-9f2ff9a7c9b3.patch
Patch309: backport-0710d7d44586.patch
Patch310: backport-990e65c3ad9a.patch
Patch311: backport-e0342ae5556f.patch
Patch312: backport-1f762642d2ca.patch
Patch313: backport-9c114178ffd7.patch
Patch314: backport-5d54282f984b.patch
Patch315: backport-dc9d9aa62dde.patch
Patch316: backport-26ea12d940b4.patch
Patch317: backport-bad1ac345b19.patch
Patch318: backport-fe1e4668b373.patch
Patch319: backport-a48bb129f1b9.patch
Patch320: backport-cb4ecb3cc17b.patch
Patch321: backport-4dd676070684.patch
Patch322: backport-478e4787fa64.patch
Patch323: backport-583f1d095052.patch
Patch324: backport-878159bf259b.patch
Patch325: backport-37541208f119.patch
Patch326: backport-475fa20b7384.patch
Patch327: backport-0a666cf2cd99.patch
Patch328: backport-f7603ca252e4.patch
Patch329: backport-1eb91a8a0623.patch
Patch330: backport-fb5b6f674471.patch
Patch331: backport-c4f427ec879e.patch
Patch332: backport-7ef0084418e1.patch
Patch333: backport-a1fb15f61692.patch
Patch334: backport-f218daf6d3a3.patch
Patch335: backport-197ecd838a2a.patch
Patch336: backport-42a572a38e22.patch
Patch337: backport-03cf7ca23e0e.patch
Patch338: backport-62018f08708a.patch
Patch339: backport-b33f191e3ca9.patch
Patch340: backport-6a98383b0877.patch
Patch341: backport-9926e692c4af.patch
Patch342: backport-489d93cd0fdd.patch
Patch343: backport-c62673c4334b.patch
Patch344: backport-94896de1a98c.patch
Patch345: backport-22390697bf1b.patch
Patch346: backport-9607aeb6602b.patch
Patch347: backport-2378d16a931d.patch
Patch348: backport-40dea83b7538.patch
Patch349: backport-97c5b8b657e4.patch
Patch350: backport-45dac88e78e8.patch
Patch351: backport-8e186f98ce0e.patch
Patch352: backport-0b66d7ce3c02.patch
Patch353: backport-62a1106415c5.patch
Patch354: backport-954c983abcee.patch
Patch355: backport-689ad48ce9cf.patch
Patch356: backport-d5887c0decbd.patch
Patch357: backport-43a07069863b.patch
Patch358: backport-abd00b037da5.patch
Patch359: backport-594b22ca5be6.patch
Patch360: backport-fa4d026737a4.patch
Patch361: backport-57338346f29c.patch
Patch362: backport-beadd68b5490.patch
Patch363: backport-c42d9ec61f6d.patch
Patch364: backport-b9bf85b5fd91.patch
Patch365: backport-86001b3970fe.patch
Patch366: xsa463-4.13-01.patch
Patch367: xsa463-4.13-02.patch
Patch368: xsa463-4.13-03.patch
Patch369: xsa463-4.13-04.patch
Patch370: xsa463-4.13-05.patch
Patch371: xsa463-4.13-06.patch
Patch372: xsa463-4.13-07.patch
Patch373: xsa463-4.13-08.patch
Patch374: xsa463-4.13-09.patch
Patch375: xsa463-4.13-10.patch
Patch376: xsa464.patch
Patch377: 0001-x86-AMD-make-HT-range-dynamic-for-Fam17-and-up.patch
Patch378: 0001-tools-Fix-pkg-config-file-for-libxenstore.patch
Patch379: 0006-x86-vpt-fix-injection-to-remote-vCPU.patch
Patch380: detect-nehalem-c-state.patch
Patch381: quirk-hp-gen8-rmrr.patch
Patch382: quirk-pci-phantom-function-devices.patch
Patch383: 0001-x86-hpet-Pre-cleanup.patch
Patch384: 0002-x86-hpet-Use-singe-apic-vector-rather-than-irq_descs.patch
Patch385: 0003-x86-hpet-Post-cleanup.patch
Patch386: 0002-libxc-retry-shadow-ops-if-EBUSY-is-returned.patch
Patch387: avoid-gnt-unmap-tlb-flush-if-not-accessed.patch
Patch388: 0002-efi-Ensure-incorrectly-typed-runtime-services-get-ma.patch
Patch389: 0001-x86-time-Don-t-use-EFI-s-GetTime-call.patch
Patch390: 0001-efi-Workaround-page-fault-during-runtime-service.patch
Patch391: 0001-x86-HVM-Avoid-cache-flush-operations-during-hvm_load.patch
Patch392: 0001-libxl-Don-t-insert-PCI-device-into-xenstore-for-HVM-.patch
Patch393: 0001-x86-PoD-Command-line-option-to-prohibit-any-PoD-oper.patch
Patch394: livepatch-ignore-duplicate-new.patch
Patch395: 0001-lib-Add-a-generic-implementation-of-current_text_add.patch
Patch396: 0002-sched-Remove-dependency-on-__LINE__-for-release-buil.patch
Patch397: pygrub-Ignore-GRUB2-if-statements.patch
Patch398: libfsimage-Add-support-for-btrfs.patch
Patch399: quiet-broke-irq-affinity.patch
Patch400: 0001-x86-msr-Blacklist-various-MSRs-which-guests-definite.patch
Patch401: 0001-Hide-AVX-512-from-guests-by-default.patch
Patch402: 0001-common-page_alloc-don-t-idle-scrub-before-microcode-.patch
Patch403: 0001-xsm-hide-detailed-Xen-version-from-unprivileged-gues.patch
Patch404: 0003-credit-Limit-load-balancing-to-once-per-millisecond.patch
Patch405: xen-tweak-cmdline-defaults.patch
Patch406: xen-tweak-debug-overhead.patch
Patch407: tweak-iommu-policy.patch
Patch408: tweak-sc-policy.patch
Patch409: disable-core-parking.patch
Patch410: 0001-Allocate-space-in-structs-pre-emptively-to-increase-.patch
Patch411: 0001-x86-mm-partially-revert-37201c62-make-logdirty-and-i.patch
Patch412: hitachi-driver-domain-ssid.patch
Patch413: livepatch-payload-in-header.patch
Patch414: xen-define-offsets-for-kdump.patch
Patch415: xen-scheduler-auto-privdom-weight.patch
Patch416: xen-hvm-disable-tsc-ramping.patch
Patch417: xen-default-cpufreq-governor-to-performance-on-intel.patch
Patch418: 0001-Partially-revert-08754333892-hvmloader-limit-CPUs-ex.patch
Patch419: 0001-x86-pv-silently-discard-writes-into-MSR_AMD64_LS_CFG.patch
Patch420: i8259-timers-pick-online-vcpu.patch
Patch421: revert-ca2eee92df44.patch
Patch422: libxc-stubs-hvm_check_pvdriver.patch
Patch423: libxc-cpuid-cores_per_socket.patch
Patch424: libxc-cpu-simple-or.patch
Patch425: libxc-cpu-clear-deps.patch
Patch426: libxc-cpu-policies.patch
Patch427: max-featureset-compat.patch
Patch428: pygrub-add-disk-as-extra-group.patch
Patch429: pygrub-add-default-and-extra-args.patch
Patch430: pygrub-always-boot-default.patch
Patch431: pygrub-friendly-no-fs.patch
Patch432: pygrub-default-xenmobile-kernel.patch
Patch433: pygrub-blacklist-support.patch
Patch434: ucode-compat.patch
Patch435: oem-bios-xensource.patch
Patch436: oem-bios-magic-from-xenstore.patch
Patch437: misc-log-guest-consoles.patch
Patch438: fix-ocaml-libs.patch
Patch439: ocaml-cpuid-helpers.patch
Patch440: xentop-vbd3.patch
Patch441: mixed-domain-runstates.patch
Patch442: xenguest.patch
Patch443: xen-vmdebug.patch
Patch444: oxenstore-censor-sensitive-data.patch
Patch445: oxenstore-large-packets.patch
Patch446: nvidia-vga.patch
Patch447: hvmloader-disable-pci-option-rom-loading.patch
Patch448: xen-force-software-vmcs-shadow.patch
Patch449: 0001-x86-vvmx-add-initial-PV-EPT-support-in-L0.patch
Patch450: use-msr-ll-instead-of-vmcs-efer.patch
Patch451: add-pv-iommu-headers.patch
Patch452: add-pv-iommu-local-domain-ops.patch
Patch453: add-pv-iommu-foreign-support.patch
Patch454: upstream-pv-iommu-tools.patch
Patch455: allow-rombios-pci-config-on-any-host-bridge.patch
Patch456: 0007-hypercall-XENMEM_get_mfn_from_pfn.patch
Patch457: gvt-g-hvmloader+rombios.patch
Patch458: xen-introduce-cmdline-to-control-introspection-extensions.patch
Patch459: xen-domctl-set-privileged-domain.patch
Patch460: xen-reexecute-instn-under-monitor-trap.patch
Patch461: revert-x86-mm-suppress-vm_events-caused-by-page-walks.patch
Patch462: xen-emulate-Bypass-the-emulator-if-emulation-fails.patch
Patch463: xen-introspection-pause.patch
Patch464: xen-always-enable-altp2m-external-mode.patch
Patch465: xen-spec-ctrl-utility.patch

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
* Tue Nov 05 2024 Javi Merino <javi.merino@cloud.com> - 4.13.5-9.45
- Fixes for XSA-463 CVE-2024-45818
- Fixes for XSA-464 CVE-2024-45819
- Fix IO-APIC directed EOIs when using AMD-Vi interrupt remapping
- Remove an overly strict check when parsing AMD IVRS ACPI tables

* Thu Sep 19 2024 Alex Brett <alex.brett@cloud.com> - 4.13.5-9.44
- Fix a packaging issue affecting livepatching

* Thu Sep 12 2024 Roger Pau Monné <roger.pau@citrix.com> - 4.13.5-9.43
- Fix for XSA-462 / CVE-2024-45817.

* Thu Sep 05 2024 Alejandro Vallejo <alejandro.vallejo@cloud.com> - 4.13.5-9.42
- Fix for XSA-460 / CVE-2024-31145.

* Thu Jul 11 2024 Roger Pau Monné <roger.pau@citrix.com> - 4.13.5-9.41
- Fixes for XSA-458 CVE-2024-31143.
- Fix early detection of CPU features on hardware with the CPUID Limit active
  in firmware.
- Fix RTC emulation.

* Mon Apr  8 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-9.40
- Fixes for:
  - XSA-454 CVE-2023-46842
  - XSA-455 CVE-2024-31142
  - XSA-456 CVE-2024-2201

* Fri Mar  8 2024 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-9.39
- Fixes for:
  - XSA-449 CVE-2023-46839
  - XSA-453 CVE-2024-2193, off by default
  - XSA-452 CVE-2023-28746

* Mon Nov 6 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-9.38
- Fixes for
  - XSA-445 CVE-2023-46835
  - XSA-446 CVE-2023-46836
- Fix for AMD erratum #1485, which has been observed to cause #UD exception on
  AMD Zen4 systems.

* Wed Oct 4 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-9.37
- Fixes for
  - XSA-438 CVE-2023-34322
  - XSA-439 CVE-2023-20588
  - XSA-440 CVE-2023-34323
  - XSA-442 CVE-2023-34326
  - XSA-443 CVE-2023-34325
  - XSA-444 CVE-2023-34327 CVE-2023-34328
- Pygrub extended to deprivilege itself before operating on guest disks.
- Ignore MADT entries with invalid APIC_IDs.
- Fix the emulation of VPBLENDMW with a mask and memory operand.
- Fix a incorrect diagnostic about spurious interrupts.
- Update IO-APIC IRTEs atomically.  Fixes a race condition which causes
  interrupts to be routed badly, often with "No irq handler for vector"
  errors.
- Further fix for XSA-433.  Extend the chicken-bit workaround to all CPUs
  which appear to be a Zen2 microarchtiecture, even those not on the published
  model list.
- Fix for AMD errata #1474.  Disable C6 after 1000 days of uptime on AMD Zen2
  systems to avoid a crash at ~1044 days.
- Fix for MSR_ARCH_CAPS boot-time calculations for PV guests.

* Thu Aug 3 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-9.36
- Fixes for
  - XSA-434 CVE-2023-20569
  - XSA-435 CVE-2022-40982
- Expose MSR_ARCH_CAPS to guests on all Intel hardware by default.  On Cascade
  Lake and later hardware, guests now see the bits stating hardware immunity
  to various speculative vulnerabilities.

* Tue Aug 1 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-9.35
- Fix bug in XSA-433 fix, which accidentally disabled a hardware errata
  workaround.

* Sat Jul 22 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-9.34
- Fix for XSA-433 CVE-2023-20593.

* Tue Jul 4 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-9.33
- Hide MPX by default from guests.  This simplifies cross-pool upgrade
  scenarios.
- Limit scheduler loadbalancing to once per millisecond.  This improves
  performance on large systems.

* Tue May 16 2023 Roger Pau Monné <roger.pau@citrix.com> - 4.13.5-9.32
- Mitigate performance degradation with logdirty by disabling
  VCPU_SSHOTTMR_future.
- Adjust bogus assert in AMD-Vi code.
- Early boot improvements.

* Mon Apr 17 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-9.31
- Remove the NR_IOMMUs compile time limit.  This is necessary to boot on
  4-socket Sapphire Rapids systems.
- Cope booting in x2APIC mode on AMD systems without XT mode.
- Load AMD microcode on all logical processors.
- Fixes for
  - XSA-427 CVE-2022-42332
  - XSA-428 CVE-2022-42333 CVE-2022-42334
  - XSA-429 CVE-2022-42331
- Increase the size of the serial transmit buffer.

* Mon Feb 6 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-9.30
- Fix for XSA-426 CVE-2022-27672.
- Fix memory corruption issues in the Ocaml bindings.
- On xenstored live update, validate the config file before launching
  into the new xenstored.

* Mon Feb 6 2023 Andrew Cooper <andrew.cooper3@citrix.com> - 4.13.5-9.29
- Update to Xen 4.13.5
