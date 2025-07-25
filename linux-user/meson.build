if not have_linux_user
   subdir_done()
endif

linux_user_ss = ss.source_set()

common_user_inc += include_directories('include/host/' / host_arch)
common_user_inc += include_directories('include')

linux_user_ss.add(files(
  'elfload.c',
  'exit.c',
  'fd-trans.c',
  'linuxload.c',
  'main.c',
  'mmap.c',
  'signal.c',
  'strace.c',
  'syscall.c',
  'thunk.c',
  'uaccess.c',
  'uname.c',
))
linux_user_ss.add(rt)
linux_user_ss.add(libdw)

linux_user_ss.add(when: 'TARGET_HAS_BFLT', if_true: files('flatload.c'))
linux_user_ss.add(when: 'TARGET_I386', if_true: files('vm86.c'))
linux_user_ss.add(when: 'CONFIG_ARM_COMPATIBLE_SEMIHOSTING', if_true: files('semihost.c'))

if get_option('plugins')
  linux_user_ss.add(files('plugin-api.c'))
endif

syscall_nr_generators = {}

gen_vdso_exe = executable('gen-vdso', 'gen-vdso.c',
                          native: true, build_by_default: false)
gen_vdso = generator(gen_vdso_exe, output: '@BASENAME@.c.inc',
                     arguments: ['-o', '@OUTPUT@', '@EXTRA_ARGS@', '@INPUT@'])

subdir('aarch64')
subdir('alpha')
subdir('arm')
subdir('hexagon')
subdir('hppa')
subdir('i386')
subdir('loongarch64')
subdir('m68k')
subdir('microblaze')
subdir('mips64')
subdir('mips')
subdir('openrisc')
subdir('ppc')
subdir('riscv')
subdir('s390x')
subdir('sh4')
subdir('sparc')
subdir('x86_64')
subdir('xtensa')

specific_ss.add_all(when: 'CONFIG_LINUX_USER', if_true: linux_user_ss)
