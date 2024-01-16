/* Run time dynamic linker.
   Copyright (C) 1995-2022 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <ldsodefs.h>
#include <_itoa.h>
#include <entry.h>
#include <fpu_control.h>
#include <hp-timing.h>
#include <libc-lock.h>
#include <dl-librecon.h>
#include <unsecvars.h>
#include <dl-cache.h>
#include <dl-osinfo.h>
#include <dl-procinfo.h>
#include <dl-prop.h>
#include <dl-vdso.h>
#include <dl-vdso-setup.h>
#include <tls.h>
#include <stap-probe.h>
#include <stackinfo.h>
#include <not-cancel.h>
#include <array_length.h>
#include <libc-early-init.h>
#include <dl-main.h>
#include <gnu/lib-names.h>
#include <dl-tunables.h>
#include <get-dynamic-info.h>
#include <dl-execve.h>
#include <dl-find_object.h>
#include <dl-audit-check.h>

#include <assert.h>

/* This #define produces dynamic linking inline functions for
   bootstrap relocation instead of general-purpose relocation.
   Since ld.so must not have any undefined symbols the result
   is trivial: always the map of ld.so itself.  */
#define RTLD_BOOTSTRAP
#define RESOLVE_MAP(map, scope, sym, version, flags) map
#include "dynamic-link.h"

/* Must include after <dl-machine.h> for DT_MIPS definition.  */
#include <dl-debug.h>

/* Only enables rtld profiling for architectures which provides non generic
   hp-timing support.  The generic support requires either syscall
   (clock_gettime), which will incur in extra overhead on loading time.
   Using vDSO is also an option, but it will require extra support on loader
   to setup the vDSO pointer before its usage.  */
#if HP_TIMING_INLINE
#define RLTD_TIMING_DECLARE(var, classifier, ...) \
  classifier hp_timing_t var __VA_ARGS__
#define RTLD_TIMING_VAR(var) RLTD_TIMING_DECLARE(var, )
#define RTLD_TIMING_SET(var, value) (var) = (value)
#define RTLD_TIMING_REF(var) &(var)

static inline void
rtld_timer_start(hp_timing_t *var)
{
  HP_TIMING_NOW(*var);
}

static inline void
rtld_timer_stop(hp_timing_t *var, hp_timing_t start)
{
  hp_timing_t stop;
  HP_TIMING_NOW(stop);
  HP_TIMING_DIFF(*var, start, stop);
}

static inline void
rtld_timer_accum(hp_timing_t *sum, hp_timing_t start)
{
  hp_timing_t stop;
  rtld_timer_stop(&stop, start);
  HP_TIMING_ACCUM_NT(*sum, stop);
}
#else
#define RLTD_TIMING_DECLARE(var, classifier...)
#define RTLD_TIMING_SET(var, value)
#define RTLD_TIMING_VAR(var)
#define RTLD_TIMING_REF(var) 0
#define rtld_timer_start(var)
#define rtld_timer_stop(var, start)
#define rtld_timer_accum(sum, start)
#endif

/* Avoid PLT use for our local calls at startup.  */
extern __typeof(__mempcpy) __mempcpy attribute_hidden;

/* GCC has mental blocks about _exit.  */
extern __typeof(_exit) exit_internal asm("_exit") attribute_hidden;
#define _exit exit_internal

/* Helper function to handle errors while resolving symbols.  */
static void print_unresolved(int errcode, const char *objname,
                             const char *errsting);

/* Helper function to handle errors when a version is missing.  */
static void print_missing_version(int errcode, const char *objname,
                                  const char *errsting);

/* Print the various times we collected.  */
static void print_statistics(const hp_timing_t *total_timep);

/* Creates an empty audit list.  */
static void audit_list_init(struct audit_list *);

/* Add a string to the end of the audit list, for later parsing.  Must
   not be called after audit_list_next.  */
static void audit_list_add_string(struct audit_list *, const char *);

/* Add the audit strings from the link map, found in the dynamic
   segment at TG (either DT_AUDIT and DT_DEPAUDIT).  Must be called
   before audit_list_next.  */
static void audit_list_add_dynamic_tag(struct audit_list *,
                                       struct link_map *,
                                       unsigned int tag);

/* Extract the next audit module from the audit list.  Only modules
   for which dso_name_valid_for_suid is true are returned.  Must be
   called after all the audit_list_add_string,
   audit_list_add_dynamic_tags calls.  */
static const char *audit_list_next(struct audit_list *);

/* Initialize *STATE with the defaults.  */
static void dl_main_state_init(struct dl_main_state *state);

/* Process all environments variables the dynamic linker must recognize.
   Since all of them start with `LD_' we are a bit smarter while finding
   all the entries.  */
extern char **_environ attribute_hidden;
static void process_envvars(struct dl_main_state *state);

#ifdef DL_ARGV_NOT_RELRO
int _dl_argc attribute_hidden;
char **_dl_argv = NULL;
/* Nonzero if we were run directly.  */
unsigned int _dl_skip_args attribute_hidden;
#else
int _dl_argc attribute_relro attribute_hidden;
char **_dl_argv attribute_relro = NULL;
unsigned int _dl_skip_args attribute_relro attribute_hidden;
#endif
rtld_hidden_data_def(_dl_argv)

#ifndef THREAD_SET_STACK_GUARD
    /* Only exported for architectures that don't store the stack guard canary
       in thread local area.  */
    uintptr_t __stack_chk_guard attribute_relro;
#endif

/* Only exported for architectures that don't store the pointer guard
   value in thread local area.  */
uintptr_t __pointer_chk_guard_local attribute_relro attribute_hidden;
#ifndef THREAD_SET_POINTER_GUARD
strong_alias(__pointer_chk_guard_local, __pointer_chk_guard)
#endif

    /* Check that AT_SECURE=0, or that the passed name does not contain
       directories and is not overly long.  Reject empty names
       unconditionally.  */
    static bool dso_name_valid_for_suid(const char *p)
{
  if (__glibc_unlikely(__libc_enable_secure))
  {
    /* Ignore pathnames with directories for AT_SECURE=1
 programs, and also skip overlong names.  */
    size_t len = strlen(p);
    if (len >= SECURE_NAME_LIMIT || memchr(p, '/', len) != NULL)
      return false;
  }
  return *p != '\0';
}

static void
audit_list_init(struct audit_list *list)
{
  list->length = 0;
  list->current_index = 0;
  list->current_tail = NULL;
}

static void
audit_list_add_string(struct audit_list *list, const char *string)
{
  /* Empty strings do not load anything.  */
  if (*string == '\0')
    return;

  if (list->length == array_length(list->audit_strings))
    _dl_fatal_printf("Fatal glibc error: Too many audit modules requested\n");

  list->audit_strings[list->length++] = string;

  /* Initialize processing of the first string for
     audit_list_next.  */
  if (list->length == 1)
    list->current_tail = string;
}

static void
audit_list_add_dynamic_tag(struct audit_list *list, struct link_map *main_map,
                           unsigned int tag)
{
  ElfW(Dyn) *info = main_map->l_info[ADDRIDX(tag)];
  const char *strtab = (const char *)D_PTR(main_map, l_info[DT_STRTAB]);
  if (info != NULL)
    audit_list_add_string(list, strtab + info->d_un.d_val);
}

static const char *
audit_list_next(struct audit_list *list)
{
  if (list->current_tail == NULL)
    return NULL;

  while (true)
  {
    /* Advance to the next string in audit_strings if the current
 string has been exhausted.  */
    while (*list->current_tail == '\0')
    {
      ++list->current_index;
      if (list->current_index == list->length)
      {
        list->current_tail = NULL;
        return NULL;
      }
      list->current_tail = list->audit_strings[list->current_index];
    }

    /* Split the in-string audit list at the next colon colon.  */
    size_t len = strcspn(list->current_tail, ":");
    if (len > 0 && len < sizeof(list->fname))
    {
      memcpy(list->fname, list->current_tail, len);
      list->fname[len] = '\0';
    }
    else
      /* Mark the name as unusable for dso_name_valid_for_suid.  */
      list->fname[0] = '\0';

    /* Skip over the substring and the following delimiter.  */
    list->current_tail += len;
    if (*list->current_tail == ':')
      ++list->current_tail;

    /* If the name is valid, return it.  */
    if (!__glibc_unlikely(__libc_enable_secure) && dso_name_valid_for_suid(list->fname))
      return list->fname;

    /* Otherwise wrap around to find the next list element. .  */
  }
}

/* Count audit modules before they are loaded so GLRO(dl_naudit)
   is not yet usable.  */
static size_t
audit_list_count(struct audit_list *list)
{
  /* Restore the audit_list iterator state at the end.  */
  const char *saved_tail = list->current_tail;
  size_t naudit = 0;

  assert(list->current_index == 0);
  while (audit_list_next(list) != NULL)
    naudit++;
  list->current_tail = saved_tail;
  list->current_index = 0;
  return naudit;
}

static void
dl_main_state_init(struct dl_main_state *state)
{
  audit_list_init(&state->audit_list);
  state->library_path = NULL;
  state->library_path_source = NULL;
  state->preloadlist = NULL;
  state->preloadarg = NULL;
  state->glibc_hwcaps_prepend = NULL;
  state->glibc_hwcaps_mask = NULL;
  state->mode = rtld_mode_normal;
  state->any_debug = false;
  state->version_info = false;
}

#ifndef HAVE_INLINED_SYSCALLS
/* Set nonzero during loading and initialization of executable and
   libraries, cleared before the executable's entry point runs.  This
   must not be initialized to nonzero, because the unused dynamic
   linker loaded in for libc.so's "ld.so.1" dep will provide the
   definition seen by libc.so's initializer; that value must be zero,
   and will be since that dynamic linker's _dl_start and dl_main will
   never be called.  */
int _dl_starting_up = 0;
rtld_hidden_def(_dl_starting_up)
#endif

    /* This is the structure which defines all variables global to ld.so
       (except those which cannot be added for some reason).  */
    struct rtld_global _rtld_global =
        {
/* Get architecture specific initializer.  */
#include <dl-procruntime.c>
            /* Generally the default presumption without further information is an
             * executable stack but this is not true for all platforms.  */
            ._dl_stack_flags = DEFAULT_STACK_PERMS,
#ifdef _LIBC_REENTRANT
            ._dl_load_lock = _RTLD_LOCK_RECURSIVE_INITIALIZER,
            ._dl_load_write_lock = _RTLD_LOCK_RECURSIVE_INITIALIZER,
            ._dl_load_tls_lock = _RTLD_LOCK_RECURSIVE_INITIALIZER,
#endif
            ._dl_nns = 1,
            ._dl_ns =
                {
#ifdef _LIBC_REENTRANT
                    [LM_ID_BASE] = {._ns_unique_sym_table = {.lock = _RTLD_LOCK_RECURSIVE_INITIALIZER}}
#endif
                }};
/* If we would use strong_alias here the compiler would see a
   non-hidden definition.  This would undo the effect of the previous
   declaration.  So spell out what strong_alias does plus add the
   visibility attribute.  */
extern struct rtld_global _rtld_local
    __attribute__((alias("_rtld_global"), visibility("hidden")));

/* This variable is similar to _rtld_local, but all values are
   read-only after relocation.  */
struct rtld_global_ro _rtld_global_ro attribute_relro =
    {
/* Get architecture specific initializer.  */
#include <dl-procinfo.c>
#ifdef NEED_DL_SYSINFO
        ._dl_sysinfo = DL_SYSINFO_DEFAULT,
#endif
        ._dl_debug_fd = STDERR_FILENO,
        ._dl_use_load_bias = -2,
        ._dl_correct_cache_id = _DL_CACHE_DEFAULT_ID,
#if !HAVE_TUNABLES
        ._dl_hwcap_mask = HWCAP_IMPORTANT,
#endif
        ._dl_lazy = 1,
        ._dl_fpu_control = _FPU_DEFAULT,
        ._dl_pagesize = EXEC_PAGESIZE,
        ._dl_inhibit_cache = 0,

        /* Function pointers.  */
        ._dl_debug_printf = _dl_debug_printf,
        ._dl_mcount = _dl_mcount,
        ._dl_lookup_symbol_x = _dl_lookup_symbol_x,
        ._dl_open = _dl_open,
        ._dl_close = _dl_close,
        ._dl_catch_error = _rtld_catch_error,
        ._dl_error_free = _dl_error_free,
        ._dl_tls_get_addr_soft = _dl_tls_get_addr_soft,
        ._dl_libc_freeres = __rtld_libc_freeres,
#ifdef HAVE_DL_DISCOVER_OSVERSION
        ._dl_discover_osversion = _dl_discover_osversion
#endif
};
/* If we would use strong_alias here the compiler would see a
   non-hidden definition.  This would undo the effect of the previous
   declaration.  So spell out was strong_alias does plus add the
   visibility attribute.  */
extern struct rtld_global_ro _rtld_local_ro
    __attribute__((alias("_rtld_global_ro"), visibility("hidden")));

static void dl_main(const ElfW(Phdr) * phdr, ElfW(Word) phnum,
                    ElfW(Addr) * user_entry, ElfW(auxv_t) * auxv);

/* These two variables cannot be moved into .data.rel.ro.  */
static struct libname_list _dl_rtld_libname;
static struct libname_list _dl_rtld_libname2;

/* Variable for statistics.  */
RLTD_TIMING_DECLARE(relocate_time, static);
RLTD_TIMING_DECLARE(load_time, static, attribute_relro);
RLTD_TIMING_DECLARE(start_time, static, attribute_relro);

/* Additional definitions needed by TLS initialization.  */
#ifdef TLS_INIT_HELPER
TLS_INIT_HELPER
#endif

/* Helper function for syscall implementation.  */
#ifdef DL_SYSINFO_IMPLEMENTATION
DL_SYSINFO_IMPLEMENTATION
#endif

/* Before ld.so is relocated we must not access variables which need
   relocations.  This means variables which are exported.  Variables
   declared as static are fine.  If we can mark a variable hidden this
   is fine, too.  The latter is important here.  We can avoid setting
   up a temporary link map for ld.so if we can mark _rtld_global as
   hidden.  */
#ifdef PI_STATIC_AND_HIDDEN
#define DONT_USE_BOOTSTRAP_MAP 1
#endif

#ifdef DONT_USE_BOOTSTRAP_MAP
static ElfW(Addr) _dl_start_final(void *arg);
#else
struct dl_start_final_info
{
  struct link_map l;
  RTLD_TIMING_VAR(start_time);
};
static ElfW(Addr) _dl_start_final(void *arg,
                                  struct dl_start_final_info *info);
#endif

/* These defined magically in the linker script.  */
extern char _begin[] attribute_hidden;
extern char _etext[] attribute_hidden;
extern char _end[] attribute_hidden;

#ifdef RTLD_START
RTLD_START
#else
#error "sysdeps/MACHINE/dl-machine.h fails to define RTLD_START"
#endif

/* This is the second half of _dl_start (below).  It can be inlined safely
   under DONT_USE_BOOTSTRAP_MAP, where it is careful not to make any GOT
   references.  When the tools don't permit us to avoid using a GOT entry
   for _dl_rtld_global (no attribute_hidden support), we must make sure
   this function is not inlined (see below).  */
/* 这是_dl_start的后半部分(如下所示)。它可以在don_use_bootstrap_map下安全地内联，其
  中要注意不进行任何GOT表引用。当工具不允许我们避免使用GOT条目
  for_dl_rtld_global(不支持ATTRIBUTE_HIDDED)时，我们必须确保该函数没有内联(见下文)。*/

#ifdef DONT_USE_BOOTSTRAP_MAP
static inline ElfW(Addr) __attribute__((always_inline))
_dl_start_final(void *arg)
#else
static ElfW(Addr) __attribute__((noinline))
_dl_start_final(void *arg, struct dl_start_final_info *info)
#endif
{
  ElfW(Addr) start_addr;

  /* If it hasn't happen yet record the startup time.  */
  // 如果还没有发生，记录启动时间。
  rtld_timer_start(&start_time);
#if !defined DONT_USE_BOOTSTRAP_MAP
  // 将 info->start_time 设置为 start_time
  RTLD_TIMING_SET(start_time, info->start_time);
#endif

  /* Transfer data about ourselves to the permanent link_map structure.  */
  // 将自身的数据传输到永久的 link_map 结构中
#ifndef DONT_USE_BOOTSTRAP_MAP
  GL(dl_rtld_map).l_addr = info->l.l_addr;
  GL(dl_rtld_map).l_ld = info->l.l_ld;
  GL(dl_rtld_map).l_ld_readonly = info->l.l_ld_readonly;
  memcpy(GL(dl_rtld_map).l_info, info->l.l_info,
         sizeof GL(dl_rtld_map).l_info);
  GL(dl_rtld_map).l_mach = info->l.l_mach;
  GL(dl_rtld_map).l_relocated = 1;
#endif
  _dl_setup_hash(&GL(dl_rtld_map));
  // _dl_rtld_map 就是动态链接器自身的 link_map 结构
  GL(dl_rtld_map).l_real = &GL(dl_rtld_map);
  GL(dl_rtld_map).l_map_start = (ElfW(Addr))_begin;
  GL(dl_rtld_map).l_map_end = (ElfW(Addr))_end;
  GL(dl_rtld_map).l_text_end = (ElfW(Addr))_etext;
  /* Copy the TLS related data if necessary.  */
#ifndef DONT_USE_BOOTSTRAP_MAP
#if NO_TLS_OFFSET != 0
  GL(dl_rtld_map).l_tls_offset = NO_TLS_OFFSET;
#endif
#endif

  /* Initialize the stack end variable.  */
  // 初始化栈顶指针为当前栈帧的栈底地址
  __libc_stack_end = __builtin_frame_address(0);

  /* Call the OS-dependent function to set up life so we can do things like
     file access.  It will call `dl_main' (below) to do all the real work
     of the dynamic linker, and then unwind our frame and run the user
     entry point on the same stack we entered on.  */
  /* 调用与操作系统相关的函数以建立生命周期，这样我们就可以执行文件访问等操作。
   该函数将调用下面的 `dl_main` 函数来执行动态链接器的所有真正工作，
   然后解开我们的栈帧并在我们进入的同一栈上运行用户入口点。 */
  start_addr = _dl_sysdep_start(arg, &dl_main);

  if (__glibc_unlikely(GLRO(dl_debug_mask) & DL_DEBUG_STATISTICS))
  {
    RTLD_TIMING_VAR(rtld_total_time);
    rtld_timer_stop(&rtld_total_time, start_time);
    print_statistics(RTLD_TIMING_REF(rtld_total_time));
  }

  return start_addr;
}

#ifdef DONT_USE_BOOTSTRAP_MAP
#define bootstrap_map GL(dl_rtld_map)
#else
#define bootstrap_map info.l
#endif

static ElfW(Addr) __attribute_used__
    // __attribute_used__ 是 GCC 的特殊属性，表示这个函数是被使用的，避免编译器产生未使用函数的警告
    // ElfW(Addr) 是一个 ELF 文件地址的宏，可以根据目标平台选择合适的字长
    _dl_start(void *arg)
{
#ifdef DONT_USE_BOOTSTRAP_MAP
  rtld_timer_start(&start_time);
#else
  struct dl_start_final_info info;
  // 启动一个计时器，并可能初始化 info 结构体中的计时器
  rtld_timer_start(&info.start_time);
#endif

  /* Partly clean the `bootstrap_map' structure up.  Don't use
     `memset' since it might not be built in or inlined and we cannot
     make function calls at this point.  Use '__builtin_memset' if we
     know it is available.  We do not have to clear the memory if we
     do not have to use the temporary bootstrap_map.  Global variables
     are initialized to zero by default.  */
  /* 清理部分‘bootstrap_map’结构结构体。不要使用‘memset’，因为它可能不是内置或内联的，
  此时我们不能进行函数调用。如果我们知道‘__builtin_memset’可用，
  请使用它。如果我们不必使用临时的 bootstrap_map，则不必清除内存。默认情况下，
  全局变量初始化为零。*/
#ifndef DONT_USE_BOOTSTRAP_MAP
#ifdef HAVE_BUILTIN_MEMSET
  __builtin_memset(bootstrap_map.l_info, '\0', sizeof(bootstrap_map.l_info));
#else
  /* bootstrap_map 是动态链接器在这个过程中使用的一个关键数据结构。它表示的是
  动态链接器自身在进程地址空间中的映射。这个映射包含了动态链接器的代码和数据，以及动态链接器
  需要用来解析符号和重定位的各种表格
  在动态链接器的代码中，bootstrap_map 通常被用来查找和解析动态链接器自身的符号，
  以及设置其他库的依赖关系。*/
  for (size_t cnt = 0;
       cnt < sizeof(bootstrap_map.l_info) / sizeof(bootstrap_map.l_info[0]);
       ++cnt)
    // 清零 bootstrap_map.l_info，该结构体用于存储加载动态库的相关信息
    bootstrap_map.l_info[cnt] = 0;
#endif
#endif

  /* Figure out the run-time load address of the dynamic linker itself.  */
  // 通过 elf_machine_load_address 函数获取动态链接器在运行时的加载地址，这个地址是 ld.so 在内存中的起始地址
  bootstrap_map.l_addr = elf_machine_load_address();

  /* Read our own dynamic section and fill in the info array.  */
  // 计算动态段的地址，读取自身的动态段信息，并填充 bootstrap_map 结构体
  // bootstrap_map.l_ld 存储了动态段的地址，通过 elf_machine_dynamic 计算得到
  bootstrap_map.l_ld = (void *)bootstrap_map.l_addr + elf_machine_dynamic();
  // bootstrap_map.l_ld_readonly 被设置为 DL_RO_DYN_SECTION，表示动态段的只读部分
  bootstrap_map.l_ld_readonly = DL_RO_DYN_SECTION;
  // elf_get_dynamic_info 函数读取 ld.so 自身的动态段信息，并填充到 bootstrap_map 结构体中
  elf_get_dynamic_info(&bootstrap_map, true, false);

// TLS 偏移，Thread Local Storage：线程局部存储
#if NO_TLS_OFFSET != 0
  bootstrap_map.l_tls_offset = NO_TLS_OFFSET;
#endif

#ifdef ELF_MACHINE_BEFORE_RTLD_RELOC
  ELF_MACHINE_BEFORE_RTLD_RELOC(&bootstrap_map, bootstrap_map.l_info);

#endif
  /* 如果 l_addr 不为零或者 DT_GNU_PRELINKED 不存在于动态信息中，执行动态重定位。
  重定位是将 ld.so 本身进行位置调整，以便进行正常的函数调用和数据访问 */
  if (bootstrap_map.l_addr || !bootstrap_map.l_info[VALIDX(DT_GNU_PRELINKED)])
  {
    /* Relocate ourselves so we can do normal function calls and
 data access using the global offset table.  */
    /* 重定位自己，这样就可以使用 GOT 表进行正常的函数调用和数据访问 */
    // 函数定义在 dynamic-link.h，第一个参数一个参数，表示动态链接器的映射信息，包括动态库的加载地址、动态段信息等
    ELF_DYNAMIC_RELOCATE(&bootstrap_map, NULL, 0, 0, 0);
  }
  // bootstrap_map.l_relocated 被设置为 1，表示 ld.so 已经完成了重定位
  bootstrap_map.l_relocated = 1;

  /* Please note that we don't allow profiling of this object and
     therefore need not test whether we have to allocate the array
     for the relocation results (as done in dl-reloc.c).  */

  /* Now life is sane; we can call functions and access global data.
     Set up to use the operating system facilities, and find out from
     the operating system's program loader where to find the program
     header table in core.  Put the rest of _dl_start into a separate
     function, that way the compiler cannot put accesses to the GOT
     before ELF_DYNAMIC_RELOCATE.  */
  /* 现在变得正常了；我们可以调用函数并访问全局数据。设置使用操作系统的功能，
   并从操作系统的程序加载器中获取在核心中找到程序头表的位置。
   将 _dl_start 的其余部分放入一个单独的函数中，这样编译器就不能在 ELF_DYNAMIC_RELOCATE
   之前将对 GOT（全局偏移表）的访问放入其中。 */

  // 初始化与动态内存分配相关的函数，就是设置了几个函数指针，比如 __minimal_malloc、__minimal_free 等
  __rtld_malloc_init_stubs();

  /* Do not use an initializer for these members because it would
     intefere with __rtld_static_init.  */
  // 将全局变量 dl_find_object 指向 _dl_find_object 函数，这是一个查找动态库的函数
  GLRO(dl_find_object) = &_dl_find_object;

  {
#ifdef DONT_USE_BOOTSTRAP_MAP
    ElfW(Addr) entry = _dl_start_final(arg);
#else
    /* 调用 _dl_start_final 函数，该函数负责完成一些后续的初始化工作，
    并返回程序的入口地址 entry */
    // _dl_start_final 函数的定义在本文件的最后
    ElfW(Addr) entry = _dl_start_final(arg, &info);
#endif

#ifndef ELF_MACHINE_START_ADDRESS
#define ELF_MACHINE_START_ADDRESS(map, start) (start)
#endif
    // 返回程序入口地址，通过宏 ELF_MACHINE_START_ADDRESS 可能对地址进行修正
    // 返回值，也即入口地址会被返回到 _start ，然后被保存在 r12 寄存器中，_start 结束后 jmp 到 r12
    return ELF_MACHINE_START_ADDRESS(GL(dl_ns)[LM_ID_BASE]._ns_loaded, entry);
  }
}

/* Now life is peachy; we can do all normal operations.
   On to the real work.  */

/* Some helper functions.  */

/* Arguments to relocate_doit.  */
struct relocate_args
{
  struct link_map *l;
  int reloc_mode;
};

struct map_args
{
  /* Argument to map_doit.  */
  const char *str;
  struct link_map *loader;
  int mode;
  /* Return value of map_doit.  */
  struct link_map *map;
};

struct dlmopen_args
{
  const char *fname;
  struct link_map *map;
};

struct lookup_args
{
  const char *name;
  struct link_map *map;
  void *result;
};

/* Arguments to version_check_doit.  */
struct version_check_args
{
  int doexit;
  int dotrace;
};

static void
relocate_doit(void *a)
{
  struct relocate_args *args = (struct relocate_args *)a;

  _dl_relocate_object(args->l, args->l->l_scope, args->reloc_mode, 0);
}

static void
map_doit(void *a)
{
  struct map_args *args = (struct map_args *)a;
  int type = (args->mode == __RTLD_OPENEXEC) ? lt_executable : lt_library;
  args->map = _dl_map_object(args->loader, args->str, type, 0,
                             args->mode, LM_ID_BASE);
}

static void
dlmopen_doit(void *a)
{
  struct dlmopen_args *args = (struct dlmopen_args *)a;
  args->map = _dl_open(args->fname,
                       (RTLD_LAZY | __RTLD_DLOPEN | __RTLD_AUDIT | __RTLD_SECURE),
                       dl_main, LM_ID_NEWLM, _dl_argc, _dl_argv,
                       __environ);
}

static void
lookup_doit(void *a)
{
  struct lookup_args *args = (struct lookup_args *)a;
  const ElfW(Sym) *ref = NULL;
  args->result = NULL;
  lookup_t l = _dl_lookup_symbol_x(args->name, args->map, &ref,
                                   args->map->l_local_scope, NULL, 0,
                                   DL_LOOKUP_RETURN_NEWEST, NULL);
  if (ref != NULL)
    args->result = DL_SYMBOL_ADDRESS(l, ref);
}

static void
version_check_doit(void *a)
{
  struct version_check_args *args = (struct version_check_args *)a;
  if (_dl_check_all_versions(GL(dl_ns)[LM_ID_BASE]._ns_loaded, 1,
                             args->dotrace) &&
      args->doexit)
    /* We cannot start the application.  Abort now.  */
    _exit(1);
}

static inline struct link_map *
find_needed(const char *name)
{
  struct r_scope_elem *scope = &GL(dl_ns)[LM_ID_BASE]._ns_loaded->l_searchlist;
  unsigned int n = scope->r_nlist;

  while (n-- > 0)
    if (_dl_name_match_p(name, scope->r_list[n]))
      return scope->r_list[n];

  /* Should never happen.  */
  return NULL;
}

static int
match_version(const char *string, struct link_map *map)
{
  const char *strtab = (const void *)D_PTR(map, l_info[DT_STRTAB]);
  ElfW(Verdef) * def;

#define VERDEFTAG (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGIDX(DT_VERDEF))
  if (map->l_info[VERDEFTAG] == NULL)
    /* The file has no symbol versioning.  */
    return 0;

  def = (ElfW(Verdef) *)((char *)map->l_addr + map->l_info[VERDEFTAG]->d_un.d_ptr);
  while (1)
  {
    ElfW(Verdaux) *aux = (ElfW(Verdaux) *)((char *)def + def->vd_aux);

    /* Compare the version strings.  */
    if (strcmp(string, strtab + aux->vda_name) == 0)
      /* Bingo!  */
      return 1;

    /* If no more definitions we failed to find what we want.  */
    if (def->vd_next == 0)
      break;

    /* Next definition.  */
    def = (ElfW(Verdef) *)((char *)def + def->vd_next);
  }

  return 0;
}

static bool tls_init_tp_called;

static void *
init_tls(size_t naudit)
{
  /* Number of elements in the static TLS block.  */
  GL(dl_tls_static_nelem) = GL(dl_tls_max_dtv_idx);

  /* Do not do this twice.  The audit interface might have required
     the DTV interfaces to be set up early.  */
  if (GL(dl_initial_dtv) != NULL)
    return NULL;

  /* Allocate the array which contains the information about the
     dtv slots.  We allocate a few entries more than needed to
     avoid the need for reallocation.  */
  size_t nelem = GL(dl_tls_max_dtv_idx) + 1 + TLS_SLOTINFO_SURPLUS;

  /* Allocate.  */
  GL(dl_tls_dtv_slotinfo_list) = (struct dtv_slotinfo_list *)
      calloc(sizeof(struct dtv_slotinfo_list) + nelem * sizeof(struct dtv_slotinfo), 1);
  /* No need to check the return value.  If memory allocation failed
     the program would have been terminated.  */

  struct dtv_slotinfo *slotinfo = GL(dl_tls_dtv_slotinfo_list)->slotinfo;
  GL(dl_tls_dtv_slotinfo_list)->len = nelem;
  GL(dl_tls_dtv_slotinfo_list)->next = NULL;

  /* Fill in the information from the loaded modules.  No namespace
     but the base one can be filled at this time.  */
  assert(GL(dl_ns)[LM_ID_BASE + 1]._ns_loaded == NULL);
  int i = 0;
  for (struct link_map *l = GL(dl_ns)[LM_ID_BASE]._ns_loaded; l != NULL;
       l = l->l_next)
    if (l->l_tls_blocksize != 0)
    {
      /* This is a module with TLS data.  Store the map reference.
         The generation counter is zero.  */
      slotinfo[i].map = l;
      /* slotinfo[i].gen = 0; */
      ++i;
    }
  assert(i == GL(dl_tls_max_dtv_idx));

  /* Calculate the size of the static TLS surplus.  */
  _dl_tls_static_surplus_init(naudit);

  /* Compute the TLS offsets for the various blocks.  */
  _dl_determine_tlsoffset();

  /* Construct the static TLS block and the dtv for the initial
     thread.  For some platforms this will include allocating memory
     for the thread descriptor.  The memory for the TLS block will
     never be freed.  It should be allocated accordingly.  The dtv
     array can be changed if dynamic loading requires it.  */
  void *tcbp = _dl_allocate_tls_storage();
  if (tcbp == NULL)
    _dl_fatal_printf("\
cannot allocate TLS data structures for initial thread\n");

  /* Store for detection of the special case by __tls_get_addr
     so it knows not to pass this dtv to the normal realloc.  */
  GL(dl_initial_dtv) = GET_DTV(tcbp);

  /* And finally install it for the main thread.  */
  const char *lossage = TLS_INIT_TP(tcbp);
  if (__glibc_unlikely(lossage != NULL))
    _dl_fatal_printf("cannot set up thread-local storage: %s\n", lossage);
  __tls_init_tp();
  tls_init_tp_called = true;

  return tcbp;
}

static unsigned int
do_preload(const char *fname, struct link_map *main_map, const char *where)
{
  const char *objname;
  const char *err_str = NULL;
  struct map_args args;
  bool malloced;

  args.str = fname;
  args.loader = main_map;
  args.mode = __RTLD_SECURE;

  unsigned int old_nloaded = GL(dl_ns)[LM_ID_BASE]._ns_nloaded;

  (void)_dl_catch_error(&objname, &err_str, &malloced, map_doit, &args);  // _dl_catch_error 负责调用 map_doit 函数并捕获异常
  if (__glibc_unlikely(err_str != NULL))
  {
    _dl_error_printf("\
ERROR: ld.so: object '%s' from %s cannot be preloaded (%s): ignored.\n",
                     fname, where, err_str);
    /* No need to call free, this is still before
      the libc's malloc is used.  */
    // 不需要调用 free，这仍然是在 libc 的 malloc 使用之前。
  }
  else if (GL(dl_ns)[LM_ID_BASE]._ns_nloaded != old_nloaded)
    /* It is no duplicate.  */
    /* 不是重复的。 */
    return 1;

  /* Nothing loaded.  */
  /* 没有加载。 */
  return 0;
}

static void
security_init(void)
{
  /* Set up the stack checker's canary.  */
  uintptr_t stack_chk_guard = _dl_setup_stack_chk_guard(_dl_random);
#ifdef THREAD_SET_STACK_GUARD
  THREAD_SET_STACK_GUARD(stack_chk_guard);
#else
  __stack_chk_guard = stack_chk_guard;
#endif

  /* Set up the pointer guard as well, if necessary.  */
  uintptr_t pointer_chk_guard = _dl_setup_pointer_guard(_dl_random, stack_chk_guard);
#ifdef THREAD_SET_POINTER_GUARD
  THREAD_SET_POINTER_GUARD(pointer_chk_guard);
#endif
  __pointer_chk_guard_local = pointer_chk_guard;

  /* We do not need the _dl_random value anymore.  The less
     information we leave behind, the better, so clear the
     variable.  */
  _dl_random = NULL;
}

#include <setup-vdso.h>

/* The LD_PRELOAD environment variable gives list of libraries
   separated by white space or colons that are loaded before the
   executable's dependencies and prepended to the global scope list.
   (If the binary is running setuid all elements containing a '/' are
   ignored since it is insecure.)  Return the number of preloads
   performed.   Ditto for --preload command argument.  */
/* LD_PRELOAD 环境变量给出了由空格或冒号分隔的库列表，这些库在可执行文件的依赖项之前加载，
   并且被预先添加到全局范围列表中。
   (如果二进制文件正在运行 setuid，则忽略所有包含“/”的元素，因为它是不安全的。)
   返回执行的预加载数量。同样适用于 --preload 命令参数。*/
unsigned int
handle_preload_list(const char *preloadlist, struct link_map *main_map,
                    const char *where)
{
  unsigned int npreloads = 0;
  const char *p = preloadlist;
  char fname[SECURE_PATH_LIMIT];

  while (*p != '\0')
  {
    /* Split preload list at space/colon.  */
    // 在空格或冒号处分割预加载列表。
    size_t len = strcspn(p, " :");  // strcspn 返回 p 中第一个不在 " :" 中的字符的位置
    if (len > 0 && len < sizeof(fname))
    {
      memcpy(fname, p, len);
      fname[len] = '\0';
    }
    else
      fname[0] = '\0';

    /* Skip over the substring and the following delimiter.  */
    // 跳过子字符串和后面的分隔符。
    p += len;
    if (*p != '\0')
      ++p;

    if (dso_name_valid_for_suid(fname))
      npreloads += do_preload(fname, main_map, where);
  }
  return npreloads;
}

/* Called if the audit DSO cannot be used: if it does not have the
   appropriate interfaces, or it expects a more recent version library
   version than what the dynamic linker provides.  */
static void
unload_audit_module(struct link_map *map, int original_tls_idx)
{
#ifndef NDEBUG
  Lmid_t ns = map->l_ns;
#endif
  _dl_close(map);

  /* Make sure the namespace has been cleared entirely.  */
  assert(GL(dl_ns)[ns]._ns_loaded == NULL);
  assert(GL(dl_ns)[ns]._ns_nloaded == 0);

  GL(dl_tls_max_dtv_idx) = original_tls_idx;
}

/* Called to print an error message if loading of an audit module
   failed.  */
static void
report_audit_module_load_error(const char *name, const char *err_str,
                               bool malloced)
{
  _dl_error_printf("\
ERROR: ld.so: object '%s' cannot be loaded as audit interface: %s; ignored.\n",
                   name, err_str);
  if (malloced)
    free((char *)err_str);
}

/* Load one audit module.  */
static void
load_audit_module(const char *name, struct audit_ifaces **last_audit)
{
  int original_tls_idx = GL(dl_tls_max_dtv_idx);

  struct dlmopen_args dlmargs;
  dlmargs.fname = name;
  dlmargs.map = NULL;

  const char *objname;
  const char *err_str = NULL;
  bool malloced;
  _dl_catch_error(&objname, &err_str, &malloced, dlmopen_doit, &dlmargs);
  if (__glibc_unlikely(err_str != NULL))
  {
    report_audit_module_load_error(name, err_str, malloced);
    return;
  }

  struct lookup_args largs;
  largs.name = "la_version";
  largs.map = dlmargs.map;
  _dl_catch_error(&objname, &err_str, &malloced, lookup_doit, &largs);
  if (__glibc_likely(err_str != NULL))
  {
    unload_audit_module(dlmargs.map, original_tls_idx);
    report_audit_module_load_error(name, err_str, malloced);
    return;
  }

  unsigned int (*laversion)(unsigned int) = largs.result;

  /* A null symbol indicates that something is very wrong with the
     loaded object because defined symbols are supposed to have a
     valid, non-null address.  */
  assert(laversion != NULL);

  unsigned int lav = laversion(LAV_CURRENT);
  if (lav == 0)
  {
    /* Only print an error message if debugging because this can
 happen deliberately.  */
    if (GLRO(dl_debug_mask) & DL_DEBUG_FILES)
      _dl_debug_printf("\
file=%s [%lu]; audit interface function la_version returned zero; ignored.\n",
                       dlmargs.map->l_name, dlmargs.map->l_ns);
    unload_audit_module(dlmargs.map, original_tls_idx);
    return;
  }

  if (!_dl_audit_check_version(lav))
  {
    _dl_debug_printf("\
ERROR: audit interface '%s' requires version %d (maximum supported version %d); ignored.\n",
                     name, lav, LAV_CURRENT);
    unload_audit_module(dlmargs.map, original_tls_idx);
    return;
  }

  enum
  {
    naudit_ifaces = 8
  };
  union
  {
    struct audit_ifaces ifaces;
    void (*fptr[naudit_ifaces])(void);
  } *newp = malloc(sizeof(*newp));
  if (newp == NULL)
    _dl_fatal_printf("Out of memory while loading audit modules\n");

  /* Names of the auditing interfaces.  All in one
     long string.  */
  static const char audit_iface_names[] =
      "la_activity\0"
      "la_objsearch\0"
      "la_objopen\0"
      "la_preinit\0" LA_SYMBIND "\0"
#define STRING(s) __STRING(s)
      "la_" STRING(ARCH_LA_PLTENTER) "\0"
                                     "la_" STRING(ARCH_LA_PLTEXIT) "\0"
                                                                   "la_objclose\0";
  unsigned int cnt = 0;
  const char *cp = audit_iface_names;
  do
  {
    largs.name = cp;
    _dl_catch_error(&objname, &err_str, &malloced, lookup_doit, &largs);

    /* Store the pointer.  */
    if (err_str == NULL && largs.result != NULL)
      newp->fptr[cnt] = largs.result;
    else
      newp->fptr[cnt] = NULL;
    ++cnt;

    cp = rawmemchr(cp, '\0') + 1;
  } while (*cp != '\0');
  assert(cnt == naudit_ifaces);

  /* Now append the new auditing interface to the list.  */
  newp->ifaces.next = NULL;
  if (*last_audit == NULL)
    *last_audit = GLRO(dl_audit) = &newp->ifaces;
  else
    *last_audit = (*last_audit)->next = &newp->ifaces;

  /* The dynamic linker link map is statically allocated, so the
     cookie in _dl_new_object has not happened.  */
  link_map_audit_state(&GL(dl_rtld_map), GLRO(dl_naudit))->cookie = (intptr_t)&GL(dl_rtld_map);

  ++GLRO(dl_naudit);

  /* Mark the DSO as being used for auditing.  */
  dlmargs.map->l_auditing = 1;
}

/* Load all audit modules.  */
static void
load_audit_modules(struct link_map *main_map, struct audit_list *audit_list)
{
  struct audit_ifaces *last_audit = NULL;

  while (true)
  {
    const char *name = audit_list_next(audit_list);
    if (name == NULL)
      break;
    load_audit_module(name, &last_audit);
  }

  /* Notify audit modules of the initially loaded modules (the main
     program and the dynamic linker itself).  */
  if (GLRO(dl_naudit) > 0)
  {
    _dl_audit_objopen(main_map, LM_ID_BASE);
    _dl_audit_objopen(&GL(dl_rtld_map), LM_ID_BASE);
  }
}

/* Check if the executable is not actualy dynamically linked, and
   invoke it directly in that case.  */
static void
rtld_chain_load(struct link_map *main_map, char *argv0)
{
  /* The dynamic loader run against itself.  */
  const char *rtld_soname = ((const char *)D_PTR(&GL(dl_rtld_map), l_info[DT_STRTAB]) + GL(dl_rtld_map).l_info[DT_SONAME]->d_un.d_val);
  if (main_map->l_info[DT_SONAME] != NULL && strcmp(rtld_soname,
                                                    ((const char *)D_PTR(main_map, l_info[DT_STRTAB]) + main_map->l_info[DT_SONAME]->d_un.d_val)) == 0)
    _dl_fatal_printf("%s: loader cannot load itself\n", rtld_soname);

  /* With DT_NEEDED dependencies, the executable is dynamically
     linked.  */
  if (__glibc_unlikely(main_map->l_info[DT_NEEDED] != NULL))
    return;

  /* If the executable has program interpreter, it is dynamically
     linked.  */
  for (size_t i = 0; i < main_map->l_phnum; ++i)
    if (main_map->l_phdr[i].p_type == PT_INTERP)
      return;

  const char *pathname = _dl_argv[0];
  if (argv0 != NULL)
    _dl_argv[0] = argv0;
  int errcode = __rtld_execve(pathname, _dl_argv, _environ);
  const char *errname = strerrorname_np(errcode);
  if (errname != NULL)
    _dl_fatal_printf("%s: cannot execute %s: %s\n",
                     rtld_soname, pathname, errname);
  else
    _dl_fatal_printf("%s: cannot execute %s: %d\n",
                     rtld_soname, pathname, errcode);
}

/* Called to complete the initialization of the link map for the main
   executable.  Returns true if there is a PT_INTERP segment.  */
// 该函数用于完成主可执行文件的链接映射的初始化，如果有 PT_INTERP 段，则返回 true
static bool
rtld_setup_main_map(struct link_map *main_map)
{
  /* This have already been filled in right after _dl_new_object, or
     as part of _dl_map_object.  */
  const ElfW(Phdr) *phdr = main_map->l_phdr;
  ElfW(Word) phnum = main_map->l_phnum;

  bool has_interp = false;

  main_map->l_map_end = 0;
  main_map->l_text_end = 0;
  /* Perhaps the executable has no PT_LOAD header entries at all.  */
  main_map->l_map_start = ~0;
  /* And it was opened directly.  */
  ++main_map->l_direct_opencount;
  main_map->l_contiguous = 1;

  /* A PT_LOAD segment at an unexpected address will clear the
     l_contiguous flag.  The ELF specification says that PT_LOAD
     segments need to be sorted in in increasing order, but perhaps
     not all executables follow this requirement.  Having l_contiguous
     equal to 1 is just an optimization, so the code below does not
     try to sort the segments in case they are unordered.

     There is one corner case in which l_contiguous is not set to 1,
     but where it could be set: If a PIE (ET_DYN) binary is loaded by
     glibc itself (not the kernel), it is always contiguous due to the
     way the glibc loader works.  However, the kernel loader may still
     create holes in this case, and the code here still uses 0
     conservatively for the glibc-loaded case, too.  */
  ElfW(Addr) expected_load_address = 0;

  /* Scan the program header table for the dynamic section.  */
  // 遍历用户程序头表，查找动态段
  for (const ElfW(Phdr) *ph = phdr; ph < &phdr[phnum]; ++ph)
    switch (ph->p_type)
    {
    case PT_PHDR:
      /* Find out the load address.  */
      main_map->l_addr = (ElfW(Addr))phdr - ph->p_vaddr;
      break;
    case PT_DYNAMIC:
      /* This tells us where to find the dynamic section,
         which tells us everything we need to do.  */
      main_map->l_ld = (void *)main_map->l_addr + ph->p_vaddr;
      main_map->l_ld_readonly = (ph->p_flags & PF_W) == 0;
      break;
    case PT_INTERP:
      /* This "interpreter segment" was used by the program loader to
         find the program interpreter, which is this program itself, the
         dynamic linker.  We note what name finds us, so that a future
         dlopen call or DT_NEEDED entry, for something that wants to link
         against the dynamic linker as a shared library, will know that
         the shared object is already loaded.  */
      _dl_rtld_libname.name = ((const char *)main_map->l_addr + ph->p_vaddr);
      /* _dl_rtld_libname.next = NULL;	Already zero.  */
      GL(dl_rtld_map).l_libname = &_dl_rtld_libname;

      /* Ordinarilly, we would get additional names for the loader from
         our DT_SONAME.  This can't happen if we were actually linked as
         a static executable (detect this case when we have no DYNAMIC).
         If so, assume the filename component of the interpreter path to
         be our SONAME, and add it to our name list.  */
      if (GL(dl_rtld_map).l_ld == NULL)
      {
        const char *p = NULL;
        const char *cp = _dl_rtld_libname.name;

        /* Find the filename part of the path.  */
        while (*cp != '\0')
          if (*cp++ == '/')
            p = cp;

        if (p != NULL)
        {
          _dl_rtld_libname2.name = p;
          /* _dl_rtld_libname2.next = NULL;  Already zero.  */
          _dl_rtld_libname.next = &_dl_rtld_libname2;
        }
      }

      has_interp = true;
      break;
    case PT_LOAD:
    {
      ElfW(Addr) mapstart;
      ElfW(Addr) allocend;

      /* Remember where the main program starts in memory.  */
      mapstart = (main_map->l_addr + (ph->p_vaddr & ~(GLRO(dl_pagesize) - 1)));
      if (main_map->l_map_start > mapstart)
        main_map->l_map_start = mapstart;

      if (main_map->l_contiguous && expected_load_address != 0 && expected_load_address != mapstart)
        main_map->l_contiguous = 0;

      /* Also where it ends.  */
      allocend = main_map->l_addr + ph->p_vaddr + ph->p_memsz;
      if (main_map->l_map_end < allocend)
        main_map->l_map_end = allocend;
      if ((ph->p_flags & PF_X) && allocend > main_map->l_text_end)
        main_map->l_text_end = allocend;

      /* The next expected address is the page following this load
         segment.  */
      expected_load_address = ((allocend + GLRO(dl_pagesize) - 1) & ~(GLRO(dl_pagesize) - 1));
    }
    break;

    case PT_TLS:
      if (ph->p_memsz > 0)
      {
        /* Note that in the case the dynamic linker we duplicate work
           here since we read the PT_TLS entry already in
           _dl_start_final.  But the result is repeatable so do not
           check for this special but unimportant case.  */
        main_map->l_tls_blocksize = ph->p_memsz;
        main_map->l_tls_align = ph->p_align;
        if (ph->p_align == 0)
          main_map->l_tls_firstbyte_offset = 0;
        else
          main_map->l_tls_firstbyte_offset = (ph->p_vaddr & (ph->p_align - 1));
        main_map->l_tls_initimage_size = ph->p_filesz;
        main_map->l_tls_initimage = (void *)ph->p_vaddr;

        /* This image gets the ID one.  */
        GL(dl_tls_max_dtv_idx) = main_map->l_tls_modid = 1;
      }
      break;

    case PT_GNU_STACK:
      GL(dl_stack_flags) = ph->p_flags;
      break;

    case PT_GNU_RELRO:
      main_map->l_relro_addr = ph->p_vaddr;
      main_map->l_relro_size = ph->p_memsz;
      break;
    }
  /* Process program headers again, but scan them backwards so
     that PT_NOTE can be skipped if PT_GNU_PROPERTY exits.  */
  for (const ElfW(Phdr) *ph = &phdr[phnum]; ph != phdr; --ph)
    switch (ph[-1].p_type)
    {
    case PT_NOTE:
      _dl_process_pt_note(main_map, -1, &ph[-1]);
      break;
    case PT_GNU_PROPERTY:
      _dl_process_pt_gnu_property(main_map, -1, &ph[-1]);
      break;
    }

  /* Adjust the address of the TLS initialization image in case
     the executable is actually an ET_DYN object.  */
  if (main_map->l_tls_initimage != NULL)
    main_map->l_tls_initimage = (char *)main_map->l_tls_initimage + main_map->l_addr;
  if (!main_map->l_map_end)
    main_map->l_map_end = ~0;
  if (!main_map->l_text_end)
    main_map->l_text_end = ~0;
  if (!GL(dl_rtld_map).l_libname && GL(dl_rtld_map).l_name)
  {
    /* We were invoked directly, so the program might not have a
 PT_INTERP.  */
    _dl_rtld_libname.name = GL(dl_rtld_map).l_name;
    /* _dl_rtld_libname.next = NULL;	Already zero.  */
    GL(dl_rtld_map).l_libname = &_dl_rtld_libname;
  }
  else
    assert(GL(dl_rtld_map).l_libname); /* How else did we get here?  */

  return has_interp;
}

static void
dl_main(const ElfW(Phdr) * phdr,
        ElfW(Word) phnum,
        ElfW(Addr) * user_entry,
        ElfW(auxv_t) * auxv)
{
  struct link_map *main_map;
  size_t file_size;
  char *file;
  unsigned int i;
  bool prelinked = false;
  bool rtld_is_main = false;
  void *tcbp = NULL;

  struct dl_main_state state;
  dl_main_state_init(&state);

  __tls_pre_init_tp();

#if !PTHREAD_IN_LIBC
  /* The explicit initialization here is cheaper than processing the reloc
     in the _rtld_local definition's initializer.  */
  /* 这里的初始化比在 _rtld_local 定义的初始化器中处理重定位要便宜得多。 */
  GL(dl_make_stack_executable_hook) = &_dl_make_stack_executable;
#endif

  /* Process the environment variable which control the behaviour.  */
  /* 处理控制行为的环境变量。 */
  process_envvars(&state); // 会设置 GLRO(dl_debug_mask) 的值，用于控制调试信息的输出

#ifndef HAVE_INLINED_SYSCALLS
  /* Set up a flag which tells we are just starting.  */
  /* 设置一个标志，告诉我们刚刚开始。 */
  _dl_starting_up = 1;
#endif

  const char *ld_so_name = _dl_argv[0];
  if (*user_entry == (ElfW(Addr))ENTRY_POINT) // 如果入口地址是 _start，那么说明 ld.so 自己作为独立的程序运行
  {
    /* Ho ho.  We are not the program interpreter!  We are the program
        itself!  This means someone ran ld.so as a command.  Well, that
        might be convenient to do sometimes.  We support it by
        interpreting the args like this:

        ld.so PROGRAM ARGS...

        The first argument is the name of a file containing an ELF
        executable we will load and run with the following arguments.
        To simplify life here, PROGRAM is searched for using the
        normal rules for shared objects, rather than $PATH or anything
        like that.  We just load it and use its entry point; we don't
        pay attention to its PT_INTERP command (we are the interpreter
        ourselves).  This is an easy way to test a new ld.so before
        installing it.  */
    /* 现在的情况下我们不是程序解释器，我们本身就是一个程序，这意味着可以将 ld.so 是作为一个命令独立运行。
       这可能有时很方便。我们通过以下方式解释参数来支持它：ld.so 程序 ARGS...
       第一个参数是包含我们将使用以下参数加载和运行的 ELF 可执行文件的文件的名称。
       为了简化这里的活动，程序使用共享对象的正常规则进行搜索，而不是 $PATH 或类似的任何内容。
       我们只是加载它并使用它的入口点；我们不注意它的 PT_INTERP 命令（我们自己是解释器）。
       这是在安装它之前测试新的 ld.so 的简单方法。 */
    rtld_is_main = true;

    char *argv0 = NULL;

    /* Note the place where the dynamic linker actually came from.  */
    /* 注意动态链接器实际来自的位置。 */
    GL(dl_rtld_map).l_name = rtld_progname;

    while (_dl_argc > 1) // 解析命令行参数（ld.so 作为单独的程序独立运行）
      if (!strcmp(_dl_argv[1], "--list"))
      {
        if (state.mode != rtld_mode_help)
        {
          state.mode = rtld_mode_list;
          /* This means do no dependency analysis.  */
          /* 这意味着不进行依赖性分析。 */
          GLRO(dl_lazy) = -1;
        }

        ++_dl_skip_args;
        --_dl_argc;
        ++_dl_argv;
      }
      else if (!strcmp(_dl_argv[1], "--verify"))
      {
        if (state.mode != rtld_mode_help)
          state.mode = rtld_mode_verify;

        ++_dl_skip_args;
        --_dl_argc;
        ++_dl_argv;
      }
      else if (!strcmp(_dl_argv[1], "--inhibit-cache"))
      {
        GLRO(dl_inhibit_cache) = 1;
        ++_dl_skip_args;
        --_dl_argc;
        ++_dl_argv;
      }
      else if (!strcmp(_dl_argv[1], "--library-path") && _dl_argc > 2)
      {
        state.library_path = _dl_argv[2];
        state.library_path_source = "--library-path";

        _dl_skip_args += 2;
        _dl_argc -= 2;
        _dl_argv += 2;
      }
      else if (!strcmp(_dl_argv[1], "--inhibit-rpath") && _dl_argc > 2)
      {
        GLRO(dl_inhibit_rpath) = _dl_argv[2];

        _dl_skip_args += 2;
        _dl_argc -= 2;
        _dl_argv += 2;
      }
      else if (!strcmp(_dl_argv[1], "--audit") && _dl_argc > 2)
      {
        audit_list_add_string(&state.audit_list, _dl_argv[2]);

        _dl_skip_args += 2;
        _dl_argc -= 2;
        _dl_argv += 2;
      }
      else if (!strcmp(_dl_argv[1], "--preload") && _dl_argc > 2)
      {
        state.preloadarg = _dl_argv[2];
        _dl_skip_args += 2;
        _dl_argc -= 2;
        _dl_argv += 2;
      }
      else if (!strcmp(_dl_argv[1], "--argv0") && _dl_argc > 2)
      {
        argv0 = _dl_argv[2];

        _dl_skip_args += 2;
        _dl_argc -= 2;
        _dl_argv += 2;
      }
      else if (strcmp(_dl_argv[1], "--glibc-hwcaps-prepend") == 0 && _dl_argc > 2)
      {
        state.glibc_hwcaps_prepend = _dl_argv[2];
        _dl_skip_args += 2;
        _dl_argc -= 2;
        _dl_argv += 2;
      }
      else if (strcmp(_dl_argv[1], "--glibc-hwcaps-mask") == 0 && _dl_argc > 2)
      {
        state.glibc_hwcaps_mask = _dl_argv[2];
        _dl_skip_args += 2;
        _dl_argc -= 2;
        _dl_argv += 2;
      }
#if HAVE_TUNABLES
      else if (!strcmp(_dl_argv[1], "--list-tunables"))
      {
        state.mode = rtld_mode_list_tunables;

        ++_dl_skip_args;
        --_dl_argc;
        ++_dl_argv;
      }
#endif
      else if (!strcmp(_dl_argv[1], "--list-diagnostics"))
      {
        state.mode = rtld_mode_list_diagnostics;

        ++_dl_skip_args;
        --_dl_argc;
        ++_dl_argv;
      }
      else if (strcmp(_dl_argv[1], "--help") == 0)
      {
        state.mode = rtld_mode_help;
        --_dl_argc;
        ++_dl_argv;
      }
      else if (strcmp(_dl_argv[1], "--version") == 0)
        _dl_version();
      else if (_dl_argv[1][0] == '-' && _dl_argv[1][1] == '-')
      {
        if (_dl_argv[1][1] == '\0')
          /* End of option list.  */
          break;
        else
          /* Unrecognized option.  */
          _dl_usage(ld_so_name, _dl_argv[1]);
      }
      else
        break;

#if HAVE_TUNABLES
    if (__glibc_unlikely(state.mode == rtld_mode_list_tunables)) // 打印 tunables 信息
    {
      __tunables_print();
      _exit(0);
    }
#endif

    if (state.mode == rtld_mode_list_diagnostics) // 打印诊断信息
      _dl_print_diagnostics(_environ);

    /* If we have no further argument the program was called incorrectly.
 Grant the user some education.  */
    /* 如果没有进一步的参数，程序被错误地调用。 */
    if (_dl_argc < 2)
    {
      if (state.mode == rtld_mode_help)
        /* --help without an executable is not an error.  */
        _dl_help(ld_so_name, &state);
      else
        _dl_usage(ld_so_name, NULL);
    }

    ++_dl_skip_args;
    --_dl_argc;
    ++_dl_argv;

    /* The initialization of _dl_stack_flags done below assumes the
        executable's PT_GNU_STACK may have been honored by the kernel, and
        so a PT_GNU_STACK with PF_X set means the stack started out with
        execute permission.  However, this is not really true if the
        dynamic linker is the executable the kernel loaded.  For this
        case, we must reinitialize _dl_stack_flags to match the dynamic
        linker itself.  If the dynamic linker was built with a
        PT_GNU_STACK, then the kernel may have loaded us with a
        nonexecutable stack that we will have to make executable when we
        load the program below unless it has a PT_GNU_STACK indicating
        nonexecutable stack is ok.  */
    /* 下面对 _dl_stack_flags 的初始化假设可执行文件的 PT_GNU_STACK 可能已经被内核采用，
       因此设置了 PF_X 的 PT_GNU_STACK 意味着堆栈最初具有执行权限。但是，如果动态链接器是内核加载的可执行文件，
       那么这并不是真的。对于这种情况，我们必须重新初始化 _dl_stack_flags 以匹配动态链接器本身。
       如果动态链接器是使用 PT_GNU_STACK 构建的，则内核可能已经使用非可执行堆栈加载了我们，
       除非它具有指示非可执行堆栈是可接受的 PT_GNU_STACK，否则我们将在下面加载程序时必须使其可执行。 */

    for (const ElfW(Phdr) *ph = phdr; ph < &phdr[phnum]; ++ph) // 遍历程序头表
      if (ph->p_type == PT_GNU_STACK)                          // 找到 PT_GNU_STACK 段，PT_GNU_STACK 段负责设置堆栈属性
      {
        GL(dl_stack_flags) = ph->p_flags;
        break;
      }

    if (__glibc_unlikely(state.mode == rtld_mode_verify    // 验证可执行文件
                         || state.mode == rtld_mode_help)) // 打印帮助信息
    {
      const char *objname;
      const char *err_str = NULL;
      struct map_args args;
      bool malloced;

      args.str = rtld_progname;
      args.loader = NULL;
      args.mode = __RTLD_OPENEXEC;
      (void)_dl_catch_error(&objname, &err_str, &malloced, map_doit, // 加载可执行文件
                            &args);
      if (__glibc_unlikely(err_str != NULL))
      {
        /* We don't free the returned string, the programs stops
     anyway.  */
        /* 我们不释放返回的字符串，程序无论如何都会停止。 */
        if (state.mode == rtld_mode_help)
          /* Mask the failure to load the main object.  The help
             message contains less information in this case.  */
          /* 掩盖加载主对象的失败。在这种情况下，帮助消息包含的信息较少。 */
          _dl_help(ld_so_name, &state);
        else
          _exit(EXIT_FAILURE); // 退出程序
      }
    }
    else
    {
      RTLD_TIMING_VAR(start);                               // 计时器
      rtld_timer_start(&start);                             // 计时器开始
      _dl_map_object(NULL, rtld_progname, lt_executable, 0, // 加载可执行文件，lt_executable 表示可执行文件
                     __RTLD_OPENEXEC, LM_ID_BASE);          // 此函数的作用是将可执行文件加载到内存中
      rtld_timer_stop(&load_time, start);                   // 计时器结束
    }

    /* Now the map for the main executable is available.  */
    /* 现在可执行文件的 map 可用了。 */
    main_map = GL(dl_ns)[LM_ID_BASE]._ns_loaded; // 获取可执行文件的 map

    if (__glibc_likely(state.mode == rtld_mode_normal))
      rtld_chain_load(main_map, argv0);

    phdr = main_map->l_phdr;
    phnum = main_map->l_phnum;
    /* We overwrite here a pointer to a malloc()ed string.  But since
      the malloc() implementation used at this point is the dummy
      implementations which has no real free() function it does not
      makes sense to free the old string first.  */
    /* 我们在这里覆盖了一个指向 malloc() 的字符串的指针。
      但是，由于此时使用的 malloc() 实现是没有真正的 free() 函数的虚拟实现，
      因此首先释放旧字符串是没有意义的。 */
    main_map->l_name = (char *)"";   // 设置可执行文件的名称
    *user_entry = main_map->l_entry; // 设置入口地址，即可执行文件的入口地址

    /* Set bit indicating this is the main program map.  */
    /* 设置指示这是主程序 map 的位。 */
    main_map->l_main_map = 1;

#ifdef HAVE_AUX_VECTOR
    /* Adjust the on-stack auxiliary vector so that it looks like the
 binary was executed directly.  */
    /* 调整栈上的辅助向量，使其看起来像直接执行了二进制文件。 */
    for (ElfW(auxv_t) *av = auxv; av->a_type != AT_NULL; av++) // 遍历辅助向量
      switch (av->a_type)
      {
      case AT_PHDR:
        av->a_un.a_val = (uintptr_t)phdr; // 设置 PT_PHDR 段的地址
        break;
      case AT_PHNUM:
        av->a_un.a_val = phnum; // 设置 PT_PHDR 段的数量
        break;
      case AT_ENTRY:
        av->a_un.a_val = *user_entry; // 设置入口地址
        break;
#ifdef AT_EXECFN
      case AT_EXECFN:
        av->a_un.a_val = (uintptr_t)_dl_argv[0]; // 设置可执行文件的路径
        break;
#endif
      }
#endif

    /* Set the argv[0] string now that we've processed the executable.  */
    /* 现在我们已经处理了可执行文件，设置 argv[0] 字符串。 */
    if (argv0 != NULL)
      _dl_argv[0] = argv0;
  }
  else // ld.so 作为解释器运行
  {
    /* Create a link_map for the executable itself.
      This will be what dlopen on "" returns.  */
    /* 为可执行文件本身创建一个 link_map。这将是 dlopen (“”）返回的内容。 */
    main_map = _dl_new_object((char *)"", "", lt_executable, NULL, // 创建可执行文件的 link_map
                              __RTLD_OPENEXEC, LM_ID_BASE);
    assert(main_map != NULL);
    main_map->l_phdr = phdr;         // 设置程序头表
    main_map->l_phnum = phnum;       // 设置程序头表的数量
    main_map->l_entry = *user_entry; // 设置入口地址

    /* Even though the link map is not yet fully initialized we can add
      it to the map list since there are no possible users running yet.  */
    /* 即使 link map 还没有完全初始化，我们也可以将其添加到 map 列表中，因为还没有可能运行的用户。 */
    _dl_add_to_namespace_list(main_map, LM_ID_BASE); // 将可执行文件的 link_map 添加到全局链表中
    assert(main_map == GL(dl_ns)[LM_ID_BASE]._ns_loaded);

    /* At this point we are in a bit of trouble.  We would have to
      fill in the values for l_dev and l_ino.  But in general we
      do not know where the file is.  We also do not handle AT_EXECFD
      even if it would be passed up.

      We leave the values here defined to 0.  This is normally no
      problem as the program code itself is normally no shared
      object and therefore cannot be loaded dynamically.  Nothing
      prevent the use of dynamic binaries and in these situations
      we might get problems.  We might not be able to find out
      whether the object is already loaded.  But since there is no
      easy way out and because the dynamic binary must also not
      have an SONAME we ignore this program for now.  If it becomes
      a problem we can force people using SONAMEs.  */
    /* 在这一点上，我们有点麻烦。我们必须填写 l_dev 和 l_ino 的值。但是一般来说，我们不知道文件在哪里。
       我们也不处理 AT_EXECFD，即使它会被传递。我们在这里定义的值为 0。通常这不是问题，因为程序代码本身通常不是共享对象，
       因此不能动态加载。没有什么可以阻止使用动态二进制文件，在这些情况下，我们可能会遇到问题。
       我们可能无法找出对象是否已加载。但是，由于没有简单的方法，而且动态二进制文件也不能有 SONAME，因此我们暂时忽略此程序。
       如果它成为问题，我们可以强制使用 SONAME 的人。 */

    /* We delay initializing the path structure until we got the dynamic
      information for the program.  */
    /* 我们延迟初始化路径结构，直到我们获得程序的动态信息。 */
  }

  bool has_interp = rtld_setup_main_map(main_map); // 设置可执行文件的 map

  /* If the current libname is different from the SONAME, add the
     latter as well.  */
  // 如果当前 libname 与 SONAME 不同，则也将后者添加。
  if (GL(dl_rtld_map).l_info[DT_SONAME] != NULL &&    // 如果 ld.so 的 map 的 DT_SONAME 段不为空
      strcmp(GL(dl_rtld_map).l_libname->name,
            (const char *)D_PTR(&GL(dl_rtld_map), 
            l_info[DT_STRTAB]) + GL(dl_rtld_map).l_info[DT_SONAME]->d_un.d_val) != 0)   // 如果 ld.so 的 map 的 DT_SONAME 段的值与 DT_STRTAB 段的值不相等
  {
    static struct libname_list newname;
    newname.name = ((char *)D_PTR(&GL(dl_rtld_map), l_info[DT_STRTAB]) + GL(dl_rtld_map).l_info[DT_SONAME]->d_un.d_ptr);
    newname.next = NULL;
    newname.dont_free = 1;

    assert(GL(dl_rtld_map).l_libname->next == NULL);
    GL(dl_rtld_map).l_libname->next = &newname;
  }
  /* The ld.so must be relocated since otherwise loading audit modules
     will fail since they reuse the very same ld.so.  */
  // ld.so 必须被重定位，否则加载审计模块将失败，因为它们重用了同一个 ld.so。
  assert(GL(dl_rtld_map).l_relocated);

  if (!rtld_is_main)    // 如果 ld.so 不是作为独立的程序运行
  {
    /* Extract the contents of the dynamic section for easy access.  */
    /* 提取动态段的内容以便于访问。 */
    elf_get_dynamic_info(main_map, false, false);

    /* If the main map is libc.so, update the base namespace to
      refer to this map.  If libc.so is loaded later, this happens
      in _dl_map_object_from_fd.  */
    /* 如果主 map 是 libc.so，则更新基本命名空间以引用此 map。
      如果稍后加载 libc.so，则会在 _dl_map_object_from_fd 中发生。 */
    if (main_map->l_info[DT_SONAME] != NULL && 
        (strcmp(((const char *)D_PTR(main_map, l_info[DT_STRTAB]) + main_map->l_info[DT_SONAME]->d_un.d_val), LIBC_SO)  // LIBC_SO 即 libc.so.6
                                                == 0))    // 如果要加载的共享对象是 libc.so.6
      GL(dl_ns)
    [LM_ID_BASE].libc_map = main_map; // 设置 libc.so 的 map 为 main_map，即可执行文件的 map

    /* Set up our cache of pointers into the hash table.  */
    /* 设置指向哈希表的指针的缓存。 */
    // 哈希表是用来存储库中的符号的，这里设置指向哈希表的指针的缓存
    _dl_setup_hash(main_map);
  }

  if (__glibc_unlikely(state.mode == rtld_mode_verify))
  {
    /* We were called just to verify that this is a dynamic
      executable using us as the program interpreter.  Exit with an
      error if we were not able to load the binary or no interpreter
      is specified (i.e., this is no dynamically linked binary.  */
    /* 我们被调用只是为了验证这是一个使用我们作为程序解释器的动态可执行文件。
       如果我们无法加载二进制文件或未指定解释器（即，这不是动态链接的二进制文件），则退出错误。 */
    if (main_map->l_ld == NULL) // 没有 PT_DYNAMIC 段，即没有动态段，说明不是动态链接的二进制文件
      _exit(1);

      /* We allow here some platform specific code.  */
      /* 我们允许这里有一些特定于平台的代码。 */
#ifdef DISTINGUISH_LIB_VERSIONS
    DISTINGUISH_LIB_VERSIONS;
#endif
    _exit(has_interp ? 0 : 2);
  }

  struct link_map **first_preload = &GL(dl_rtld_map).l_next;
  /* Set up the data structures for the system-supplied DSO early,
     so they can influence _dl_init_paths.  */
  /* 尽早为系统提供的 DSO 设置数据结构，以便它们可以影响 _dl_init_paths。 */
  setup_vdso(main_map, &first_preload); // 设置 vDSO

  /* With vDSO setup we can initialize the function pointers.  */
  /* 有了 vDSO 设置，我们可以初始化函数指针。 */
  setup_vdso_pointers();

#ifdef DL_SYSDEP_OSCHECK
  DL_SYSDEP_OSCHECK(_dl_fatal_printf);
#endif

  /* Initialize the data structures for the search paths for shared
     objects.  */
  /* 初始化共享对象搜索路径的数据结构。 */
  call_init_paths(&state);    // 封装了 _dl_init_paths 函数，用于初始化搜索路径

  /* Initialize _r_debug_extended.  */
  /* 初始化 _r_debug_extended。 */
  struct r_debug *r = _dl_debug_initialize(GL(dl_rtld_map).l_addr, LM_ID_BASE);
  r->r_state = RT_CONSISTENT;

  /* Put the link_map for ourselves on the chain so it can be found by
     name.  Note that at this point the global chain of link maps contains
     exactly one element, which is pointed to by dl_loaded.  */
  /* 将我们自己的 link_map 放在链上，以便可以通过名称找到它。
      请注意，此时 link map 的全局链仅包含一个元素，该元素由 dl_loaded 指向。 */
  if (!GL(dl_rtld_map).l_name)
    /* If not invoked directly, the dynamic linker shared object file was
       found by the PT_INTERP name.  */
    /* 如果没有直接调用，则动态链接器共享对象文件是通过 PT_INTERP 名称找到的。 */
    GL(dl_rtld_map).l_name = (char *)GL(dl_rtld_map).l_libname->name;
  GL(dl_rtld_map).l_type = lt_library;
  main_map->l_next = &GL(dl_rtld_map);  // 将 ld.so 的 map 放到可执行文件的 map 的后面
  GL(dl_rtld_map).l_prev = main_map;    // 设置 ld.so 的 map 的前驱为可执行文件的 map
  ++GL(dl_ns)[LM_ID_BASE]._ns_nloaded;  // 增加全局命名空间的加载的共享对象的数量
  ++GL(dl_load_adds);

  /* If LD_USE_LOAD_BIAS env variable has not been seen, default
     to not using bias for non-prelinked PIEs and libraries
     and using it for executables or prelinked PIEs or libraries.  */
  /* 如果没有看到 LD_USE_LOAD_BIAS 环境变量，则默认不使用偏差来加载非预链接的 PIE 和库，
      并使用它来加载可执行文件或预链接的 PIE 或库。 */
  if (GLRO(dl_use_load_bias) == (ElfW(Addr)) - 2)
    GLRO(dl_use_load_bias) = main_map->l_addr == 0 ? -1 : 0;

  /* Starting from binutils-2.23, the linker will define the magic symbol
     __ehdr_start to point to our own ELF header if it is visible in a
     segment that also includes the phdrs.  If that's not available, we use
     the old method that assumes the beginning of the file is part of the
     lowest-addressed PT_LOAD segment.  */
  /* 从 binutils-2.23 开始，如果在包含 phdrs 的段中可见，则链接器将定义魔术符号 __ehdr_start 指向我们自己的 ELF 标头。
      如果不可用，则使用假设文件开头是最低地址 PT_LOAD 段的一部分的旧方法。 */
  extern const ElfW(Ehdr) __ehdr_start __attribute__((visibility("hidden")));

  /* Set up the program header information for the dynamic linker
     itself.  It is needed in the dl_iterate_phdr callbacks.  */
  /* 为动态链接器本身设置程序头信息。它在 dl_iterate_phdr 回调中需要。 */
  const ElfW(Ehdr) *rtld_ehdr = &__ehdr_start;
  assert(rtld_ehdr->e_ehsize == sizeof *rtld_ehdr);
  assert(rtld_ehdr->e_phentsize == sizeof(ElfW(Phdr)));

  const ElfW(Phdr) *rtld_phdr = (const void *)rtld_ehdr + rtld_ehdr->e_phoff;

  GL(dl_rtld_map).l_phdr = rtld_phdr;
  GL(dl_rtld_map).l_phnum = rtld_ehdr->e_phnum;

  /* PT_GNU_RELRO is usually the last phdr.  */
  /* PT_GNU_RELRO 通常是最后一个 phdr。 */
  size_t cnt = rtld_ehdr->e_phnum;
  while (cnt-- > 0)
    if (rtld_phdr[cnt].p_type == PT_GNU_RELRO)
    {
      GL(dl_rtld_map).l_relro_addr = rtld_phdr[cnt].p_vaddr;
      GL(dl_rtld_map).l_relro_size = rtld_phdr[cnt].p_memsz;
      break;
    }

  /* Add the dynamic linker to the TLS list if it also uses TLS.  */
  /* 如果动态链接器也使用 TLS，则将其添加到 TLS 列表中。 */
  if (GL(dl_rtld_map).l_tls_blocksize != 0)
    /* Assign a module ID.  Do this before loading any audit modules.  */
    /* 分配一个模块 ID。在加载任何审计模块之前执行此操作。 */
    _dl_assign_tls_modid(&GL(dl_rtld_map));

  audit_list_add_dynamic_tag(&state.audit_list, main_map, DT_AUDIT);
  audit_list_add_dynamic_tag(&state.audit_list, main_map, DT_DEPAUDIT);

  /* At this point, all data has been obtained that is included in the
     --help output.  */
  /* 此时，已获取包含在 --help 输出中的所有数据。 */
  if (__glibc_unlikely(state.mode == rtld_mode_help))
    _dl_help(ld_so_name, &state);

  /* If we have auditing DSOs to load, do it now.  */
  /* 如果我们有审计 DSO 要加载，现在就这样做。 */
  bool need_security_init = true;
  if (state.audit_list.length > 0)
  {
    size_t naudit = audit_list_count(&state.audit_list);

    /* Since we start using the auditing DSOs right away we need to
 initialize the data structures now.  */
    /* 由于我们立即开始使用审计 DSO，因此现在需要初始化数据结构。 */
    tcbp = init_tls(naudit);

    /* Initialize security features.  We need to do it this early
 since otherwise the constructors of the audit libraries will
 use different values (especially the pointer guard) and will
 fail later on.  */
    /* 初始化安全功能。我们需要这样做，因为否则审计库的构造函数将使用不同的值（特别是指针保护），
       并且稍后将失败。 */
    security_init();
    need_security_init = false;

    load_audit_modules(main_map, &state.audit_list);

    /* The count based on audit strings may overestimate the number
 of audit modules that got loaded, but not underestimate.  */
    /* 基于审计字符串的计数可能会高估加载的审计模块的数量，但不会低估。 */
    assert(GLRO(dl_naudit) <= naudit);
  }

  /* Keep track of the currently loaded modules to count how many
     non-audit modules which use TLS are loaded.  */
  /* 跟踪当前加载的模块以计算加载了多少个使用 TLS 的非审计模块。 */
  size_t count_modids = _dl_count_modids();

  /* Set up debugging before the debugger is notified for the first time.  */
  /* 在第一次通知调试器之前设置调试。 */
  elf_setup_debug_entry(main_map, r);

  /* We start adding objects.  */
  /* 我们开始添加对象。 */
  r->r_state = RT_ADD;
  _dl_debug_state();
  LIBC_PROBE(init_start, 2, LM_ID_BASE, r);

  /* Auditing checkpoint: we are ready to signal that the initial map
     is being constructed.  */
  /* 审计检查点：我们已准备好发出信号，表示正在构建初始 map。 */
  _dl_audit_activity_map(main_map, LA_ACT_ADD);

  /* We have two ways to specify objects to preload: via environment
     variable and via the file /etc/ld.so.preload.  The latter can also
     be used when security is enabled.  */
  /* 我们有两种方法可以指定要预加载的对象：通过环境变量和通过文件 /etc/ld.so.preload。
      当启用安全性时，也可以使用后者。 */
  assert(*first_preload == NULL);
  struct link_map **preloads = NULL;
  unsigned int npreloads = 0;

  if (__glibc_unlikely(state.preloadlist != NULL)) // 如果有预加载的库
  {
    RTLD_TIMING_VAR(start);
    rtld_timer_start(&start);
    npreloads += handle_preload_list(state.preloadlist, main_map, // 加载预加载的库
                                     "LD_PRELOAD");
    rtld_timer_accum(&load_time, start);
  }

  if (__glibc_unlikely(state.preloadarg != NULL)) // 如果有预加载的库
  {
    RTLD_TIMING_VAR(start);
    rtld_timer_start(&start);
    npreloads += handle_preload_list(state.preloadarg, main_map,
                                     "--preload");
    rtld_timer_accum(&load_time, start);
  }

  /* There usually is no ld.so.preload file, it should only be used
     for emergencies and testing.  So the open call etc should usually
     fail.  Using access() on a non-existing file is faster than using
     open().  So we do this first.  If it succeeds we do almost twice
     the work but this does not matter, since it is not for production
     use.  */
  /* 通常没有 ld.so.preload 文件，它应该仅用于紧急情况和测试。因此，打开调用等通常会失败。
      在不存在的文件上使用 access() 比使用 open() 更快。所以我们首先这样做。如果成功，我们将做几乎两倍的工作，
      但这并不重要，因为它不是用于生产使用。 */
  static const char preload_file[] = "/etc/ld.so.preload"; // 预加载的库的文件路径
  if (__glibc_unlikely(__access(preload_file, R_OK) == 0))
  {
    /* Read the contents of the file.  */
    /* 读取文件的内容。 */
    file = _dl_sysdep_read_whole_file(preload_file, &file_size,
                                      PROT_READ | PROT_WRITE); // 读取文件的内容
    if (__glibc_unlikely(file != MAP_FAILED))
    {
      /* Parse the file.  It contains names of libraries to be loaded,
         separated by white spaces or `:'.  It may also contain
         comments introduced by `#'.  */
      /* 解析文件。它包含要加载的库的名称，由空格或 `:` 分隔。它还可以包含由 `#` 引入的注释。 */
      char *problem;
      char *runp;
      size_t rest;

      /* Eliminate comments.  */
      /* 消除注释。 */
      runp = file;
      rest = file_size;
      while (rest > 0)
      {
        char *comment = memchr(runp, '#', rest);
        if (comment == NULL)
          break;

        rest -= comment - runp;
        do
          *comment = ' ';
        while (--rest > 0 && *++comment != '\n');
      }

      /* We have one problematic case: if we have a name at the end of
         the file without a trailing terminating characters, we cannot
         place the \0.  Handle the case separately.  */
      /* 我们有一个有问题的情况：如果我们在文件末尾有一个没有尾随终止字符的名称，我们无法放置 \0。
         单独处理该情况。 */
      if (file[file_size - 1] != ' ' && file[file_size - 1] != '\t' && file[file_size - 1] != '\n' && file[file_size - 1] != ':')
      {
        problem = &file[file_size];
        while (problem > file && problem[-1] != ' ' && problem[-1] != '\t' && problem[-1] != '\n' && problem[-1] != ':')
          --problem;

        if (problem > file)
          problem[-1] = '\0';
      }
      else
      {
        problem = NULL;
        file[file_size - 1] = '\0';
      }

      RTLD_TIMING_VAR(start);
      rtld_timer_start(&start);

      if (file != problem)
      {
        char *p;
        runp = file;
        while ((p = strsep(&runp, ": \t\n")) != NULL)   // 以空格、制表符、换行符或冒号为分隔符，分割字符串，解析出预加载的库的路径
          if (p[0] != '\0')
            npreloads += do_preload(p, main_map, preload_file);   // 加载预加载的库
      }

      if (problem != NULL)
      {
        char *p = strndupa(problem, file_size - (problem - file));

        npreloads += do_preload(p, main_map, preload_file);
      }

      rtld_timer_accum(&load_time, start);

      /* We don't need the file anymore.  */
      /* 我们不再需要该文件。 */
      __munmap(file, file_size);    // 释放文件的内存
    }
  }

  if (__glibc_unlikely(*first_preload != NULL)) // 如果有预加载的库
  {
    /* Set up PRELOADS with a vector of the preloaded libraries.  */
    /* 使用预加载的库的向量设置 PRELOADS。 */
    struct link_map *l = *first_preload;
    preloads = __alloca(npreloads * sizeof preloads[0]);
    i = 0;
    do
    {
      preloads[i++] = l;
      l = l->l_next;
    } while (l);
    assert(i == npreloads);
  }

#ifdef NEED_DL_SYSINFO_DSO
  /* Now that the audit modules are opened, call la_objopen for the vDSO.  */
  /* 现在已经打开了审计模块，调用 la_objopen 来打开 vDSO。 */
  if (GLRO(dl_sysinfo_map) != NULL)
    _dl_audit_objopen(GLRO(dl_sysinfo_map), LM_ID_BASE);
#endif

  /* Load all the libraries specified by DT_NEEDED entries.  If LD_PRELOAD
     specified some libraries to load, these are inserted before the actual
     dependencies in the executable's searchlist for symbol resolution.  */
  /* 加载 DT_NEEDED 条目指定的所有库。如果 LD_PRELOAD 指定要加载一些库，则将这些库插入到可执行文件的搜索列表中，
      以便在符号解析中插入实际依赖项。 */
  {
    RTLD_TIMING_VAR(start);
    rtld_timer_start(&start);
    _dl_map_object_deps(main_map, preloads, npreloads,    // 分析可执行文件的依赖项
                        state.mode == rtld_mode_trace, 0);
    rtld_timer_accum(&load_time, start);
  }

  /* Mark all objects as being in the global scope.  */
  /* 将所有对象标记为处于全局范围。 */
  for (i = main_map->l_searchlist.r_nlist; i > 0;)
    main_map->l_searchlist.r_list[--i]->l_global = 1;

  /* Remove _dl_rtld_map from the chain.  */
  /* 从链中删除 _dl_rtld_map。 */
  GL(dl_rtld_map).l_prev->l_next = GL(dl_rtld_map).l_next;
  if (GL(dl_rtld_map).l_next != NULL)
    GL(dl_rtld_map).l_next->l_prev = GL(dl_rtld_map).l_prev;

  for (i = 1; i < main_map->l_searchlist.r_nlist; ++i)
    if (main_map->l_searchlist.r_list[i] == &GL(dl_rtld_map))
      break;

  bool rtld_multiple_ref = false;
  if (__glibc_likely(i < main_map->l_searchlist.r_nlist))
  {
    /* Some DT_NEEDED entry referred to the interpreter object itself, so
 put it back in the list of visible objects.  We insert it into the
 chain in symbol search order because gdb uses the chain's order as
 its symbol search order.  */
    /* 一些 DT_NEEDED 条目引用了解释器对象本身，因此将其放回可见对象的列表中。
       我们按符号搜索顺序将其插入到链中，因为 gdb 使用链的顺序作为其符号搜索顺序。 */
    rtld_multiple_ref = true;

    GL(dl_rtld_map).l_prev = main_map->l_searchlist.r_list[i - 1];
    if (__glibc_likely(state.mode == rtld_mode_normal))
    {
      GL(dl_rtld_map).l_next = (i + 1 < main_map->l_searchlist.r_nlist
                                    ? main_map->l_searchlist.r_list[i + 1]
                                    : NULL);
#ifdef NEED_DL_SYSINFO_DSO
      if (GLRO(dl_sysinfo_map) != NULL && GL(dl_rtld_map).l_prev->l_next == GLRO(dl_sysinfo_map) && GL(dl_rtld_map).l_next != GLRO(dl_sysinfo_map))
        GL(dl_rtld_map).l_prev = GLRO(dl_sysinfo_map);
#endif
    }
    else
      /* In trace mode there might be an invisible object (which we
         could not find) after the previous one in the search list.
         In this case it doesn't matter much where we put the
         interpreter object, so we just initialize the list pointer so
         that the assertion below holds.  */
      /* 在跟踪模式下，搜索列表中的前一个对象后可能有一个不可见的对象（我们找不到）。
          在这种情况下，我们放置解释器对象并不重要，因此我们只需初始化列表指针，以便下面的断言成立。 */
      GL(dl_rtld_map).l_next = GL(dl_rtld_map).l_prev->l_next;

    assert(GL(dl_rtld_map).l_prev->l_next == GL(dl_rtld_map).l_next);
    GL(dl_rtld_map).l_prev->l_next = &GL(dl_rtld_map);
    if (GL(dl_rtld_map).l_next != NULL)
    {
      assert(GL(dl_rtld_map).l_next->l_prev == GL(dl_rtld_map).l_prev);
      GL(dl_rtld_map).l_next->l_prev = &GL(dl_rtld_map);
    }
  }

  /* Now let us see whether all libraries are available in the
     versions we need.  */
  /* 现在让我们看看所有库是否都在我们需要的版本中可用。 */
  {
    struct version_check_args args;
    args.doexit = state.mode == rtld_mode_normal;
    args.dotrace = state.mode == rtld_mode_trace;
    _dl_receive_error(print_missing_version, version_check_doit, &args);
  }

  /* We do not initialize any of the TLS functionality unless any of the
     initial modules uses TLS.  This makes dynamic loading of modules with
     TLS impossible, but to support it requires either eagerly doing setup
     now or lazily doing it later.  Doing it now makes us incompatible with
     an old kernel that can't perform TLS_INIT_TP, even if no TLS is ever
     used.  Trying to do it lazily is too hairy to try when there could be
     multiple threads (from a non-TLS-using libpthread).  */
  /* 除非任何初始模块使用 TLS，否则我们不会初始化任何 TLS 功能。
      这使得动态加载具有 TLS 的模块变得不可能，但是要支持它需要急切地现在进行设置或者稍后懒惰地进行设置。
      现在这样做使我们与旧内核不兼容，即使从不使用 TLS。尝试在可能存在多个线程
      （来自不使用 TLS 的 libpthread）时进行懒惰地尝试太复杂了。 */
  bool was_tls_init_tp_called = tls_init_tp_called;
  if (tcbp == NULL)
    tcbp = init_tls(0);

  if (__glibc_likely(need_security_init))
    /* Initialize security features.  But only if we have not done it
       earlier.  */
    /* 初始化安全功能。但是只有在我们之前没有这样做时才这样做。 */
    security_init();

  if (__glibc_unlikely(state.mode != rtld_mode_normal))
  {
    /* We were run just to list the shared libraries.  It is
      important that we do this before real relocation, because the
      functions we call below for output may no longer work properly
      after relocation.  */
    /* 我们只是为了列出共享库而运行。重要的是，我们在真正的重定位之前就这样做，
       因为我们在重定位后调用的函数可能不再正常工作。 */
    struct link_map *l;

    if (GLRO(dl_debug_mask) & DL_DEBUG_PRELINK)
    {
      struct r_scope_elem *scope = &main_map->l_searchlist;

      for (i = 0; i < scope->r_nlist; i++)
      {
        l = scope->r_list[i];
        if (l->l_faked)
        {
          _dl_printf("\t%s => not found\n", l->l_libname->name);
          continue;
        }
        if (_dl_name_match_p(GLRO(dl_trace_prelink), l))
          GLRO(dl_trace_prelink_map) = l;
        _dl_printf("\t%s => %s (0x%0*Zx, 0x%0*Zx)",
                   DSO_FILENAME(l->l_libname->name),
                   DSO_FILENAME(l->l_name),
                   (int)sizeof l->l_map_start * 2,
                   (size_t)l->l_map_start,
                   (int)sizeof l->l_addr * 2,
                   (size_t)l->l_addr);

        if (l->l_tls_modid)
          _dl_printf(" TLS(0x%Zx, 0x%0*Zx)\n", l->l_tls_modid,
                     (int)sizeof l->l_tls_offset * 2,
                     (size_t)l->l_tls_offset);
        else
          _dl_printf("\n");
      }
    }
    else if (GLRO(dl_debug_mask) & DL_DEBUG_UNUSED)
    {
      /* Look through the dependencies of the main executable
         and determine which of them is not actually
         required.  */
      /* 查看主可执行文件的依赖项，并确定哪些实际上不是必需的。 */
      struct link_map *l = main_map;

      /* Relocate the main executable.  */
      // 重定位主可执行文件，这是为了让 main_map->l_next 指向第一个依赖项
      struct relocate_args args = {.l = l,
                                   .reloc_mode = ((GLRO(dl_lazy)
                                                       ? RTLD_LAZY
                                                       : 0) |
                                                  __RTLD_NOIFUNC)};
      _dl_receive_error(print_unresolved, relocate_doit, &args);

      /* This loop depends on the dependencies of the executable to
         correspond in number and order to the DT_NEEDED entries.  */
      /* 此循环取决于可执行文件的依赖项与 DT_NEEDED 条目的数量和顺序相对应。 */
      ElfW(Dyn) *dyn = main_map->l_ld;
      bool first = true;
      while (dyn->d_tag != DT_NULL)
      {
        if (dyn->d_tag == DT_NEEDED)
        {
          l = l->l_next;
#ifdef NEED_DL_SYSINFO_DSO
          /* Skip the VDSO since it's not part of the list
             of objects we brought in via DT_NEEDED entries.  */
          // 跳过 VDSO，因为它不是我们通过 DT_NEEDED 条目带入的对象列表的一部分。
          if (l == GLRO(dl_sysinfo_map))
            l = l->l_next;
#endif
          if (!l->l_used)
          {
            if (first)
            {
              _dl_printf("Unused direct dependencies:\n");
              first = false;
            }

            _dl_printf("\t%s\n", l->l_name);
          }
        }

        ++dyn;
      }

      _exit(first != true);
    }
    else if (!main_map->l_info[DT_NEEDED])
      _dl_printf("\tstatically linked\n");
    else
    {
      for (l = main_map->l_next; l; l = l->l_next)
        if (l->l_faked)
          /* The library was not found.  */
          // 未找到库
          _dl_printf("\t%s => not found\n", l->l_libname->name);
        else if (strcmp(l->l_libname->name, l->l_name) == 0)
          _dl_printf("\t%s (0x%0*Zx)\n", l->l_libname->name,
                     (int)sizeof l->l_map_start * 2,
                     (size_t)l->l_map_start);
        else
          _dl_printf("\t%s => %s (0x%0*Zx)\n", l->l_libname->name,
                     l->l_name, (int)sizeof l->l_map_start * 2,
                     (size_t)l->l_map_start);
    }

    if (__glibc_unlikely(state.mode != rtld_mode_trace))
      for (i = 1; i < (unsigned int)_dl_argc; ++i)
      {
        const ElfW(Sym) *ref = NULL;
        ElfW(Addr) loadbase;
        lookup_t result;

        result = _dl_lookup_symbol_x(_dl_argv[i], main_map,
                                     &ref, main_map->l_scope,
                                     NULL, ELF_RTYPE_CLASS_PLT,
                                     DL_LOOKUP_ADD_DEPENDENCY, NULL);

        loadbase = LOOKUP_VALUE_ADDRESS(result, false);

        _dl_printf("%s found at 0x%0*Zd in object at 0x%0*Zd\n",
                   _dl_argv[i],
                   (int)sizeof ref->st_value * 2,
                   (size_t)ref->st_value,
                   (int)sizeof loadbase * 2, (size_t)loadbase);
      }
    else
    {
      /* If LD_WARN is set, warn about undefined symbols.  */
      /* 如果设置了 LD_WARN，则警告未定义的符号。 */
      if (GLRO(dl_lazy) >= 0 && GLRO(dl_verbose))
      {
        /* We have to do symbol dependency testing.  */
        /* 我们必须进行符号依赖性测试。 */
        struct relocate_args args;
        unsigned int i;

        args.reloc_mode = ((GLRO(dl_lazy) ? RTLD_LAZY : 0) | __RTLD_NOIFUNC);

        i = main_map->l_searchlist.r_nlist;
        while (i-- > 0)
        {
          struct link_map *l = main_map->l_initfini[i];
          if (l != &GL(dl_rtld_map) && !l->l_faked)
          {
            args.l = l;
            _dl_receive_error(print_unresolved, relocate_doit,
                              &args);
          }
        }

        if ((GLRO(dl_debug_mask) & DL_DEBUG_PRELINK) && rtld_multiple_ref)
        {
          /* Mark the link map as not yet relocated again.  */
          /* 将链接映射标记为尚未重新定位。 */
          GL(dl_rtld_map).l_relocated = 0;
          _dl_relocate_object(&GL(dl_rtld_map),
                              main_map->l_scope, __RTLD_NOIFUNC, 0);
        }
      }
#define VERNEEDTAG (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGIDX(DT_VERNEED))
      if (state.version_info)
      {
        /* Print more information.  This means here, print information
     about the versions needed.  */
        /* 打印更多信息。这意味着在这里打印有关所需版本的信息。 */
        int first = 1;
        struct link_map *map;

        for (map = main_map; map != NULL; map = map->l_next) // 遍历所有的 link_map
        {
          const char *strtab;
          ElfW(Dyn) *dyn = map->l_info[VERNEEDTAG];
          ElfW(Verneed) * ent;

          if (dyn == NULL)
            continue;

          strtab = (const void *)D_PTR(map, l_info[DT_STRTAB]);
          ent = (ElfW(Verneed) *)(map->l_addr + dyn->d_un.d_ptr);

          if (first)
          {
            _dl_printf("\n\tVersion information:\n");
            first = 0;
          }

          _dl_printf("\t%s:\n", DSO_FILENAME(map->l_name));

          while (1)
          {
            ElfW(Vernaux) * aux;
            struct link_map *needed;

            needed = find_needed(strtab + ent->vn_file);
            aux = (ElfW(Vernaux) *)((char *)ent + ent->vn_aux);

            while (1)
            {
              const char *fname = NULL;

              if (needed != NULL && match_version(strtab + aux->vna_name,
                                                  needed))
                fname = needed->l_name;

              _dl_printf("\t\t%s (%s) %s=> %s\n",
                         strtab + ent->vn_file,
                         strtab + aux->vna_name,
                         aux->vna_flags & VER_FLG_WEAK
                             ? "[WEAK] "
                             : "",
                         fname ?: "not found");

              if (aux->vna_next == 0)
                /* No more symbols.  */
                // 没有更多的符号。
                break;

              /* Next symbol.  */
              // 下一个符号。
              aux = (ElfW(Vernaux) *)((char *)aux + aux->vna_next);
            }

            if (ent->vn_next == 0)
              /* No more dependencies.  */
              // 没有更多的依赖项。
              break;

            /* Next dependency.  */
            // 下一个依赖项。
            ent = (ElfW(Verneed) *)((char *)ent + ent->vn_next);
          }
        }
      }
    }

    _exit(0);
  }

  if (main_map->l_info[ADDRIDX(DT_GNU_LIBLIST)] &&        // 如果有预链接的库
      !__builtin_expect(GLRO(dl_profile) != NULL, 0) &&   // 如果没有启用性能分析
      !__builtin_expect(GLRO(dl_dynamic_weak), 0))        // 如果没有启用动态弱符号
  {
    ElfW(Lib) * liblist, *liblistend;
    struct link_map **r_list, **r_listend, *l;
    const char *strtab = (const void *)D_PTR(main_map, l_info[DT_STRTAB]);

    assert(main_map->l_info[VALIDX(DT_GNU_LIBLISTSZ)] != NULL);
    liblist = (ElfW(Lib) *)   // 预链接的库的列表
                  main_map->l_info[ADDRIDX(DT_GNU_LIBLIST)]
                      ->d_un.d_ptr;
    liblistend = (ElfW(Lib) *)((char *)liblist + main_map->l_info[VALIDX(DT_GNU_LIBLISTSZ)]->d_un.d_val);
    r_list = main_map->l_searchlist.r_list;
    r_listend = r_list + main_map->l_searchlist.r_nlist;

    for (; r_list < r_listend && liblist < liblistend; r_list++)
    {
      l = *r_list;

      if (l == main_map)
        continue;

      /* If the library is not mapped where it should, fail.  */
      // 如果库没有映射到应该的位置，则失败。
      if (l->l_addr)
        break;

      /* Next, check if checksum matches.  */
      // 接下来，检查校验和是否匹配。
      if (l->l_info[VALIDX(DT_CHECKSUM)] == NULL || l->l_info[VALIDX(DT_CHECKSUM)]->d_un.d_val != liblist->l_checksum)
        break;

      if (l->l_info[VALIDX(DT_GNU_PRELINKED)] == NULL || l->l_info[VALIDX(DT_GNU_PRELINKED)]->d_un.d_val != liblist->l_time_stamp)
        break;

      if (!_dl_name_match_p(strtab + liblist->l_name, l))
        break;

      ++liblist;
    }

    if (r_list == r_listend && liblist == liblistend)
      prelinked = true;

    if (__glibc_unlikely(GLRO(dl_debug_mask) & DL_DEBUG_LIBS))
      _dl_debug_printf("\nprelink checking: %s\n",
                       prelinked ? "ok" : "failed");
  }

  /* Now set up the variable which helps the assembler startup code.  */
  // 现在设置帮助汇编器启动代码的变量。
  GL(dl_ns)
  [LM_ID_BASE]._ns_main_searchlist = &main_map->l_searchlist;

  /* Save the information about the original global scope list since
     we need it in the memory handling later.  */
  // 保存有关原始全局范围列表的信息，因为我们稍后需要在内存处理中使用它。
  GLRO(dl_initial_searchlist) = *GL(dl_ns)[LM_ID_BASE]._ns_main_searchlist;

  /* Remember the last search directory added at startup, now that
     malloc will no longer be the one from dl-minimal.c.  As a side
     effect, this marks ld.so as initialized, so that the rtld_active
     function returns true from now on.  */
  /* 记住在启动时添加的最后一个搜索目录，现在 malloc 将不再是来自 dl-minimal.c 的目录。
     作为副作用，这将 ld.so 标记为已初始化，因此 rtld_active 函数从现在开始返回 true。 */
  GLRO(dl_init_all_dirs) = GL(dl_all_dirs);

  /* Print scope information.  */
  // 打印范围信息。
  if (__glibc_unlikely(GLRO(dl_debug_mask) & DL_DEBUG_SCOPES))
  {
    _dl_debug_printf("\nInitial object scopes\n");

    for (struct link_map *l = main_map; l != NULL; l = l->l_next)
      _dl_show_scope(l, 0);
  }

  _rtld_main_check(main_map, _dl_argv[0]);

  if (prelinked)
  {
    if (main_map->l_info[ADDRIDX(DT_GNU_CONFLICT)] != NULL)
    {
      ElfW(Rela) * conflict, *conflictend;

      RTLD_TIMING_VAR(start);
      rtld_timer_start(&start);

      assert(main_map->l_info[VALIDX(DT_GNU_CONFLICTSZ)] != NULL);
      conflict = (ElfW(Rela) *)
                     main_map->l_info[ADDRIDX(DT_GNU_CONFLICT)]
                         ->d_un.d_ptr;
      conflictend = (ElfW(Rela) *)((char *)conflict + main_map->l_info[VALIDX(DT_GNU_CONFLICTSZ)]->d_un.d_val);
      _dl_resolve_conflicts(main_map, conflict, conflictend);

      rtld_timer_stop(&relocate_time, start);
    }

    /* Set up the object lookup structures.  */
    // 设置对象查找结构。
    _dl_find_object_init();

    /* The library defining malloc has already been relocated due to
 prelinking.  Resolve the malloc symbols for the dynamic
 loader.  */
    /* 由于预链接，定义 malloc 的库已经被重定位。解析动态加载器的 malloc 符号。 */
    __rtld_malloc_init_real(main_map);

    /* Likewise for the locking implementation.  */
    /* 同样适用于锁定实现。 */
    __rtld_mutex_init();

    /* Mark all the objects so we know they have been already relocated.  */
    /* 标记所有对象，以便我们知道它们已经被重定位。 */
    for (struct link_map *l = main_map; l != NULL; l = l->l_next)
    {
      l->l_relocated = 1;
      if (l->l_relro_size)
        _dl_protect_relro(l);

      /* Add object to slot information data if necessasy.  */
      // 如果需要，将对象添加到槽信息数据中。
      if (l->l_tls_blocksize != 0 && tls_init_tp_called)
        _dl_add_to_slotinfo(l, true);
    }
  }
  else
  {
    /* Now we have all the objects loaded.  Relocate them all except for
        the dynamic linker itself.  We do this in reverse order so that copy
        relocs of earlier objects overwrite the data written by later
        objects.  We do not re-relocate the dynamic linker itself in this
        loop because that could result in the GOT entries for functions we
        call being changed, and that would break us.  It is safe to relocate
        the dynamic linker out of order because it has no copy relocs (we
        know that because it is self-contained).  */
    /* 现在我们已经加载了所有对象。重新定位它们，除了动态链接器本身。我们以相反的顺序执行此操作，
       以便较早对象的复制重定位覆盖稍后对象写入的数据。在此循环中，我们不会重新定位动态链接器本身，
       因为这可能导致我们调用的函数的 GOT 条目发生更改，这将使我们中断。可以安全地重新定位动态链接器，
       因为它没有复制重定位（我们知道这一点，因为它是自包含的）。 */

    int consider_profiling = GLRO(dl_profile) != NULL;

    /* If we are profiling we also must do lazy reloaction.  */
    /* 如果我们正在进行分析，我们还必须进行延迟重定位。 */
    GLRO(dl_lazy) |= consider_profiling;

    RTLD_TIMING_VAR(start);
    rtld_timer_start(&start);
    unsigned i = main_map->l_searchlist.r_nlist;
    while (i-- > 0)
    {
      struct link_map *l = main_map->l_initfini[i];

      /* While we are at it, help the memory handling a bit.  We have to
         mark some data structures as allocated with the fake malloc()
         implementation in ld.so.  */
      /* 当我们在处理它时，帮助内存处理一点。我们必须将某些数据结构标记为使用 ld.so 中的伪 malloc() 实现分配。 */
      struct libname_list *lnp = l->l_libname->next;

      while (__builtin_expect(lnp != NULL, 0))
      {
        lnp->dont_free = 1;
        lnp = lnp->next;
      }
      /* Also allocated with the fake malloc().  */
      /* 也使用伪 malloc() 分配。 */
      l->l_free_initfini = 0;

      if (l != &GL(dl_rtld_map))
        _dl_relocate_object(l, l->l_scope, GLRO(dl_lazy) ? RTLD_LAZY : 0,
                            consider_profiling);

      /* Add object to slot information data if necessasy.  */
      // 如果需要，将对象添加到槽信息数据中。
      if (l->l_tls_blocksize != 0 && tls_init_tp_called)
        _dl_add_to_slotinfo(l, true);
    }
    rtld_timer_stop(&relocate_time, start);

    /* Now enable profiling if needed.  Like the previous call,
      this has to go here because the calls it makes should use the
      rtld versions of the functions (particularly calloc()), but it
      needs to have _dl_profile_map set up by the relocator.  */
    /* 现在根据需要启用分析。与前面的调用一样，这必须放在这里，因为它所做的调用应该使用函数的 rtld 版本
       （特别是 calloc()），但它需要由重定位器设置 _dl_profile_map。 */
    if (__glibc_unlikely(GL(dl_profile_map) != NULL))
      /* We must prepare the profiling.  */
      /* 我们必须准备分析。 */
      _dl_start_profile();
  }

  if ((!was_tls_init_tp_called && GL(dl_tls_max_dtv_idx) > 0) || count_modids != _dl_count_modids())
    ++GL(dl_tls_generation);

  /* Now that we have completed relocation, the initializer data
     for the TLS blocks has its final values and we can copy them
     into the main thread's TLS area, which we allocated above.
     Note: thread-local variables must only be accessed after completing
     the next step.  */
  /* 现在我们已经完成了重定位，TLS 块的初始化程序数据具有其最终值，我们可以将它们复制到我们在上面分配的主线程的 TLS 区域中。
      注意：线程局部变量必须在完成下一步之后才能访问。 */
  _dl_allocate_tls_init(tcbp, false);

  /* And finally install it for the main thread.  */
  /* 最后为主线程安装它。 */
  if (!tls_init_tp_called)
  {
    const char *lossage = TLS_INIT_TP(tcbp);
    if (__glibc_unlikely(lossage != NULL))
      _dl_fatal_printf("cannot set up thread-local storage: %s\n",
                       lossage);
    __tls_init_tp();
  }

  /* Make sure no new search directories have been added.  */
  /* 确保没有添加新的搜索目录。 */
  assert(GLRO(dl_init_all_dirs) == GL(dl_all_dirs));

  if (!prelinked && rtld_multiple_ref)
  {
    /* There was an explicit ref to the dynamic linker as a shared lib.
      Re-relocate ourselves with user-controlled symbol definitions.

      We must do this after TLS initialization in case after this
      re-relocation, we might call a user-supplied function
      (e.g. calloc from _dl_relocate_object) that uses TLS data.  */
    /* 动态链接器作为共享库有一个显式引用。使用用户控制的符号定义重新定位自己。
       我们必须在 TLS 初始化之后执行此操作，以防在此重新定位之后，我们可能会调用用户提供的函数
       （例如，_dl_relocate_object 中的 calloc）使用 TLS 数据。 */

    /* Set up the object lookup structures.  */
    /* 设置对象查找结构。 */
    _dl_find_object_init();

    /* The malloc implementation has been relocated, so resolving
      its symbols (and potentially calling IFUNC resolvers) is safe
      at this point.  */
    /* malloc 实现已被重定位，因此在此时解析其符号（并潜在地调用 IFUNC 解析器）是安全的。 */
    __rtld_malloc_init_real(main_map);

    /* Likewise for the locking implementation.  */
    /* 同样适用于锁定实现。 */
    __rtld_mutex_init();

    RTLD_TIMING_VAR(start);
    rtld_timer_start(&start);

    /* Mark the link map as not yet relocated again.  */
    /* 将链接映射标记为尚未重新定位。 */
    GL(dl_rtld_map).l_relocated = 0;
    _dl_relocate_object(&GL(dl_rtld_map), main_map->l_scope, 0, 0);

    rtld_timer_accum(&relocate_time, start);
  }

  /* Relocation is complete.  Perform early libc initialization.  This
     is the initial libc, even if audit modules have been loaded with
     other libcs.  */
  /* 重定位完成。执行 libc 早期初始化。这是初始 libc，即使已经使用其他 libc 加载了审核模块。 */
  _dl_call_libc_early_init(GL(dl_ns)[LM_ID_BASE].libc_map, true);

  /* Do any necessary cleanups for the startup OS interface code.
     We do these now so that no calls are made after rtld re-relocation
     which might be resolved to different functions than we expect.
     We cannot do this before relocating the other objects because
     _dl_relocate_object might need to call `mprotect' for DT_TEXTREL.  */
  /* 对启动 OS 接口代码进行任何必要的清理。我们现在这样做是为了在 rtld 重新定位之后不进行任何调用，
      因为这些调用可能会解析为与我们期望的不同的函数。我们不能在重定位其他对象之前这样做，
      因为 _dl_relocate_object 可能需要为 DT_TEXTREL 调用 `mprotect'。 */
  _dl_sysdep_start_cleanup();

#ifdef SHARED
  /* Auditing checkpoint: we have added all objects.  */
  /* 审计检查点：我们已添加了所有对象。 */
  _dl_audit_activity_nsid(LM_ID_BASE, LA_ACT_CONSISTENT);
#endif

  /* Notify the debugger all new objects are now ready to go.  We must re-get
     the address since by now the variable might be in another object.  */
  /* 通知调试器所有新对象现在都准备就绪。我们必须重新获取地址，因为现在该变量可能在另一个对象中。 */
  r = _dl_debug_update(LM_ID_BASE);
  r->r_state = RT_CONSISTENT;
  _dl_debug_state();
  LIBC_PROBE(init_complete, 2, LM_ID_BASE, r);

#if defined USE_LDCONFIG && !defined MAP_COPY
  /* We must munmap() the cache file.  */
  /* 我们必须 munmap() 缓存文件。 */
  _dl_unload_cache();
#endif

  /* Once we return, _dl_sysdep_start will invoke
     the DT_INIT functions and then *USER_ENTRY.  */
  /* 一旦我们返回，_dl_sysdep_start 将调用 DT_INIT 函数，然后 *USER_ENTRY。 */
}

/* This is a little helper function for resolving symbols while
   tracing the binary.  */
static void
print_unresolved(int errcode __attribute__((unused)), const char *objname,
                 const char *errstring)
{
  if (objname[0] == '\0')
    objname = RTLD_PROGNAME;
  _dl_error_printf("%s	(%s)\n", errstring, objname);
}

/* This is a little helper function for resolving symbols while
   tracing the binary.  */
static void
print_missing_version(int errcode __attribute__((unused)),
                      const char *objname, const char *errstring)
{
  _dl_error_printf("%s: %s: %s\n", RTLD_PROGNAME,
                   objname, errstring);
}

/* Process the string given as the parameter which explains which debugging
   options are enabled.  */
static void
process_dl_debug(struct dl_main_state *state, const char *dl_debug)
{
  /* When adding new entries make sure that the maximal length of a name
     is correctly handled in the LD_DEBUG_HELP code below.  */
  static const struct
  {
    unsigned char len;
    const char name[10];
    const char helptext[41];
    unsigned short int mask;
  } debopts[] =
      {
#define LEN_AND_STR(str) sizeof(str) - 1, str
          {LEN_AND_STR("libs"), "display library search paths",
           DL_DEBUG_LIBS | DL_DEBUG_IMPCALLS},
          {LEN_AND_STR("reloc"), "display relocation processing",
           DL_DEBUG_RELOC | DL_DEBUG_IMPCALLS},
          {LEN_AND_STR("files"), "display progress for input file",
           DL_DEBUG_FILES | DL_DEBUG_IMPCALLS},
          {LEN_AND_STR("symbols"), "display symbol table processing",
           DL_DEBUG_SYMBOLS | DL_DEBUG_IMPCALLS},
          {LEN_AND_STR("bindings"), "display information about symbol binding",
           DL_DEBUG_BINDINGS | DL_DEBUG_IMPCALLS},
          {LEN_AND_STR("versions"), "display version dependencies",
           DL_DEBUG_VERSIONS | DL_DEBUG_IMPCALLS},
          {LEN_AND_STR("scopes"), "display scope information",
           DL_DEBUG_SCOPES},
          {LEN_AND_STR("all"), "all previous options combined",
           DL_DEBUG_LIBS | DL_DEBUG_RELOC | DL_DEBUG_FILES | DL_DEBUG_SYMBOLS | DL_DEBUG_BINDINGS | DL_DEBUG_VERSIONS | DL_DEBUG_IMPCALLS | DL_DEBUG_SCOPES},
          {LEN_AND_STR("statistics"), "display relocation statistics",
           DL_DEBUG_STATISTICS},
          {LEN_AND_STR("unused"), "determined unused DSOs",
           DL_DEBUG_UNUSED},
          {LEN_AND_STR("help"), "display this help message and exit",
           DL_DEBUG_HELP},
      };
#define ndebopts (sizeof(debopts) / sizeof(debopts[0]))

  /* Skip separating white spaces and commas.  */
  while (*dl_debug != '\0')
  {
    if (*dl_debug != ' ' && *dl_debug != ',' && *dl_debug != ':')
    {
      size_t cnt;
      size_t len = 1;

      while (dl_debug[len] != '\0' && dl_debug[len] != ' ' && dl_debug[len] != ',' && dl_debug[len] != ':')
        ++len;

      for (cnt = 0; cnt < ndebopts; ++cnt)
        if (debopts[cnt].len == len && memcmp(dl_debug, debopts[cnt].name, len) == 0)
        {
          GLRO(dl_debug_mask) |= debopts[cnt].mask;
          state->any_debug = true;
          break;
        }

      if (cnt == ndebopts)
      {
        /* Display a warning and skip everything until next
     separator.  */
        char *copy = strndupa(dl_debug, len);
        _dl_error_printf("\
warning: debug option `%s' unknown; try LD_DEBUG=help\n",
                         copy);
      }

      dl_debug += len;
      continue;
    }

    ++dl_debug;
  }

  if (GLRO(dl_debug_mask) & DL_DEBUG_UNUSED)
  {
    /* In order to get an accurate picture of whether a particular
 DT_NEEDED entry is actually used we have to process both
 the PLT and non-PLT relocation entries.  */
    GLRO(dl_lazy) = 0;
  }

  if (GLRO(dl_debug_mask) & DL_DEBUG_HELP)
  {
    size_t cnt;

    _dl_printf("\
Valid options for the LD_DEBUG environment variable are:\n\n");

    for (cnt = 0; cnt < ndebopts; ++cnt)
      _dl_printf("  %.*s%s%s\n", debopts[cnt].len, debopts[cnt].name,
                 "         " + debopts[cnt].len - 3,
                 debopts[cnt].helptext);

    _dl_printf("\n\
To direct the debugging output into a file instead of standard output\n\
a filename can be specified using the LD_DEBUG_OUTPUT environment variable.\n");
    _exit(0);
  }
}

static void
process_envvars(struct dl_main_state *state)
{
  char **runp = _environ;
  char *envline;
  char *debug_output = NULL;

  /* This is the default place for profiling data file.  */
  GLRO(dl_profile_output) = &"/var/tmp\0/var/profile"[__libc_enable_secure ? 9 : 0];

  while ((envline = _dl_next_ld_env_entry(&runp)) != NULL)
  {
    size_t len = 0;

    while (envline[len] != '\0' && envline[len] != '=')
      ++len;

    if (envline[len] != '=')
      /* This is a "LD_" variable at the end of the string without
         a '=' character.  Ignore it since otherwise we will access
         invalid memory below.  */
      continue;

    switch (len)
    {
    case 4:
      /* Warning level, verbose or not.  */
      if (memcmp(envline, "WARN", 4) == 0)
        GLRO(dl_verbose) = envline[5] != '\0';
      break;

    case 5:
      /* Debugging of the dynamic linker?  */
      if (memcmp(envline, "DEBUG", 5) == 0)
      {
        process_dl_debug(state, &envline[6]);
        break;
      }
      if (memcmp(envline, "AUDIT", 5) == 0)
        audit_list_add_string(&state->audit_list, &envline[6]);
      break;

    case 7:
      /* Print information about versions.  */
      if (memcmp(envline, "VERBOSE", 7) == 0)
      {
        state->version_info = envline[8] != '\0';
        break;
      }

      /* List of objects to be preloaded.  */
      if (memcmp(envline, "PRELOAD", 7) == 0)
      {
        state->preloadlist = &envline[8];
        break;
      }

      /* Which shared object shall be profiled.  */
      if (memcmp(envline, "PROFILE", 7) == 0 && envline[8] != '\0')
        GLRO(dl_profile) = &envline[8];
      break;

    case 8:
      /* Do we bind early?  */
      if (memcmp(envline, "BIND_NOW", 8) == 0)
      {
        GLRO(dl_lazy) = envline[9] == '\0';
        break;
      }
      if (memcmp(envline, "BIND_NOT", 8) == 0)
        GLRO(dl_bind_not) = envline[9] != '\0';
      break;

    case 9:
      /* Test whether we want to see the content of the auxiliary
         array passed up from the kernel.  */
      if (!__libc_enable_secure && memcmp(envline, "SHOW_AUXV", 9) == 0)
        _dl_show_auxv();
      break;

#if !HAVE_TUNABLES
    case 10:
      /* Mask for the important hardware capabilities.  */
      if (!__libc_enable_secure && memcmp(envline, "HWCAP_MASK", 10) == 0)
        GLRO(dl_hwcap_mask) = _dl_strtoul(&envline[11], NULL);
      break;
#endif

    case 11:
      /* Path where the binary is found.  */
      if (!__libc_enable_secure && memcmp(envline, "ORIGIN_PATH", 11) == 0)
        GLRO(dl_origin_path) = &envline[12];
      break;

    case 12:
      /* The library search path.  */
      if (!__libc_enable_secure && memcmp(envline, "LIBRARY_PATH", 12) == 0)
      {
        state->library_path = &envline[13];
        state->library_path_source = "LD_LIBRARY_PATH";
        break;
      }

      /* Where to place the profiling data file.  */
      if (memcmp(envline, "DEBUG_OUTPUT", 12) == 0)
      {
        debug_output = &envline[13];
        break;
      }

      if (!__libc_enable_secure && memcmp(envline, "DYNAMIC_WEAK", 12) == 0)
        GLRO(dl_dynamic_weak) = 1;
      break;

    case 13:
      /* We might have some extra environment variable with length 13
         to handle.  */
#ifdef EXTRA_LD_ENVVARS_13
      EXTRA_LD_ENVVARS_13
#endif
      if (!__libc_enable_secure && memcmp(envline, "USE_LOAD_BIAS", 13) == 0)
      {
        GLRO(dl_use_load_bias) = envline[14] == '1' ? -1 : 0;
        break;
      }
      break;

    case 14:
      /* Where to place the profiling data file.  */
      if (!__libc_enable_secure && memcmp(envline, "PROFILE_OUTPUT", 14) == 0 && envline[15] != '\0')
        GLRO(dl_profile_output) = &envline[15];
      break;

    case 16:
      /* The mode of the dynamic linker can be set.  */
      if (memcmp(envline, "TRACE_PRELINKING", 16) == 0)
      {
        state->mode = rtld_mode_trace;
        GLRO(dl_verbose) = 1;
        GLRO(dl_debug_mask) |= DL_DEBUG_PRELINK;
        GLRO(dl_trace_prelink) = &envline[17];
      }
      break;

    case 20:
      /* The mode of the dynamic linker can be set.  */
      if (memcmp(envline, "TRACE_LOADED_OBJECTS", 20) == 0)
        state->mode = rtld_mode_trace;
      break;

      /* We might have some extra environment variable to handle.  This
         is tricky due to the pre-processing of the length of the name
         in the switch statement here.  The code here assumes that added
         environment variables have a different length.  */
#ifdef EXTRA_LD_ENVVARS
      EXTRA_LD_ENVVARS
#endif
    }
  }

  /* Extra security for SUID binaries.  Remove all dangerous environment
     variables.  */
  if (__builtin_expect(__libc_enable_secure, 0))
  {
    static const char unsecure_envvars[] =
#ifdef EXTRA_UNSECURE_ENVVARS
        EXTRA_UNSECURE_ENVVARS
#endif
            UNSECURE_ENVVARS;
    const char *nextp;

    nextp = unsecure_envvars;
    do
    {
      unsetenv(nextp);
      /* We could use rawmemchr but this need not be fast.  */
      nextp = (char *)(strchr)(nextp, '\0') + 1;
    } while (*nextp != '\0');

    if (__access("/etc/suid-debug", F_OK) != 0)
    {
#if !HAVE_TUNABLES
      unsetenv("MALLOC_CHECK_");
#endif
      GLRO(dl_debug_mask) = 0;
    }

    if (state->mode != rtld_mode_normal)
      _exit(5);
  }
  /* If we have to run the dynamic linker in debugging mode and the
     LD_DEBUG_OUTPUT environment variable is given, we write the debug
     messages to this file.  */
  else if (state->any_debug && debug_output != NULL)
  {
    const int flags = O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW;
    size_t name_len = strlen(debug_output);
    char buf[name_len + 12];
    char *startp;

    buf[name_len + 11] = '\0';
    startp = _itoa(__getpid(), &buf[name_len + 11], 10, 0);
    *--startp = '.';
    startp = memcpy(startp - name_len, debug_output, name_len);

    GLRO(dl_debug_fd) = __open64_nocancel(startp, flags, DEFFILEMODE);
    if (GLRO(dl_debug_fd) == -1)
      /* We use standard output if opening the file failed.  */
      GLRO(dl_debug_fd) = STDOUT_FILENO;
  }
}

#if HP_TIMING_INLINE
static void
print_statistics_item(const char *title, hp_timing_t time,
                      hp_timing_t total)
{
  char cycles[HP_TIMING_PRINT_SIZE];
  HP_TIMING_PRINT(cycles, sizeof(cycles), time);

  char relative[3 * sizeof(hp_timing_t) + 2];
  char *cp = _itoa((1000ULL * time) / total, relative + sizeof(relative),
                   10, 0);
  /* Sets the decimal point.  */
  char *wp = relative;
  switch (relative + sizeof(relative) - cp)
  {
  case 3:
    *wp++ = *cp++;
    /* Fall through.  */
  case 2:
    *wp++ = *cp++;
    /* Fall through.  */
  case 1:
    *wp++ = '.';
    *wp++ = *cp++;
  }
  *wp = '\0';
  _dl_debug_printf("%s: %s cycles (%s%%)\n", title, cycles, relative);
}
#endif

/* Print the various times we collected.  */
static void
    __attribute((noinline))
    print_statistics(const hp_timing_t *rtld_total_timep)
{
#if HP_TIMING_INLINE
  {
    char cycles[HP_TIMING_PRINT_SIZE];
    HP_TIMING_PRINT(cycles, sizeof(cycles), *rtld_total_timep);
    _dl_debug_printf("\nruntime linker statistics:\n"
                     "  total startup time in dynamic loader: %s cycles\n",
                     cycles);
    print_statistics_item("            time needed for relocation",
                          relocate_time, *rtld_total_timep);
  }
#endif

  unsigned long int num_relative_relocations = 0;
  for (Lmid_t ns = 0; ns < GL(dl_nns); ++ns)
  {
    if (GL(dl_ns)[ns]._ns_loaded == NULL)
      continue;

    struct r_scope_elem *scope = &GL(dl_ns)[ns]._ns_loaded->l_searchlist;

    for (unsigned int i = 0; i < scope->r_nlist; i++)
    {
      struct link_map *l = scope->r_list[i];

      if (l->l_addr != 0 && l->l_info[VERSYMIDX(DT_RELCOUNT)])
        num_relative_relocations += l->l_info[VERSYMIDX(DT_RELCOUNT)]->d_un.d_val;
#ifndef ELF_MACHINE_REL_RELATIVE
      /* Relative relocations are processed on these architectures if
         library is loaded to different address than p_vaddr or
         if not prelinked.  */
      if ((l->l_addr != 0 || !l->l_info[VALIDX(DT_GNU_PRELINKED)]) && l->l_info[VERSYMIDX(DT_RELACOUNT)])
#else
      /* On e.g. IA-64 or Alpha, relative relocations are processed
         only if library is loaded to different address than p_vaddr.  */
      if (l->l_addr != 0 && l->l_info[VERSYMIDX(DT_RELACOUNT)])
#endif
        num_relative_relocations += l->l_info[VERSYMIDX(DT_RELACOUNT)]->d_un.d_val;
    }
  }

  _dl_debug_printf("                 number of relocations: %lu\n"
                   "      number of relocations from cache: %lu\n"
                   "        number of relative relocations: %lu\n",
                   GL(dl_num_relocations),
                   GL(dl_num_cache_relocations),
                   num_relative_relocations);

#if HP_TIMING_INLINE
  print_statistics_item("           time needed to load objects",
                        load_time, *rtld_total_timep);
#endif
}
