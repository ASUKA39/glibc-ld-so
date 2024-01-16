/* Data structure for communication from the run-time dynamic linker for
   loaded ELF shared objects.
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

#ifndef _PRIVATE_LINK_H
#define _PRIVATE_LINK_H 1

#ifdef _LINK_H
#error this should be impossible
#endif

#ifndef _ISOMAC
/* Get most of the contents from the public header, but we define a
   different `struct link_map' type for private use.  The la_objopen
   prototype uses the type, so we have to declare it separately.  */
#define link_map link_map_public
#define la_objopen la_objopen_wrongproto
#endif

#include <elf/link.h>

#ifndef _ISOMAC

#undef link_map
#undef la_objopen

struct link_map;
extern unsigned int la_objopen(struct link_map *__map, Lmid_t __lmid,
                               uintptr_t *__cookie);

#include <stdint.h>
#include <stddef.h>
#include <linkmap.h>
#include <dl-fileid.h>
#include <dl-lookupcfg.h>
#include <tls.h>
#include <libc-lock.h>

/* Some internal data structures of the dynamic linker used in the
   linker map.  We only provide forward declarations.  */
struct libname_list;
struct r_found_version;
struct r_search_path_elem;

/* Forward declaration.  */
struct link_map;

/* Structure to describe a single list of scope elements.  The lookup
   functions get passed an array of pointers to such structures.  */
struct r_scope_elem
{
   /* Array of maps for the scope.  */
   struct link_map **r_list;
   /* Number of entries in the scope.  */
   unsigned int r_nlist;
};

/* Structure to record search path and allocation mechanism.  */
struct r_search_path_struct
{
   struct r_search_path_elem **dirs;
   int malloced;
};

/* Search path information computed by _dl_init_paths.  */
extern struct r_search_path_struct __rtld_search_dirs attribute_hidden;
extern struct r_search_path_struct __rtld_env_path_list attribute_hidden;

/* Structure describing a loaded shared object.  The `l_next' and `l_prev'
   members form a chain of all the shared objects loaded at startup.

   These data structures exist in space used by the run-time dynamic linker;
   modifying them may have disastrous results.

   This data structure might change in future, if necessary.  User-level
   programs must avoid defining objects of this type.  */
/* 描述已加载的共享对象的结构。l_next和l_prev成员形成启动时加载的所有共享对象的链。
   这些数据结构存在于运行时动态链接器使用的空间中；修改它们可能会产生灾难性的结果。
   如果需要，此数据结构可能会在将来发生变化。用户级程序必须避免定义此类型的对象。*/
struct link_map
{
   /* These first few members are part of the protocol with the debugger.
      This is the same format used in SVR4.  */
   /* 这个结构体的前几个成员是与调试器的协议的一部分。这是在SVR4中使用的相同格式。*/

   ElfW(Addr) l_addr;                /* Difference between the address in the ELF   // ELF文件中的地址与内存中的地址的差值
                                       file and the addresses in memory.  */
   char *l_name;                     /* Absolute file name object was found in.  */ // 被找到的对象的绝对文件名
   ElfW(Dyn) * l_ld;                 /* Dynamic section of the shared object.  */   // 共享对象的动态段
   struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */                // 已加载对象的链表

   /* All following members are internal to the dynamic linker.
      They may change without notice.  */
   /* 以下所有成员都是动态链接器内部的。
      他们可能会在没有通知的情况下改变。*/
   /* This is an element which is only ever different from a pointer to
      the very same copy of this type for ld.so when it is used in more
      than one namespace.  */
   /* 这是一个元素，它与ld.so的指针只有在它在多个命名空间中使用时才会与此类型的完全相同的副本不同。*/
   struct link_map *l_real;

   /* Number of the namespace this link map belongs to.  */
   /* 此链接映射所属的命名空间的编号。*/
   Lmid_t l_ns;

   struct libname_list *l_libname;
   /* Indexed pointers to dynamic section.   // 动态段的索引指针
      [0,DT_NUM) are indexed by the processor-independent tags.
      [DT_NUM,DT_NUM+DT_THISPROCNUM) are indexed by the tag minus DT_LOPROC.
      [DT_NUM+DT_THISPROCNUM,DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM) are
      indexed by DT_VERSIONTAGIDX(tagvalue).
      [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM,
  DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM) are indexed by
      DT_EXTRATAGIDX(tagvalue).
      [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM,
  DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM) are
      indexed by DT_VALTAGIDX(tagvalue) and
      [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM,
  DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM+DT_ADDRNUM)
      are indexed by DT_ADDRTAGIDX(tagvalue), see <elf.h>.  */

   ElfW(Dyn) * l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];   // 动态段的索引指针
   const ElfW(Phdr) * l_phdr; /* Pointer to program header table in core.  */ // 指向内核中程序头表的指针
   ElfW(Addr) l_entry;        /* Entry point location.  */                  // 入口点位置
   ElfW(Half) l_phnum;        /* Number of program header entries.  */     // 程序头表条目数
   ElfW(Half) l_ldnum;        /* Number of dynamic segment entries.  */   // 动态段条目数

   /* Array of DT_NEEDED dependencies and their dependencies, in
      dependency order for symbol lookup (with and without
      duplicates).  There is no entry before the dependencies have
      been loaded.  */
   /* DT_NEEDED依赖项及其依赖项的数组，按依赖项顺序进行符号查找（有和没有重复项）。
      在依赖项加载之前没有条目。*/
   struct r_scope_elem l_searchlist;

   /* We need a special searchlist to process objects marked with
      DT_SYMBOLIC.  */
   /* 我们需要一个特殊的searchlist来处理标记为DT_SYMBOLIC的对象。*/
   struct r_scope_elem l_symbolic_searchlist;

   /* Dependent object that first caused this object to be loaded.  */
   /* 第一个导致加载此对象的依赖对象。*/
   struct link_map *l_loader;

   /* Array with version names.  */
   /* 版本名称数组。*/
   struct r_found_version *l_versions;
   unsigned int l_nversions;

   /* Symbol hash table.  */
   /* 符号哈希表。*/
   Elf_Symndx l_nbuckets;
   Elf32_Word l_gnu_bitmask_idxbits;
   Elf32_Word l_gnu_shift;
   const ElfW(Addr) * l_gnu_bitmask;
   union
   {
      const Elf32_Word *l_gnu_buckets;
      const Elf_Symndx *l_chain;
   };
   union
   {
      const Elf32_Word *l_gnu_chain_zero;
      const Elf_Symndx *l_buckets;
   };

   unsigned int l_direct_opencount; /* Reference count for dlopen/dlclose.  */   // dlopen/dlclose的引用计数
   enum                             /* Where this object came from.  */        // 这个对象来自哪里
   {
      lt_executable, /* The main executable program.  */                    // 主可执行程序
      lt_library,    /* Library needed by main executable.  */            // 主可执行程序所需的库
      lt_loaded      /* Extra run-time loaded shared object.  */       // 额外的运行时加载的共享对象
   } l_type : 2;
   unsigned int l_relocated : 1;               /* Nonzero if object's relocations done.  */  // 如果对象的重定位完成，则为非零。
   unsigned int l_init_called : 1;             /* Nonzero if DT_INIT function called.  */  // 如果调用了DT_INIT函数，则为非零。
   unsigned int l_global : 1;                  /* Nonzero if object in _dl_global_scope.  */ // 如果对象在_dl_global_scope中，则为非零。
   unsigned int l_reserved : 2;                /* Reserved for internal use.  */         // 保留供内部使用。
   unsigned int l_main_map : 1;                /* Nonzero for the map of the main program.  */  // 主程序的映射为非零。
   unsigned int l_visited : 1;                 /* Used internally for map dependency
                              graph traversal.  */                        // 用于映射依赖图遍历的内部使用。
   unsigned int l_map_used : 1;                /* These two bits are used during traversal */   // 在遍历期间使用这两个位
   unsigned int l_map_done : 1;                /* of maps in _dl_close_worker. */         // 在_dl_close_worker中的映射。
   unsigned int l_phdr_allocated : 1;          /* Nonzero if the data structure pointed
                         to by `l_phdr' is allocated.  */                  // 如果由“l_phdr”指向的数据结构已分配，则为非零。
   unsigned int l_soname_added : 1;            /* Nonzero if the SONAME is for sure in
                              the l_libname list.  */                     // 如果SONAME肯定在l_libname列表中，则为非零。
   unsigned int l_faked : 1;                   /* Nonzero if this is a faked descriptor
                                without associated file.  */            // 如果这是一个没有关联文件的伪描述符，则为非零。
   unsigned int l_need_tls_init : 1;           /* Nonzero if GL(dl_init_static_tls)
                              should be called on this link map
                              when relocation finishes.  */              // 如果在重定位完成时应该在此链接映射上调用GL（dl_init_static_tls），则为非零。
   unsigned int l_auditing : 1;                /* Nonzero if the DSO is used in auditing.  */   // 如果DSO在审计中使用，则为非零。
   unsigned int l_audit_any_plt : 1;           /* Nonzero if at least one audit module
                              is interested in the PLT interception.*/  // 如果至少有一个审计模块对PLT拦截感兴趣，则为非零。
   unsigned int l_removed : 1;                 /* Nozero if the object cannot be used anymore
                                since it is removed.  */               // 如果对象已被删除，则不再使用。
   unsigned int l_contiguous : 1;              /* Nonzero if inter-segment holes are
                              mprotected or if no holes are present at  // 如果mprotected存在段间空洞或者没有空洞
                              all.  */
   unsigned int l_symbolic_in_local_scope : 1; /* Nonzero if l_local_scope
                    during LD_TRACE_PRELINKING=1
                    contains any DT_SYMBOLIC
                    libraries.  */                                 // 如果l_local_scope在LD_TRACE_PRELINKING=1期间包含任何DT_SYMBOLIC库，则为非零。
   unsigned int l_free_initfini : 1;           /* Nonzero if l_initfini can be
                              freed, ie. not allocated with
                              the dummy malloc in ld.so.  */         // 如果l_initfini可以被释放，则为非零，即不是用ld.so中的虚拟malloc分配的。
   unsigned int l_ld_readonly : 1;             /* Nonzero if dynamic section is readonly.  */   // 如果动态段是只读的，则为非零。
   unsigned int l_find_object_processed : 1;   /* Zero if _dl_find_object_update
                         needs to process this
                         lt_library map.  */                         // 如果_dl_find_object_update需要处理此lt_library映射，则为零。

   /* NODELETE status of the map.  Only valid for maps of type
      lt_loaded.  Lazy binding sets l_nodelete_active directly,
      potentially from signal handlers.  Initial loading of an
      DF_1_NODELETE object set l_nodelete_pending.  Relocation may
      set l_nodelete_pending as well.  l_nodelete_pending maps are
      promoted to l_nodelete_active status in the final stages of
      dlopen, prior to calling ELF constructors.  dlclose only
      refuses to unload l_nodelete_active maps, the pending status is
      ignored.  */
   /* 映射的NODELETE状态。仅对lt_loaded类型的映射有效。
      惰性绑定直接设置l_nodelete_active，可能来自信号处理程序。
      初始加载DF_1_NODELETE对象设置l_nodelete_pending。
      重定位也可能设置l_nodelete_pending。
      l_nodelete_pending映射在dlopen的最后阶段，在调用ELF构造函数之前，被提升为l_nodelete_active状态。
      dlclose只拒绝卸载l_nodelete_active映射，忽略挂起状态。*/
   bool l_nodelete_active;
   bool l_nodelete_pending;

#include <link_map.h>

   /* Collected information about own RPATH directories.  */
   /* 收集有关自己的RPATH目录的信息。*/
   struct r_search_path_struct l_rpath_dirs;

   /* Collected results of relocation while profiling.  */
   /* 在分析过程中收集的重定位结果。*/
   struct reloc_result
   {
      DL_FIXUP_VALUE_TYPE addr;
      struct link_map *bound;
      unsigned int boundndx;
      uint32_t enterexit;
      unsigned int flags;
      /* CONCURRENCY NOTE: This is used to guard the concurrent initialization
         of the relocation result across multiple threads.  See the more
         detailed notes in elf/dl-runtime.c.  */
      /* 并发注意事项：这用于保护多个线程之间的重定位结果的并发初始化。
         请参阅elf/dl-runtime.c中的更详细说明。*/
      unsigned int init;
   } *l_reloc_result;

   /* Pointer to the version information if available.  */
   /* 如果可用，则指向版本信息。*/
   ElfW(Versym) * l_versyms;

   /* String specifying the path where this object was found.  */
   /* 字符串，指定找到此对象的路径。*/
   const char *l_origin;

   /* Start and finish of memory map for this object.  l_map_start
      need not be the same as l_addr.  */
   /* 此对象的内存映射的开始和结束。l_map_start不需要与l_addr相同。*/
   ElfW(Addr) l_map_start, l_map_end;
   /* End of the executable part of the mapping.  */
   /* 映射的可执行部分的结束。*/
   ElfW(Addr) l_text_end;

   /* Default array for 'l_scope'.  */
   /* l_scope的默认数组。*/
   struct r_scope_elem *l_scope_mem[4];
   /* Size of array allocated for 'l_scope'.  */
   /* 为“l_scope”分配的数组的大小。*/
   size_t l_scope_max;
   /* This is an array defining the lookup scope for this link map.
      There are initially at most three different scope lists.  */
   /* 这是一个数组，定义了此链接映射的查找范围。
      最初最多有三个不同的范围列表。*/
   struct r_scope_elem **l_scope;

   /* A similar array, this time only with the local scope.  This is
      used occasionally.  */
   /* 类似的数组，这次只有本地范围。这是偶尔使用的。*/
   struct r_scope_elem *l_local_scope[2];

   /* This information is kept to check for sure whether a shared
      object is the same as one already loaded.  */
   /* 保留此信息以确保共享对象与已加载的对象相同。*/
   struct r_file_id l_file_id;

   /* Collected information about own RUNPATH directories.  */
   /* 收集有关自己的RUNPATH目录的信息。*/
   struct r_search_path_struct l_runpath_dirs;

   /* List of object in order of the init and fini calls.  */
   /* 按init和fini调用顺序列出对象。*/
   struct link_map **l_initfini;

   /* List of the dependencies introduced through symbol binding.  */
   /* 通过符号绑定引入的依赖项列表。*/
   struct link_map_reldeps
   {
      unsigned int act;
      struct link_map *list[];
   } *l_reldeps;
   unsigned int l_reldepsmax;

   /* Nonzero if the DSO is used.  */
   /* 如果DSO被使用，则为非零。*/
   unsigned int l_used;

   /* Various flag words.  */
   ElfW(Word) l_feature_1;
   ElfW(Word) l_flags_1;
   ElfW(Word) l_flags;

   /* Temporarily used in `dl_close'.  */
   /* 在“dl_close”中临时使用。*/
   int l_idx;

   struct link_map_machine l_mach;

   struct
   {
      const ElfW(Sym) * sym;
      int type_class;
      struct link_map *value;
      const ElfW(Sym) * ret;
   } l_lookup_cache;

   /* Thread-local storage related info.  */
   /* 与TLS相关的信息。*/
   /* Start of the initialization image.  */
   /* 初始化图像的开始。*/
   void *l_tls_initimage;
   /* Size of the initialization image.  */
   /* 初始化图像的大小。*/
   size_t l_tls_initimage_size;
   /* Size of the TLS block.  */
   /* TLS块的大小。*/
   size_t l_tls_blocksize;
   /* Alignment requirement of the TLS block.  */
   /* TLS块的对齐要求。*/
   size_t l_tls_align;
   /* Offset of first byte module alignment.  */
   /* 第一个字节模块对齐的偏移量。*/
   size_t l_tls_firstbyte_offset;
#ifndef NO_TLS_OFFSET
#define NO_TLS_OFFSET 0
#endif
#ifndef FORCED_DYNAMIC_TLS_OFFSET
#if NO_TLS_OFFSET == 0
#define FORCED_DYNAMIC_TLS_OFFSET -1
#elif NO_TLS_OFFSET == -1
#define FORCED_DYNAMIC_TLS_OFFSET -2
#else
#error "FORCED_DYNAMIC_TLS_OFFSET is not defined"
#endif
#endif
   /* For objects present at startup time: offset in the static TLS block.  */
   /* 对于在启动时存在的对象：静态TLS块中的偏移量。*/
   ptrdiff_t l_tls_offset;
   /* Index of the module in the dtv array.  */
   /* dtv数组中模块的索引。*/
   size_t l_tls_modid;

   /* Number of thread_local objects constructed by this DSO.  This is
      atomically accessed and modified and is not always protected by the load
      lock.  See also: CONCURRENCY NOTES in cxa_thread_atexit_impl.c.  */
   /* 此DSO构造的thread_local对象的数量。这是原子访问和修改的，并且并不总是由加载锁保护。
      另请参阅：cxa_thread_atexit_impl.c中的并发注意事项。*/
   size_t l_tls_dtor_count;

   /* Information used to change permission after the relocations are
      done.  */
   /* 在重定位完成后更改权限时使用的信息。*/
   ElfW(Addr) l_relro_addr;
   size_t l_relro_size;

   unsigned long long int l_serial;
};

#include <dl-relocate-ld.h>

/* Information used by audit modules.  For most link maps, this data
   immediate follows the link map in memory.  For the dynamic linker,
   it is allocated separately.  See link_map_audit_state in
   <ldsodefs.h>.  */
struct auditstate
{
   uintptr_t cookie;
   unsigned int bindflags;
};

/* This is the hidden instance of struct r_debug_extended used by the
   dynamic linker.  */
extern struct r_debug_extended _r_debug_extended attribute_hidden;

#if __ELF_NATIVE_CLASS == 32
#define symbind symbind32
#define LA_SYMBIND "la_symbind32"
#elif __ELF_NATIVE_CLASS == 64
#define symbind symbind64
#define LA_SYMBIND "la_symbind64"
#else
#error "__ELF_NATIVE_CLASS must be defined"
#endif

extern int __dl_iterate_phdr(int (*callback)(struct dl_phdr_info *info,
                                             size_t size, void *data),
                             void *data);
hidden_proto(__dl_iterate_phdr)

/* We use this macro to refer to ELF macros independent of the native
   wordsize.  `ELFW(R_TYPE)' is used in place of `ELF32_R_TYPE' or
   `ELF64_R_TYPE'.  */
#define ELFW(type) _ElfW(ELF, __ELF_NATIVE_CLASS, type)

#endif /* !_ISOMAC */
#endif /* include/link.h */
