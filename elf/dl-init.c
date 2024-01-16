/* Run initializers for newly loaded objects.
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

#include <assert.h>
#include <stddef.h>
#include <ldsodefs.h>
#include <elf-initfini.h>

static void
call_init(struct link_map *l, int argc, char **argv, char **env)
{
  /* If the object has not been relocated, this is a bug.  The
     function pointers are invalid in this case.  (Executables do not
     need relocation, and neither do proxy objects.)  */
  /* 如果对象未被重定位，则存在错误。在这种情况下，函数指针是无效的。
     （可执行文件不需要重定位，代理对象也不需要。） */
  assert(l->l_real->l_relocated || l->l_real->l_type == lt_executable);

  if (l->l_init_called)
    /* This object is all done.  */
    /* 如果已经调用了对象的初始化函数，则直接返回。这表示对象的初始化已经完成。 */
    return;

  /* Avoid handling this constructor again in case we have a circular
     dependency.  */
  /* 为了防止处理循环依赖的构造函数，将 l_init_called 标志设置为1。 */
  l->l_init_called = 1;

  /* Check for object which constructors we do not run here.  */
  /* 检查是否有对象的构造函数不在这里运行。此处忽略 lt_executable 类型的对象，
     以及名称以 'a' 开头的对象。这可能是为了跳过一些不需要在这个时候运行的构造函数。 */
  if (__builtin_expect(l->l_name[0], 'a') == '\0' && l->l_type == lt_executable)
    return;

  /* Print a debug message if wanted.  */
  if (__glibc_unlikely(GLRO(dl_debug_mask) & DL_DEBUG_IMPCALLS))
    _dl_debug_printf("\ncalling init: %s\n\n",
                     DSO_FILENAME(l->l_name));

  /* Now run the local constructors.  There are two forms of them:
     - the one named by DT_INIT
     - the others in the DT_INIT_ARRAY.
  */
  /* 现在运行本地构造函数。有两种形式：
     - 由 DT_INIT 命名的构造函数
     - 在 DT_INIT_ARRAY 中的其他构造函数。 */
  if (ELF_INITFINI && l->l_info[DT_INIT] != NULL)
    DL_CALL_DT_INIT(l, l->l_addr + l->l_info[DT_INIT]->d_un.d_ptr, argc, argv, env);

  /* Next see whether there is an array with initialization functions.  */
  /* 接下来查看是否存在带有初始化函数的数组。如果存在，则遍历该数组并调用其中的初始化函数。 */
  ElfW(Dyn) *init_array = l->l_info[DT_INIT_ARRAY];
  if (init_array != NULL)
  {
    unsigned int j;
    unsigned int jm;
    ElfW(Addr) * addrs;

    jm = l->l_info[DT_INIT_ARRAYSZ]->d_un.d_val / sizeof(ElfW(Addr));

    addrs = (ElfW(Addr) *)(init_array->d_un.d_ptr + l->l_addr);
    for (j = 0; j < jm; ++j)
      ((dl_init_t)addrs[j])(argc, argv, env);
  }
}

void _dl_init(struct link_map *main_map, int argc, char **argv, char **env)
{
  // main_map 是指向主程序的 link_map 结构体的指针
  ElfW(Dyn) *preinit_array = main_map->l_info[DT_PREINIT_ARRAY];
  ElfW(Dyn) *preinit_array_size = main_map->l_info[DT_PREINIT_ARRAYSZ];
  unsigned int i;

  // 如果存在全局初始化函数 GL(dl_initfirst)，则调用该函数并将其设为 NULL。这是为了在启动时执行全局初始化函数。
  if (__glibc_unlikely(GL(dl_initfirst) != NULL))   // 如果存在全局初始化函数
  {
    call_init(GL(dl_initfirst), argc, argv, env);   // 调用全局初始化函数
    GL(dl_initfirst) = NULL;
  }

  /* Don't do anything if there is no preinit array.  */
  /* 如果存在预初始化数组 preinit_array，则按照数组中的顺序调用其中的初始化函数。
  这些函数在动态链接器启动过程中执行，用于执行一些必要的初始化工作 */
  if (__builtin_expect(preinit_array != NULL, 0) && preinit_array_size != NULL    // 如果存在预初始化数组
      && (i = preinit_array_size->d_un.d_val / sizeof(ElfW(Addr))) > 0)           // 遍历预初始化数组
  {
    ElfW(Addr) * addrs;
    unsigned int cnt;

    if (__glibc_unlikely(GLRO(dl_debug_mask) & DL_DEBUG_IMPCALLS))  // 如果设置了 DL_DEBUG_IMPCALLS 标志，则打印调试信息
      _dl_debug_printf("\ncalling preinit: %s\n\n",
                       DSO_FILENAME(main_map->l_name));

    addrs = (ElfW(Addr) *)(preinit_array->d_un.d_ptr + main_map->l_addr); // 获取预初始化数组的地址
    for (cnt = 0; cnt < i; ++cnt)
      ((dl_init_t)addrs[cnt])(argc, argv, env);   // 遍历函数指针数组，调用其中的初始化函数
  }

  /* Stupid users forced the ELF specification to be changed.  It now
     says that the dynamic loader is responsible for determining the
     order in which the constructors have to run.  The constructors
     for all dependencies of an object must run before the constructor
     for the object itself.  Circular dependencies are left unspecified.

     This is highly questionable since it puts the burden on the dynamic
     loader which has to find the dependencies at runtime instead of
     letting the user do it right.  Stupidity rules!  */
  /* 愚蠢的用户迫使 ELF 规范被修改。现在规范中说动态加载器负责确定构造函数的运行顺序。
      对象的所有依赖项的构造函数必须在对象本身的构造函数之前运行。循环依赖未指定。

      这是非常可疑的，因为它将负担放在了动态加载器上，动态加载器必须在运行时找到依赖项，
      而不是让用户做正确的事情。愚蠢的规则！ */

  i = main_map->l_searchlist.r_nlist;
  while (i-- > 0)
    call_init(main_map->l_initfini[i], argc, argv, env);

#ifndef HAVE_INLINED_SYSCALLS
  /* Finished starting up.  */
  // 设置全局变量 GL(dl_starting_up) 为 0，表示动态链接器已经启动完成
  // 此后若有新的动态链接库被加载，就不会再调用 _dl_init 函数了
  _dl_starting_up = 0;
#endif
}
