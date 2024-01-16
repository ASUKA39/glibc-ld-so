/* Call the termination functions of loaded shared objects.
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
#include <string.h>
#include <ldsodefs.h>
#include <elf-initfini.h>

/* Type of the constructor functions.  */
/* 构造函数的类型。 */
typedef void (*fini_t)(void);

void _dl_fini(void)
{
	/* Lots of fun ahead.  We have to call the destructors for all still
	   loaded objects, in all namespaces.  The problem is that the ELF
	   specification now demands that dependencies between the modules
	   are taken into account.  I.e., the destructor for a module is
	   called before the ones for any of its dependencies.

	   To make things more complicated, we cannot simply use the reverse
	   order of the constructors.  Since the user might have loaded objects
	   using `dlopen' there are possibly several other modules with its
	   dependencies to be taken into account.  Therefore we have to start
	   determining the order of the modules once again from the beginning.  */
	/* 我们必须在所有命名空间中调用所有仍然加载的对象的析构函数。
	   问题是 ELF 规范现在要求考虑模块之间的依赖关系。
	   也就是说，模块的析构函数在其任何依赖项的析构函数之前被调用。

	   为了使事情更加复杂，我们不能简单地使用构造函数的反向顺序。
	   由于用户可能使用 `dlopen' 加载对象，因此可能有几个其他模块及其依赖项需要考虑。
	   因此，我们必须从头开始再次确定模块的顺序。 */
	/* We run the destructors of the main namespaces last.  As for the
	   other namespaces, we pick run the destructors in them in reverse
	   order of the namespace ID.  */
	/* 我们最后运行主命名空间的析构函数。至于其他命名空间，我们选择以命名空间 ID 的反向顺序运行其中的析构函数。 */
#ifdef SHARED
	int do_audit = 0;
again:
#endif
	for (Lmid_t ns = GL(dl_nns) - 1; ns >= 0; --ns)
	{
		/* Protect against concurrent loads and unloads.  */
		/* 防止并发加载和卸载。 */
		__rtld_lock_lock_recursive(GL(dl_load_lock));

		unsigned int nloaded = GL(dl_ns)[ns]._ns_nloaded;
		/* No need to do anything for empty namespaces or those used for
	   auditing DSOs.  */
	   	/* 对于空命名空间或用于审核 DSO 的命名空间，无需执行任何操作。 */
		if (nloaded == 0
#ifdef SHARED
			|| GL(dl_ns)[ns]._ns_loaded->l_auditing != do_audit
#endif
		)
			__rtld_lock_unlock_recursive(GL(dl_load_lock));
		else
		{
#ifdef SHARED
			_dl_audit_activity_nsid(ns, LA_ACT_DELETE);
#endif

			/* Now we can allocate an array to hold all the pointers and
			   copy the pointers in.  */
			/* 现在我们可以分配一个数组来保存所有指针并将指针复制到其中。 */
			struct link_map *maps[nloaded];

			unsigned int i;
			struct link_map *l;
			assert(nloaded != 0 || GL(dl_ns)[ns]._ns_loaded == NULL);
			for (l = GL(dl_ns)[ns]._ns_loaded, i = 0; l != NULL; l = l->l_next)
				/* Do not handle ld.so in secondary namespaces.  */
				/* 不要在次要命名空间中处理 ld.so。 */
				if (l == l->l_real)
				{
					assert(i < nloaded);

					maps[i] = l;
					l->l_idx = i;
					++i;

					/* Bump l_direct_opencount of all objects so that they
					   are not dlclose()ed from underneath us.  */
					/* 增加所有对象的 l_direct_opencount，以便它们不会从我们下面的 dlclose()。 */
					++l->l_direct_opencount;
				}
			assert(ns != LM_ID_BASE || i == nloaded);
			assert(ns == LM_ID_BASE || i == nloaded || i == nloaded - 1);
			unsigned int nmaps = i;

			/* Now we have to do the sorting.  We can skip looking for the
			   binary itself which is at the front of the search list for
			   the main namespace.  */
			/* 现在我们必须进行排序。我们可以跳过查找二进制文件本身，它位于主命名空间的搜索列表的前面。 */
			_dl_sort_maps(maps, nmaps, (ns == LM_ID_BASE), true);

			/* We do not rely on the linked list of loaded object anymore
			   from this point on.  We have our own list here (maps).  The
			   various members of this list cannot vanish since the open
			   count is too high and will be decremented in this loop.  So
			   we release the lock so that some code which might be called
			   from a destructor can directly or indirectly access the
			   lock.  */
			/* 从这一点开始，我们不再依赖于已加载对象的链接列表。我们在这里有自己的列表（maps）。
			   该列表的各个成员不能消失，因为打开计数太高，并且将在此循环中递减。
			   因此，我们释放锁，以便某些可能从析构函数调用的代码可以直接或间接地访问锁。 */
			__rtld_lock_unlock_recursive(GL(dl_load_lock));

			/* 'maps' now contains the objects in the right order.  Now
			   call the destructors.  We have to process this array from
			   the front.  */
			/* 'maps' 现在包含正确顺序的对象。现在调用析构函数。我们必须从前面处理此数组。 */
			for (i = 0; i < nmaps; ++i)
			{
				struct link_map *l = maps[i];

				if (l->l_init_called)
				{
					/* Make sure nothing happens if we are called twice.  */
					/* 确保我们被调用两次时不会发生任何事情。 */
					l->l_init_called = 0;

					/* Is there a destructor function?  */
					/* 有析构函数吗？ */
					if (l->l_info[DT_FINI_ARRAY] != NULL || (ELF_INITFINI && l->l_info[DT_FINI] != NULL))
					{
						/* When debugging print a message first.  */
						/* 调试时先打印一条消息。 */
						if (__builtin_expect(GLRO(dl_debug_mask) & DL_DEBUG_IMPCALLS, 0))
							_dl_debug_printf("\ncalling fini: %s [%lu]\n\n",
											 DSO_FILENAME(l->l_name),
											 ns);

						/* First see whether an array is given.  */
						/* 首先看看是否给出了一个数组。 */
						if (l->l_info[DT_FINI_ARRAY] != NULL)
						{
							ElfW(Addr) *array =
								(ElfW(Addr) *)(l->l_addr + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
							unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val / sizeof(ElfW(Addr)));
							while (i-- > 0)
								((fini_t)array[i])();
						}

						/* Next try the old-style destructor.  */
						/* 接下来尝试旧式析构函数。 */
						if (ELF_INITFINI && l->l_info[DT_FINI] != NULL)
							DL_CALL_DT_FINI(l, l->l_addr + l->l_info[DT_FINI]->d_un.d_ptr);
					}

#ifdef SHARED
					/* Auditing checkpoint: another object closed.  */
					/* 审计检查点：另一个对象关闭。 */
					_dl_audit_objclose(l);
#endif
				}

				/* Correct the previous increment.  */
				/* 纠正先前的增量。 */
				--l->l_direct_opencount;
			}

#ifdef SHARED
			_dl_audit_activity_nsid(ns, LA_ACT_CONSISTENT);
#endif
		}
	}

#ifdef SHARED
	if (!do_audit && GLRO(dl_naudit) > 0)
	{
		do_audit = 1;
		goto again;
	}

	if (__glibc_unlikely(GLRO(dl_debug_mask) & DL_DEBUG_STATISTICS))
		_dl_debug_printf("\nruntime linker statistics:\n"
						 "           final number of relocations: %lu\n"
						 "final number of relocations from cache: %lu\n",
						 GL(dl_num_relocations),
						 GL(dl_num_cache_relocations));
#endif
}
