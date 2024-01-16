/* Support for reading /etc/ld.so.cache files written by Linux ldconfig.
   Copyright (C) 1996-2022 Free Software Foundation, Inc.
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
#include <unistd.h>
#include <ldsodefs.h>
#include <sys/mman.h>
#include <dl-cache.h>
#include <dl-procinfo.h>
#include <stdint.h>
#include <_itoa.h>
#include <dl-hwcaps.h>
#include <dl-isa-level.h>
#include <fcntl.h>
#include <sysdep.h>
#include <not-errno.h>

#ifndef _DL_PLATFORMS_COUNT
#define _DL_PLATFORMS_COUNT 0
#endif

/* This is the starting address and the size of the mmap()ed file.  */
static struct cache_file *cache;
static struct cache_file_new *cache_new;
static size_t cachesize;

#ifdef SHARED
/* This is used to cache the priorities of glibc-hwcaps
   subdirectories.  The elements of _dl_cache_priorities correspond to
   the strings in the cache_extension_tag_glibc_hwcaps section.  */
static uint32_t *glibc_hwcaps_priorities;
static uint32_t glibc_hwcaps_priorities_length;
static uint32_t glibc_hwcaps_priorities_allocated;

/* True if the full malloc was used to allocated the array.  */
static bool glibc_hwcaps_priorities_malloced;

/* Deallocate the glibc_hwcaps_priorities array.  */
static void
glibc_hwcaps_priorities_free(void)
{
	/* When the minimal malloc is in use, free does not do anything,
	   so it does not make sense to call it.  */
	if (glibc_hwcaps_priorities_malloced)
		free(glibc_hwcaps_priorities);
	glibc_hwcaps_priorities = NULL;
	glibc_hwcaps_priorities_allocated = 0;
}

/* Ordered comparison of a hwcaps string from the cache on the left
   (identified by its string table index) and a _dl_hwcaps_priorities
   element on the right.  */
static int
glibc_hwcaps_compare(uint32_t left_index, struct dl_hwcaps_priority *right)
{
	const char *left_name = (const char *)cache + left_index;
	uint32_t left_name_length = strlen(left_name);
	uint32_t to_compare;
	if (left_name_length < right->name_length)
		to_compare = left_name_length;
	else
		to_compare = right->name_length;
	int cmp = memcmp(left_name, right->name, to_compare);
	if (cmp != 0)
		return cmp;
	if (left_name_length < right->name_length)
		return -1;
	else if (left_name_length > right->name_length)
		return 1;
	else
		return 0;
}

/* Initialize the glibc_hwcaps_priorities array and its length,
   glibc_hwcaps_priorities_length.  */
static void
glibc_hwcaps_priorities_init(void)
{
	struct cache_extension_all_loaded ext;
	if (!cache_extension_load(cache_new, cache, cachesize, &ext))
		return;

	uint32_t length = (ext.sections[cache_extension_tag_glibc_hwcaps].size / sizeof(uint32_t));
	if (length > glibc_hwcaps_priorities_allocated)
	{
		glibc_hwcaps_priorities_free();

		uint32_t *new_allocation = malloc(length * sizeof(uint32_t));
		if (new_allocation == NULL)
			/* This effectively disables hwcaps on memory allocation
			   errors.  */
			return;

		glibc_hwcaps_priorities = new_allocation;
		glibc_hwcaps_priorities_allocated = length;
		glibc_hwcaps_priorities_malloced = __rtld_malloc_is_complete();
	}

	/* Compute the priorities for the subdirectories by merging the
	   array in the cache with the dl_hwcaps_priorities array.  */
	const uint32_t *left = ext.sections[cache_extension_tag_glibc_hwcaps].base;
	const uint32_t *left_end = left + length;
	struct dl_hwcaps_priority *right = _dl_hwcaps_priorities;
	struct dl_hwcaps_priority *right_end = right + _dl_hwcaps_priorities_length;
	uint32_t *result = glibc_hwcaps_priorities;

	while (left < left_end && right < right_end)
	{
		if (*left < cachesize)
		{
			int cmp = glibc_hwcaps_compare(*left, right);
			if (cmp == 0)
			{
				*result = right->priority;
				++result;
				++left;
				++right;
			}
			else if (cmp < 0)
			{
				*result = 0;
				++result;
				++left;
			}
			else
				++right;
		}
		else
		{
			*result = 0;
			++result;
		}
	}
	while (left < left_end)
	{
		*result = 0;
		++result;
		++left;
	}

	glibc_hwcaps_priorities_length = length;
}

/* Return the priority of the cache_extension_tag_glibc_hwcaps section
   entry at INDEX.  Zero means do not use.  Otherwise, lower values
   indicate greater preference.  */
static uint32_t
glibc_hwcaps_priority(uint32_t index)
{
	/* This does not need to repeated initialization attempts because
	   this function is only called if there is glibc-hwcaps data in the
	   cache, so the first call initializes the glibc_hwcaps_priorities
	   array.  */
	if (glibc_hwcaps_priorities_length == 0)
		glibc_hwcaps_priorities_init();

	if (index < glibc_hwcaps_priorities_length)
		return glibc_hwcaps_priorities[index];
	else
		return 0;
}
#endif /* SHARED */

/* True if PTR is a valid string table index.  */
static inline bool
_dl_cache_verify_ptr(uint32_t ptr, size_t string_table_size)
{
	return ptr < string_table_size;
}

/* Compute the address of the element INDEX of the array at LIBS.
   Conceptually, this is &LIBS[INDEX], but use ENTRY_SIZE for the size
   of *LIBS.  */
static inline const struct file_entry *
_dl_cache_file_entry(const struct file_entry *libs, size_t entry_size,
					 size_t index)
{
	return (const void *)libs + index * entry_size;
}

/* We use binary search since the table is sorted in the cache file.
   The first matching entry in the table is returned.  It is important
   to use the same algorithm as used while generating the cache file.
   STRING_TABLE_SIZE indicates the maximum offset in STRING_TABLE at
   which data is mapped; it is not exact.  */
/* 我们使用二分查找，因为表在缓存文件中是排序的。返回表中的第一个匹配项。
	使用与生成缓存文件时使用的相同算法很重要。STRING_TABLE_SIZE 指示在 STRING_TABLE 中
	映射数据的最大偏移量；它不是精确的。 */
// ld.so.cache文件包含了所有的共享库的信息，包括共享库的名称、路径、版本、哈希值等等，不包含共享库的内容。
static const char *
search_cache(const char *string_table, uint32_t string_table_size,
			 struct file_entry *libs, uint32_t nlibs, uint32_t entry_size,
			 const char *name)
{
	/* Used by the HWCAP check in the struct file_entry_new case.  */
	uint64_t platform = _dl_string_platform(GLRO(dl_platform));
	int disable_hwcap = 0;
	if (platform != (uint64_t)-1)
		platform = 1ULL << platform;
	uint64_t hwcap_mask = GET_HWCAP_MASK();
#ifdef NEED_LD_SO_NOHWCAP
	if (__access_noerrno("/etc/ld.so.nohwcap", F_OK) == 0)
		disable_hwcap = 1;
#endif
#define _DL_HWCAP_TLS_MASK (1LL << 63)
	uint64_t hwcap_exclude = ~((GLRO(dl_hwcap) & hwcap_mask) | _DL_HWCAP_PLATFORM | _DL_HWCAP_TLS_MASK);

	int left = 0;
	int right = nlibs - 1;
	const char *best = NULL;
#ifdef SHARED
	uint32_t best_priority = 0;
#endif

	while (left <= right)
	{
		int middle = (left + right) / 2;
		uint32_t key = _dl_cache_file_entry(libs, entry_size, middle)->key;

		/* Make sure string table indices are not bogus before using
	   them.  */
		if (!_dl_cache_verify_ptr(key, string_table_size))
			return NULL;

		/* Actually compare the entry with the key.  */
		int cmpres = _dl_cache_libcmp(name, string_table + key);
		if (__glibc_unlikely(cmpres == 0))
		{
			/* Found it.  LEFT now marks the last entry for which we
			   know the name is correct.  */
			left = middle;

			/* There might be entries with this name before the one we
			   found.  So we have to find the beginning.  */
			while (middle > 0)
			{
				key = _dl_cache_file_entry(libs, entry_size, middle - 1)->key;
				/* Make sure string table indices are not bogus before
			   using them.  */
				if (!_dl_cache_verify_ptr(key, string_table_size)
					/* Actually compare the entry.  */
					|| _dl_cache_libcmp(name, string_table + key) != 0)
					break;
				--middle;
			}

			do
			{
				int flags;
				const struct file_entry *lib = _dl_cache_file_entry(libs, entry_size, middle);

				/* Only perform the name test if necessary.  */
				if (middle > left
					/* We haven't seen this string so far.  Test whether the
					   index is ok and whether the name matches.  Otherwise
					   we are done.  */
					&& (!_dl_cache_verify_ptr(lib->key, string_table_size) || (_dl_cache_libcmp(name, string_table + lib->key) != 0)))
					break;

				flags = lib->flags;
				if (_dl_cache_check_flags(flags) && _dl_cache_verify_ptr(lib->value, string_table_size))
				{
					/* Named/extension hwcaps get slightly different
					   treatment: We keep searching for a better
					   match.  */
					bool named_hwcap = false;

					if (entry_size >= sizeof(struct file_entry_new))
					{
						/* The entry is large enough to include
					   HWCAP data.  Check it.  */
						struct file_entry_new *libnew = (struct file_entry_new *)lib;

#ifdef SHARED
						named_hwcap = dl_cache_hwcap_extension(libnew);
						if (named_hwcap && !dl_cache_hwcap_isa_level_compatible(libnew))
							continue;
#endif

						/* The entries with named/extension hwcaps have
					   been exhausted (they are listed before all
					   other entries).  Return the best match
					   encountered so far if there is one.  */
						if (!named_hwcap && best != NULL)
							break;

						if ((libnew->hwcap & hwcap_exclude) && !named_hwcap)
							continue;
						if (GLRO(dl_osversion) && libnew->osversion > GLRO(dl_osversion))
							continue;
						if (disable_hwcap && libnew->hwcap != 0)
							continue;
						if (_DL_PLATFORMS_COUNT && (libnew->hwcap & _DL_HWCAP_PLATFORM) != 0 && ((libnew->hwcap & _DL_HWCAP_PLATFORM) != platform))
							continue;

#ifdef SHARED
						/* For named hwcaps, determine the priority and
					   see if beats what has been found so far.  */
						if (named_hwcap)
						{
							uint32_t entry_priority = glibc_hwcaps_priority(libnew->hwcap);
							if (entry_priority == 0)
								/* Not usable at all.  Skip.  */
								continue;
							else if (best == NULL || entry_priority < best_priority)
								/* This entry is of higher priority
								   than the previous one, or it is the
								   first entry.  */
								best_priority = entry_priority;
							else
								/* An entry has already been found,
								   but it is a better match.  */
								continue;
						}
#endif /* SHARED */
					}

					best = string_table + lib->value;

					if (!named_hwcap && flags == _DL_CACHE_DEFAULT_ID)
						/* With named hwcaps, we need to keep searching to
						   see if we find a better match.  A better match
						   is also possible if the flags of the current
						   entry do not match the expected cache flags.
						   But if the flags match, no better entry will be
						   found.  */
						break;
				}
			} while (++middle <= right);
			break;
		}

		if (cmpres < 0)
			left = middle + 1;
		else
			right = middle - 1;
	}

	return best;
}

int _dl_cache_libcmp(const char *p1, const char *p2)
{
	while (*p1 != '\0')
	{
		if (*p1 >= '0' && *p1 <= '9')
		{
			if (*p2 >= '0' && *p2 <= '9')
			{
				/* Must compare this numerically.  */
				int val1;
				int val2;

				val1 = *p1++ - '0';
				val2 = *p2++ - '0';
				while (*p1 >= '0' && *p1 <= '9')
					val1 = val1 * 10 + *p1++ - '0';
				while (*p2 >= '0' && *p2 <= '9')
					val2 = val2 * 10 + *p2++ - '0';
				if (val1 != val2)
					return val1 - val2;
			}
			else
				return 1;
		}
		else if (*p2 >= '0' && *p2 <= '9')
			return -1;
		else if (*p1 != *p2)
			return *p1 - *p2;
		else
		{
			++p1;
			++p2;
		}
	}
	return *p1 - *p2;
}

/* Look up NAME in ld.so.cache and return the file name stored there, or null
   if none is found.  The cache is loaded if it was not already.  If loading
   the cache previously failed there will be no more attempts to load it.
   The caller is responsible for freeing the returned string.  The ld.so.cache
   may be unmapped at any time by a completing recursive dlopen and
   this function must take care that it does not return references to
   any data in the mapping.  */
/* 在 ld.so.cache 中查找 NAME 并返回存储在其中的文件名，如果没有找到则返回 null。
   如果之前加载缓存失败，则不会再尝试加载。调用者负责释放返回的字符串。
   ld.so.cache 可以随时被递归 dlopen 完成卸载，该函数必须确保它不会返回对映射中任何数据的引用。 */
char *
_dl_load_cache_lookup(const char *name)
{
	/* Print a message if the loading of libs is traced.  */
	/* 如果跟踪加载 libs，则打印消息。 */
	if (__glibc_unlikely(GLRO(dl_debug_mask) & DL_DEBUG_LIBS))
		_dl_debug_printf(" search cache=%s\n", LD_SO_CACHE);

	if (cache == NULL)
	{
		/* Read the contents of the file.  */
		// 读取文件的内容
		void *file = _dl_sysdep_read_whole_file(LD_SO_CACHE, &cachesize,	// 读取ld.so.cache文件并映射到内存，返回映射的起始地址
												PROT_READ);

		/* We can handle three different cache file formats here:
	   - only the new format
	   - the old libc5/glibc2.0/2.1 format
	   - the old format with the new format in it
	   The following checks if the cache contains any of these formats.  */
		// 我们可以在这里处理三种不同的缓存文件格式：
		// - 仅新格式
		// - 旧的 libc5/glibc2.0/2.1 格式
		// - 旧格式中包含新格式
		// 以下检查缓存是否包含其中任何格式。
		if (file != MAP_FAILED && cachesize > sizeof *cache_new && memcmp(file, CACHEMAGIC_VERSION_NEW, sizeof CACHEMAGIC_VERSION_NEW - 1) == 0
			/* Check for corruption, avoiding overflow.  */
			/* 检查是否损坏，避免溢出。 */
			&& ((cachesize - sizeof *cache_new) / sizeof(struct file_entry_new) >= ((struct cache_file_new *)file)->nlibs))
		{
			if (!cache_file_new_matches_endian(file))		// 检查字节序是否匹配
			{
				__munmap(file, cachesize);
				file = (void *)-1;
			}
			cache_new = file;
			cache = file;							// cache指向映射的起始地址
		}
		else if (file != MAP_FAILED && cachesize > sizeof *cache && memcmp(file, CACHEMAGIC, sizeof CACHEMAGIC - 1) == 0
				 /* Check for corruption, avoiding overflow.  */
				 /* 检查是否损坏，避免溢出。 */
				 && ((cachesize - sizeof *cache) / sizeof(struct file_entry) >= ((struct cache_file *)file)->nlibs))
		{
			size_t offset;
			/* Looks ok.  */	/* 看起来没问题。 */
			cache = file;

			/* Check for new version.  */
			/* 检查新版本。 */
			offset = ALIGN_CACHE(sizeof(struct cache_file) + cache->nlibs * sizeof(struct file_entry));

			cache_new = (struct cache_file_new *)((void *)cache + offset);
			if (cachesize < (offset + sizeof(struct cache_file_new)) || memcmp(cache_new->magic, CACHEMAGIC_VERSION_NEW,
																			   sizeof CACHEMAGIC_VERSION_NEW - 1) != 0)
				cache_new = (void *)-1;
			else
			{
				if (!cache_file_new_matches_endian(cache_new))
				{
					/* The old-format part of the cache is bogus as well
					   if the endianness does not match.  (But it is
					   unclear how the new header can be located if the
					   endianess does not match.)  */
					/* 如果字节顺序不匹配，则缓存的旧格式部分也是错误的。
					   （但是如果字节顺序不匹配，则不清楚如何定位新标题。） */
					cache = (void *)-1;
					cache_new = (void *)-1;
					__munmap(file, cachesize);
				}
			}
		}
		else
		{
			if (file != MAP_FAILED)
				__munmap(file, cachesize);
			cache = (void *)-1;
		}

		assert(cache != NULL);
	}

	if (cache == (void *)-1)
		/* Previously looked for the cache file and didn't find it.  */
		/* 之前查找缓存文件并没有找到它。 */
		return NULL;

	const char *best;
	if (cache_new != (void *)-1)
	{
		const char *string_table = (const char *)cache_new;
		best = search_cache(string_table, cachesize,					// 调用search_cache函数查找name
							&cache_new->libs[0].entry, cache_new->nlibs,
							sizeof(cache_new->libs[0]), name);
	}
	else
	{
		const char *string_table = (const char *)&cache->libs[cache->nlibs];
		uint32_t string_table_size = (const char *)cache + cachesize - string_table;
		best = search_cache(string_table, string_table_size,
							&cache->libs[0], cache->nlibs,
							sizeof(cache->libs[0]), name);
	}

	/* Print our result if wanted.  */
	/* 如果需要，打印我们的结果。 */
	if (__builtin_expect(GLRO(dl_debug_mask) & DL_DEBUG_LIBS, 0) && best != NULL)
		_dl_debug_printf("  trying file=%s\n", best);

	if (best == NULL)
		return NULL;

	/* The double copy is *required* since malloc may be interposed
	   and call dlopen itself whose completion would unmap the data
	   we are accessing. Therefore we must make the copy of the
	   mapping data without using malloc.  */
	/* 双重复制是必需的，因为 malloc 可能会被插入并调用 dlopen 本身，
		完成会取消映射我们正在访问的数据。因此，我们必须在不使用 malloc 的情况下对映射数据进行复制。 */
	char *temp;
	temp = alloca(strlen(best) + 1);
	strcpy(temp, best);
	return __strdup(temp);
}

#ifndef MAP_COPY
/* If the system does not support MAP_COPY we cannot leave the file open
   all the time since this would create problems when the file is replaced.
   Therefore we provide this function to close the file and open it again
   once needed.  */
/* 如果系统不支持 MAP_COPY，则不能一直保持文件打开状态，因为这会在文件被替换时创建问题。
	 因此，我们提供此函数来关闭文件，一旦需要就重新打开它。 */
void _dl_unload_cache(void)
{
	if (cache != NULL && cache != (struct cache_file *)-1)
	{
		__munmap(cache, cachesize);
		cache = NULL;
	}
#ifdef SHARED
	/* This marks the glibc_hwcaps_priorities array as out-of-date.  */
	/* 这将 glibc_hwcaps_priorities 数组标记为过时。 */
	glibc_hwcaps_priorities_length = 0;
#endif
}
#endif
