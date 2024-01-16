/* Map in a shared object's segments from the file.
   Copyright (C) 1995-2022 Free Software Foundation, Inc.
   Copyright The GNU Toolchain Authors.
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

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ldsodefs.h>
#include <bits/wordsize.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gnu/lib-names.h>

/* Type for the buffer we put the ELF header and hopefully the program
   header.  This buffer does not really have to be too large.  In most
   cases the program header follows the ELF header directly.  If this
   is not the case all bets are off and we can make the header
   arbitrarily large and still won't get it read.  This means the only
   question is how large are the ELF and program header combined.  The
   ELF header 32-bit files is 52 bytes long and in 64-bit files is 64
   bytes long.  Each program header entry is again 32 and 56 bytes
   long respectively.  I.e., even with a file which has 10 program
   header entries we only have to read 372B/624B respectively.  Add to
   this a bit of margin for program notes and reading 512B and 832B
   for 32-bit and 64-bit files respecitvely is enough.  If this
   heuristic should really fail for some file the code in
   `_dl_map_object_from_fd' knows how to recover.  */
/* 用于存放 ELF 头和程序头的缓冲区。这个缓冲区不需要太大。在大多数情况下，程序头直接跟在 ELF 头后面。
   如果不是这种情况，那么我们可以任意增大缓冲区的大小，但是仍然无法读取到程序头。这意味着唯一的问题是 ELF
   头和程序头的大小。32位文件的 ELF 头长度为 52 字节，64位文件的 ELF 头长度为 64 字节。每个程序头条目
   的长度分别为 32 和 56 字节。也就是说，即使文件有 10 个程序头条目，我们也只需要读取 372B/624B。再加上一些
   程序注释，32位和64位文件分别读取 512B 和 832B 就足够了。如果这种启发式方法真的对某些文件失效了，那么
   `_dl_map_object_from_fd' 中的代码就知道如何恢复了。 */
struct filebuf
{
	ssize_t len;
#if __WORDSIZE == 32
#define FILEBUF_SIZE 512
#else
#define FILEBUF_SIZE 832
#endif
	char buf[FILEBUF_SIZE] __attribute__((aligned(__alignof(ElfW(Ehdr)))));
};

#include "dynamic-link.h"
#include "get-dynamic-info.h"
#include <abi-tag.h>
#include <stackinfo.h>
#include <sysdep.h>
#include <stap-probe.h>
#include <libc-pointer-arith.h>
#include <array_length.h>

#include <dl-dst.h>
#include <dl-load.h>
#include <dl-map-segments.h>
#include <dl-unmap-segments.h>
#include <dl-machine-reject-phdr.h>
#include <dl-sysdep-open.h>
#include <dl-prop.h>
#include <not-cancel.h>

#include <endian.h>
#if BYTE_ORDER == BIG_ENDIAN
#define byteorder ELFDATA2MSB
#elif BYTE_ORDER == LITTLE_ENDIAN
#define byteorder ELFDATA2LSB
#else
#error "Unknown BYTE_ORDER " BYTE_ORDER
#define byteorder ELFDATANONE
#endif

#define STRING(x) __STRING(x)

int __stack_prot attribute_hidden attribute_relro
#if _STACK_GROWS_DOWN && defined PROT_GROWSDOWN
	= PROT_GROWSDOWN;
#elif _STACK_GROWS_UP && defined PROT_GROWSUP
	= PROT_GROWSUP;
#else
	= 0;
#endif

/* This is the decomposed LD_LIBRARY_PATH search path.  */
struct r_search_path_struct __rtld_env_path_list attribute_relro;

/* List of the hardware capabilities we might end up using.  */
#ifdef SHARED
static const struct r_strlenpair *capstr attribute_relro;
static size_t ncapstr attribute_relro;
static size_t max_capstrlen attribute_relro;
#else
enum
{
	ncapstr = 1,
	max_capstrlen = 0
};
#endif

/* Get the generated information about the trusted directories.  Use
   an array of concatenated strings to avoid relocations.  See
   gen-trusted-dirs.awk.  */
#include "trusted-dirs.h"

static const char system_dirs[] = SYSTEM_DIRS;
static const size_t system_dirs_len[] =
	{
		SYSTEM_DIRS_LEN};
#define nsystem_dirs_len array_length(system_dirs_len)

static bool
is_trusted_path_normalize(const char *path, size_t len)
{
	if (len == 0)
		return false;

	char *npath = (char *)alloca(len + 2);
	char *wnp = npath;
	while (*path != '\0')
	{
		if (path[0] == '/')
		{
			if (path[1] == '.')
			{
				if (path[2] == '.' && (path[3] == '/' || path[3] == '\0'))
				{
					while (wnp > npath && *--wnp != '/')
						;
					path += 3;
					continue;
				}
				else if (path[2] == '/' || path[2] == '\0')
				{
					path += 2;
					continue;
				}
			}

			if (wnp > npath && wnp[-1] == '/')
			{
				++path;
				continue;
			}
		}

		*wnp++ = *path++;
	}

	if (wnp == npath || wnp[-1] != '/')
		*wnp++ = '/';

	const char *trun = system_dirs;

	for (size_t idx = 0; idx < nsystem_dirs_len; ++idx)
	{
		if (wnp - npath >= system_dirs_len[idx] && memcmp(trun, npath, system_dirs_len[idx]) == 0)
			/* Found it.  */
			return true;

		trun += system_dirs_len[idx] + 1;
	}

	return false;
}

/* Given a substring starting at INPUT, just after the DST '$' start
   token, determine if INPUT contains DST token REF, following the
   ELF gABI rules for DSTs:

   * Longest possible sequence using the rules (greedy).

   * Must start with a $ (enforced by caller).

   * Must follow $ with one underscore or ASCII [A-Za-z] (caller
	 follows these rules for REF) or '{' (start curly quoted name).

   * Must follow first two characters with zero or more [A-Za-z0-9_]
	 (enforced by caller) or '}' (end curly quoted name).

   If the sequence is a DST matching REF then the length of the DST
   (excluding the $ sign but including curly braces, if any) is
   returned, otherwise 0.  */
static size_t
is_dst(const char *input, const char *ref)
{
	bool is_curly = false;

	/* Is a ${...} input sequence?  */
	if (input[0] == '{')
	{
		is_curly = true;
		++input;
	}

	/* Check for matching name, following closing curly brace (if
	   required), or trailing characters which are part of an
	   identifier.  */
	size_t rlen = strlen(ref);
	if (strncmp(input, ref, rlen) != 0 || (is_curly && input[rlen] != '}') || ((input[rlen] >= 'A' && input[rlen] <= 'Z') || (input[rlen] >= 'a' && input[rlen] <= 'z') || (input[rlen] >= '0' && input[rlen] <= '9') || (input[rlen] == '_')))
		return 0;

	if (is_curly)
		/* Count the two curly braces.  */
		return rlen + 2;
	else
		return rlen;
}

/* INPUT should be the start of a path e.g DT_RPATH or name e.g.
   DT_NEEDED.  The return value is the number of known DSTs found.  We
   count all known DSTs regardless of __libc_enable_secure; the caller
   is responsible for enforcing the security of the substitution rules
   (usually _dl_dst_substitute).  */
size_t
_dl_dst_count(const char *input)
{
	size_t cnt = 0;

	input = strchr(input, '$');

	/* Most likely there is no DST.  */
	if (__glibc_likely(input == NULL))
		return 0;

	do
	{
		size_t len;

		++input;
		/* All DSTs must follow ELF gABI rules, see is_dst ().  */
		if ((len = is_dst(input, "ORIGIN")) != 0 || (len = is_dst(input, "PLATFORM")) != 0 || (len = is_dst(input, "LIB")) != 0)
			++cnt;

		/* There may be more than one DST in the input.  */
		input = strchr(input + len, '$');
	} while (input != NULL);

	return cnt;
}

/* Process INPUT for DSTs and store in RESULT using the information
   from link map L to resolve the DSTs. This function only handles one
   path at a time and does not handle colon-separated path lists (see
   fillin_rpath ()).  Lastly the size of result in bytes should be at
   least equal to the value returned by DL_DST_REQUIRED.  Note that it
   is possible for a DT_NEEDED, DT_AUXILIARY, and DT_FILTER entries to
   have colons, but we treat those as literal colons here, not as path
   list delimeters.  */
char *
_dl_dst_substitute(struct link_map *l, const char *input, char *result)
{
	/* Copy character-by-character from input into the working pointer
	   looking for any DSTs.  We track the start of input and if we are
	   going to check for trusted paths, all of which are part of $ORIGIN
	   handling in SUID/SGID cases (see below).  In some cases, like when
	   a DST cannot be replaced, we may set result to an empty string and
	   return.  */
	char *wp = result;
	const char *start = input;
	bool check_for_trusted = false;

	do
	{
		if (__glibc_unlikely(*input == '$'))
		{
			const char *repl = NULL;
			size_t len;

			++input;
			if ((len = is_dst(input, "ORIGIN")) != 0)
			{
				/* For SUID/GUID programs we normally ignore the path with
			   $ORIGIN in DT_RUNPATH, or DT_RPATH.  However, there is
			   one exception to this rule, and it is:

				 * $ORIGIN appears as the first path element, and is
				   the only string in the path or is immediately
				   followed by a path separator and the rest of the
				   path,

				 and ...

				 * The path is rooted in a trusted directory.

			   This exception allows such programs to reference
			   shared libraries in subdirectories of trusted
			   directories.  The use case is one of general
			   organization and deployment flexibility.
			   Trusted directories are usually such paths as "/lib64"
			   or "/usr/lib64", and the usual RPATHs take the form of
			   [$ORIGIN/../$LIB/somedir].  */
				if (__glibc_unlikely(__libc_enable_secure) && !(input == start + 1 && (input[len] == '\0' || input[len] == '/')))
					repl = (const char *)-1;
				else
					repl = l->l_origin;

				check_for_trusted = (__libc_enable_secure && l->l_type == lt_executable);
			}
			else if ((len = is_dst(input, "PLATFORM")) != 0)
				repl = GLRO(dl_platform);
			else if ((len = is_dst(input, "LIB")) != 0)
				repl = DL_DST_LIB;

			if (repl != NULL && repl != (const char *)-1)
			{
				wp = __stpcpy(wp, repl);
				input += len;
			}
			else if (len != 0)
			{
				/* We found a valid DST that we know about, but we could
				   not find a replacement value for it, therefore we
			   cannot use this path and discard it.  */
				*result = '\0';
				return result;
			}
			else
				/* No DST we recognize.  */
				*wp++ = '$';
		}
		else
		{
			*wp++ = *input++;
		}
	} while (*input != '\0');

	/* In SUID/SGID programs, after $ORIGIN expansion the normalized
	   path must be rooted in one of the trusted directories.  The $LIB
	   and $PLATFORM DST cannot in any way be manipulated by the caller
	   because they are fixed values that are set by the dynamic loader
	   and therefore any paths using just $LIB or $PLATFORM need not be
	   checked for trust, the authors of the binaries themselves are
	   trusted to have designed this correctly.  Only $ORIGIN is tested in
	   this way because it may be manipulated in some ways with hard
	   links.  */
	if (__glibc_unlikely(check_for_trusted) && !is_trusted_path_normalize(result, wp - result))
	{
		*result = '\0';
		return result;
	}

	*wp = '\0';

	return result;
}

/* Return a malloc allocated copy of INPUT with all recognized DSTs
   replaced. On some platforms it might not be possible to determine the
   path from which the object belonging to the map is loaded.  In this
   case the path containing the DST is left out.  On error NULL
   is returned.  */
static char *
expand_dynamic_string_token(struct link_map *l, const char *input)
{
	/* We make two runs over the string.  First we determine how large the
	   resulting string is and then we copy it over.  Since this is no
	   frequently executed operation we are looking here not for performance
	   but rather for code size.  */
	size_t cnt;
	size_t total;
	char *result;

	/* Determine the number of DSTs.  */
	cnt = _dl_dst_count(input);

	/* If we do not have to replace anything simply copy the string.  */
	if (__glibc_likely(cnt == 0))
		return __strdup(input);

	/* Determine the length of the substituted string.  */
	total = DL_DST_REQUIRED(l, input, strlen(input), cnt);

	/* Allocate the necessary memory.  */
	result = (char *)malloc(total + 1);
	if (result == NULL)
		return NULL;

	return _dl_dst_substitute(l, input, result);
}

/* Add `name' to the list of names for a particular shared object.
   `name' is expected to have been allocated with malloc and will
   be freed if the shared object already has this name.
   Returns false if the object already had this name.  */
static void
add_name_to_object(struct link_map *l, const char *name)
{
	struct libname_list *lnp, *lastp;
	struct libname_list *newname;
	size_t name_len;

	lastp = NULL;
	for (lnp = l->l_libname; lnp != NULL; lastp = lnp, lnp = lnp->next)
		if (strcmp(name, lnp->name) == 0)
			return;

	name_len = strlen(name) + 1;
	newname = (struct libname_list *)malloc(sizeof *newname + name_len);
	if (newname == NULL)
	{
		/* No more memory.  */
		_dl_signal_error(ENOMEM, name, NULL, N_("cannot allocate name record"));
		return;
	}
	/* The object should have a libname set from _dl_new_object.  */
	assert(lastp != NULL);

	newname->name = memcpy(newname + 1, name, name_len);
	newname->next = NULL;
	newname->dont_free = 0;
	/* CONCURRENCY NOTES:

	   Make sure the initialization of newname happens before its address is
	   read from the lastp->next store below.

	   GL(dl_load_lock) is held here (and by other writers, e.g. dlclose), so
	   readers of libname_list->next (e.g. _dl_check_caller or the reads above)
	   can use that for synchronization, however the read in _dl_name_match_p
	   may be executed without holding the lock during _dl_runtime_resolve
	   (i.e. lazy symbol resolution when a function of library l is called).

	   The release MO store below synchronizes with the acquire MO load in
	   _dl_name_match_p.  Other writes need to synchronize with that load too,
	   however those happen either early when the process is single threaded
	   (dl_main) or when the library is unloaded (dlclose) and the user has to
	   synchronize library calls with unloading.  */
	atomic_store_release(&lastp->next, newname);
}

/* Standard search directories.  */
struct r_search_path_struct __rtld_search_dirs attribute_relro;

static size_t max_dirnamelen;

static struct r_search_path_elem **
fillin_rpath(char *rpath, struct r_search_path_elem **result, const char *sep,
			 const char *what, const char *where, struct link_map *l)
{
	char *cp;
	size_t nelems = 0;

	while ((cp = __strsep(&rpath, sep)) != NULL)
	{
		struct r_search_path_elem *dirp;
		char *to_free = NULL;
		size_t len = 0;

		/* `strsep' can pass an empty string.  */
		if (*cp != '\0')
		{
			to_free = cp = expand_dynamic_string_token(l, cp);

			/* expand_dynamic_string_token can return NULL in case of empty
			   path or memory allocation failure.  */
			if (cp == NULL)
				continue;

			/* Compute the length after dynamic string token expansion and
			   ignore empty paths.  */
			len = strlen(cp);
			if (len == 0)
			{
				free(to_free);
				continue;
			}

			/* Remove trailing slashes (except for "/").  */
			while (len > 1 && cp[len - 1] == '/')
				--len;

			/* Now add one if there is none so far.  */
			if (len > 0 && cp[len - 1] != '/')
				cp[len++] = '/';
		}

		/* See if this directory is already known.  */
		for (dirp = GL(dl_all_dirs); dirp != NULL; dirp = dirp->next)
			if (dirp->dirnamelen == len && memcmp(cp, dirp->dirname, len) == 0)
				break;

		if (dirp != NULL)
		{
			/* It is available, see whether it's on our own list.  */
			size_t cnt;
			for (cnt = 0; cnt < nelems; ++cnt)
				if (result[cnt] == dirp)
					break;

			if (cnt == nelems)
				result[nelems++] = dirp;
		}
		else
		{
			size_t cnt;
			enum r_dir_status init_val;
			size_t where_len = where ? strlen(where) + 1 : 0;

			/* It's a new directory.  Create an entry and add it.  */
			dirp = (struct r_search_path_elem *)
				malloc(sizeof(*dirp) + ncapstr * sizeof(enum r_dir_status) + where_len + len + 1);
			if (dirp == NULL)
				_dl_signal_error(ENOMEM, NULL, NULL,
								 N_("cannot create cache for search path"));

			dirp->dirname = ((char *)dirp + sizeof(*dirp) + ncapstr * sizeof(enum r_dir_status));
			*((char *)__mempcpy((char *)dirp->dirname, cp, len)) = '\0';
			dirp->dirnamelen = len;

			if (len > max_dirnamelen)
				max_dirnamelen = len;

			/* We have to make sure all the relative directories are
			   never ignored.  The current directory might change and
			   all our saved information would be void.  */
			init_val = cp[0] != '/' ? existing : unknown;
			for (cnt = 0; cnt < ncapstr; ++cnt)
				dirp->status[cnt] = init_val;

			dirp->what = what;
			if (__glibc_likely(where != NULL))
				dirp->where = memcpy((char *)dirp + sizeof(*dirp) + len + 1 + (ncapstr * sizeof(enum r_dir_status)),
									 where, where_len);
			else
				dirp->where = NULL;

			dirp->next = GL(dl_all_dirs);
			GL(dl_all_dirs) = dirp;

			/* Put it in the result array.  */
			result[nelems++] = dirp;
		}
		free(to_free);
	}

	/* Terminate the array.  */
	result[nelems] = NULL;

	return result;
}

static bool
decompose_rpath(struct r_search_path_struct *sps,
				const char *rpath, struct link_map *l, const char *what)
{
	/* Make a copy we can work with.  */
	const char *where = l->l_name;
	char *cp;
	struct r_search_path_elem **result;
	size_t nelems;
	/* Initialize to please the compiler.  */
	const char *errstring = NULL;

	/* First see whether we must forget the RUNPATH and RPATH from this
	   object.  */
	if (__glibc_unlikely(GLRO(dl_inhibit_rpath) != NULL) && !__libc_enable_secure)
	{
		const char *inhp = GLRO(dl_inhibit_rpath);

		do
		{
			const char *wp = where;

			while (*inhp == *wp && *wp != '\0')
			{
				++inhp;
				++wp;
			}

			if (*wp == '\0' && (*inhp == '\0' || *inhp == ':'))
			{
				/* This object is on the list of objects for which the
			   RUNPATH and RPATH must not be used.  */
				sps->dirs = (void *)-1;
				return false;
			}

			while (*inhp != '\0')
				if (*inhp++ == ':')
					break;
		} while (*inhp != '\0');
	}

	/* Ignore empty rpaths.  */
	if (*rpath == '\0')
	{
		sps->dirs = (struct r_search_path_elem **)-1;
		return false;
	}

	/* Make a writable copy.  */
	char *copy = __strdup(rpath);
	if (copy == NULL)
	{
		errstring = N_("cannot create RUNPATH/RPATH copy");
		goto signal_error;
	}

	/* Count the number of necessary elements in the result array.  */
	nelems = 0;
	for (cp = copy; *cp != '\0'; ++cp)
		if (*cp == ':')
			++nelems;

	/* Allocate room for the result.  NELEMS + 1 is an upper limit for the
	   number of necessary entries.  */
	result = (struct r_search_path_elem **)malloc((nelems + 1 + 1) * sizeof(*result));
	if (result == NULL)
	{
		free(copy);
		errstring = N_("cannot create cache for search path");
	signal_error:
		_dl_signal_error(ENOMEM, NULL, NULL, errstring);
	}

	fillin_rpath(copy, result, ":", what, where, l);

	/* Free the copied RPATH string.  `fillin_rpath' make own copies if
	   necessary.  */
	free(copy);

	/* There is no path after expansion.  */
	if (result[0] == NULL)
	{
		free(result);
		sps->dirs = (struct r_search_path_elem **)-1;
		return false;
	}

	sps->dirs = result;
	/* The caller will change this value if we haven't used a real malloc.  */
	sps->malloced = 1;
	return true;
}

/* Make sure cached path information is stored in *SP
   and return true if there are any paths to search there.  */
static bool
cache_rpath(struct link_map *l,
			struct r_search_path_struct *sp,
			int tag,
			const char *what)
{
	if (sp->dirs == (void *)-1)
		return false;

	if (sp->dirs != NULL)
		return true;

	if (l->l_info[tag] == NULL)
	{
		/* There is no path.  */
		sp->dirs = (void *)-1;
		return false;
	}

	/* Make sure the cache information is available.  */
	return decompose_rpath(sp, (const char *)(D_PTR(l, l_info[DT_STRTAB]) + l->l_info[tag]->d_un.d_val),
						   l, what);
}

void _dl_init_paths(const char *llp, const char *source,
					const char *glibc_hwcaps_prepend,
					const char *glibc_hwcaps_mask)
{
	size_t idx;
	const char *strp;
	struct r_search_path_elem *pelem, **aelem;
	size_t round_size;
	struct link_map __attribute__((unused)) *l = NULL;
	/* Initialize to please the compiler.  */
	const char *errstring = NULL;

	/* Fill in the information about the application's RPATH and the
	   directories addressed by the LD_LIBRARY_PATH environment variable.  */

#ifdef SHARED
	/* Get the capabilities.  */
	capstr = _dl_important_hwcaps(glibc_hwcaps_prepend, glibc_hwcaps_mask,
								  &ncapstr, &max_capstrlen);
#endif

	/* First set up the rest of the default search directory entries.  */
	aelem = __rtld_search_dirs.dirs = (struct r_search_path_elem **)
		malloc((nsystem_dirs_len + 1) * sizeof(struct r_search_path_elem *));
	if (__rtld_search_dirs.dirs == NULL)
	{
		errstring = N_("cannot create search path array");
	signal_error:
		_dl_signal_error(ENOMEM, NULL, NULL, errstring);
	}

	round_size = ((2 * sizeof(struct r_search_path_elem) - 1 + ncapstr * sizeof(enum r_dir_status)) / sizeof(struct r_search_path_elem));

	__rtld_search_dirs.dirs[0] = malloc(nsystem_dirs_len * round_size * sizeof(*__rtld_search_dirs.dirs[0]));
	if (__rtld_search_dirs.dirs[0] == NULL)
	{
		errstring = N_("cannot create cache for search path");
		goto signal_error;
	}

	__rtld_search_dirs.malloced = 0;
	pelem = GL(dl_all_dirs) = __rtld_search_dirs.dirs[0];
	strp = system_dirs;
	idx = 0;

	do
	{
		size_t cnt;

		*aelem++ = pelem;

		pelem->what = "system search path";
		pelem->where = NULL;

		pelem->dirname = strp;
		pelem->dirnamelen = system_dirs_len[idx];
		strp += system_dirs_len[idx] + 1;

		/* System paths must be absolute.  */
		assert(pelem->dirname[0] == '/');
		for (cnt = 0; cnt < ncapstr; ++cnt)
			pelem->status[cnt] = unknown;

		pelem->next = (++idx == nsystem_dirs_len ? NULL : (pelem + round_size));

		pelem += round_size;
	} while (idx < nsystem_dirs_len);

	max_dirnamelen = SYSTEM_DIRS_MAX_LEN;
	*aelem = NULL;

	/* This points to the map of the main object.  If there is no main
	   object (e.g., under --help, use the dynamic loader itself as a
	   stand-in.  */
	l = GL(dl_ns)[LM_ID_BASE]._ns_loaded;
#ifdef SHARED
	if (l == NULL)
		l = &GL(dl_rtld_map);
#endif
	assert(l->l_type != lt_loaded);

	if (l->l_info[DT_RUNPATH])
	{
		/* Allocate room for the search path and fill in information
	   from RUNPATH.  */
		decompose_rpath(&l->l_runpath_dirs,
						(const void *)(D_PTR(l, l_info[DT_STRTAB]) + l->l_info[DT_RUNPATH]->d_un.d_val),
						l, "RUNPATH");
		/* During rtld init the memory is allocated by the stub malloc,
	   prevent any attempt to free it by the normal malloc.  */
		l->l_runpath_dirs.malloced = 0;

		/* The RPATH is ignored.  */
		l->l_rpath_dirs.dirs = (void *)-1;
	}
	else
	{
		l->l_runpath_dirs.dirs = (void *)-1;

		if (l->l_info[DT_RPATH])
		{
			/* Allocate room for the search path and fill in information
			   from RPATH.  */
			decompose_rpath(&l->l_rpath_dirs,
							(const void *)(D_PTR(l, l_info[DT_STRTAB]) + l->l_info[DT_RPATH]->d_un.d_val),
							l, "RPATH");
			/* During rtld init the memory is allocated by the stub
			   malloc, prevent any attempt to free it by the normal
			   malloc.  */
			l->l_rpath_dirs.malloced = 0;
		}
		else
			l->l_rpath_dirs.dirs = (void *)-1;
	}

	if (llp != NULL && *llp != '\0')
	{
		char *llp_tmp = strdupa(llp);

		/* Decompose the LD_LIBRARY_PATH contents.  First determine how many
	   elements it has.  */
		size_t nllp = 1;
		for (const char *cp = llp_tmp; *cp != '\0'; ++cp)
			if (*cp == ':' || *cp == ';')
				++nllp;

		__rtld_env_path_list.dirs = (struct r_search_path_elem **)
			malloc((nllp + 1) * sizeof(struct r_search_path_elem *));
		if (__rtld_env_path_list.dirs == NULL)
		{
			errstring = N_("cannot create cache for search path");
			goto signal_error;
		}

		(void)fillin_rpath(llp_tmp, __rtld_env_path_list.dirs, ":;",
						   source, NULL, l);

		if (__rtld_env_path_list.dirs[0] == NULL)
		{
			free(__rtld_env_path_list.dirs);
			__rtld_env_path_list.dirs = (void *)-1;
		}

		__rtld_env_path_list.malloced = 0;
	}
	else
		__rtld_env_path_list.dirs = (void *)-1;
}

/* Process PT_GNU_PROPERTY program header PH in module L after
   PT_LOAD segments are mapped.  Only one NT_GNU_PROPERTY_TYPE_0
   note is handled which contains processor specific properties.
   FD is -1 for the kernel mapped main executable otherwise it is
   the fd used for loading module L.  */

void _dl_process_pt_gnu_property(struct link_map *l, int fd, const ElfW(Phdr) * ph)
{
	const ElfW(Nhdr) *note = (const void *)(ph->p_vaddr + l->l_addr);
	const ElfW(Addr) size = ph->p_memsz;
	const ElfW(Addr) align = ph->p_align;

	/* The NT_GNU_PROPERTY_TYPE_0 note must be aligned to 4 bytes in
	   32-bit objects and to 8 bytes in 64-bit objects.  Skip notes
	   with incorrect alignment.  */
	if (align != (__ELF_NATIVE_CLASS / 8))
		return;

	const ElfW(Addr) start = (ElfW(Addr))note;
	unsigned int last_type = 0;

	while ((ElfW(Addr))(note + 1) - start < size)
	{
		/* Find the NT_GNU_PROPERTY_TYPE_0 note.  */
		if (note->n_namesz == 4 && note->n_type == NT_GNU_PROPERTY_TYPE_0 && memcmp(note + 1, "GNU", 4) == 0)
		{
			/* Check for invalid property.  */
			if (note->n_descsz < 8 || (note->n_descsz % sizeof(ElfW(Addr))) != 0)
				return;

			/* Start and end of property array.  */
			unsigned char *ptr = (unsigned char *)(note + 1) + 4;
			unsigned char *ptr_end = ptr + note->n_descsz;

			do
			{
				unsigned int type = *(unsigned int *)ptr;
				unsigned int datasz = *(unsigned int *)(ptr + 4);

				/* Property type must be in ascending order.  */
				if (type < last_type)
					return;

				ptr += 8;
				if ((ptr + datasz) > ptr_end)
					return;

				last_type = type;

				/* Target specific property processing.  */
				if (_dl_process_gnu_property(l, fd, type, datasz, ptr) == 0)
					return;

				/* Check the next property item.  */
				ptr += ALIGN_UP(datasz, sizeof(ElfW(Addr)));
			} while ((ptr_end - ptr) >= 8);

			/* Only handle one NT_GNU_PROPERTY_TYPE_0.  */
			return;
		}

		note = ((const void *)note + ELF_NOTE_NEXT_OFFSET(note->n_namesz, note->n_descsz,
														  align));
	}
}

/* Map in the shared object NAME, actually located in REALNAME, and already
   opened on FD.  */
/* 将共享对象NAME映射到内存中，实际上位于REALNAME，已经打开在FD上 */
#ifndef EXTERNAL_MAP_FROM_FD
static
#endif
	struct link_map *
	_dl_map_object_from_fd(const char *name, const char *origname, int fd,
						   struct filebuf *fbp, char *realname,
						   struct link_map *loader, int l_type, int mode,
						   void **stack_endp, Lmid_t nsid)
{
	struct link_map *l = NULL;
	const ElfW(Ehdr) * header; // Ehdr ELF文件头
	const ElfW(Phdr) * phdr;   // Phdr ELF程序头
	const ElfW(Phdr) * ph;
	size_t maplength;
	int type;
	/* Initialize to keep the compiler happy.  */
	/* 初始化，编译时少点warning */
	const char *errstring = NULL;
	int errval = 0;
	struct r_debug *r = _dl_debug_update(nsid);
	bool make_consistent = false;

	/* Get file information.  To match the kernel behavior, do not fill
	   in this information for the executable in case of an explicit
	   loader invocation.  */
	/* 获取文件信息。为了匹配内核行为，在显式加载器调用的情况下不要为可执行文件填写此信息。 */
	struct r_file_id id;
	if (mode & __RTLD_OPENEXEC)
	{
		assert(nsid == LM_ID_BASE);
		memset(&id, 0, sizeof(id));
	}
	else
	{
		if (__glibc_unlikely(!_dl_get_file_id(fd, &id)))
		{
			errstring = N_("cannot stat shared object");
		lose_errno:
			errval = errno;
		lose:
			/* The file might already be closed.  */
			/* 文件可能已经关闭了 */
			if (fd != -1)
				__close_nocancel(fd);
			if (l != NULL && l->l_map_start != 0)
				_dl_unmap_segments(l);
			if (l != NULL && l->l_origin != (char *)-1l)
				free((char *)l->l_origin);
			if (l != NULL && !l->l_libname->dont_free)
				free(l->l_libname);
			if (l != NULL && l->l_phdr_allocated)
				free((void *)l->l_phdr);
			free(l);
			free(realname);

			if (make_consistent && r != NULL)
			{
				r->r_state = RT_CONSISTENT;
				_dl_debug_state();
				LIBC_PROBE(map_failed, 2, nsid, r);
			}

			_dl_signal_error(errval, name, NULL, errstring);
		}

		/* Look again to see if the real name matched another already loaded.  */
		/* 再次查看真实名称是否与另一个已加载的名称匹配。 */
		for (l = GL(dl_ns)[nsid]._ns_loaded; l != NULL; l = l->l_next)
			if (!l->l_removed && _dl_file_id_match_p(&l->l_file_id, &id))
			{
				/* The object is already loaded.
				   Just bump its reference count and return it.  */
				/* 对象已经加载。只需增加其引用计数并返回它。 */
				__close_nocancel(fd);

				/* If the name is not in the list of names for this object add
				   it.  */
				/* 如果名称不在此对象的名称列表中，请将其添加。 */
				free(realname);
				add_name_to_object(l, name);

				return l;
			}
	}

#ifdef SHARED
	/* When loading into a namespace other than the base one we must
	   avoid loading ld.so since there can only be one copy.  Ever.  */
	if (__glibc_unlikely(nsid != LM_ID_BASE) && (_dl_file_id_match_p(&id, &GL(dl_rtld_map).l_file_id) || _dl_name_match_p(name, &GL(dl_rtld_map))))
	{
		/* This is indeed ld.so.  Create a new link_map which refers to
	   the real one for almost everything.  */
		l = _dl_new_object(realname, name, l_type, loader, mode, nsid);
		if (l == NULL)
			goto fail_new;

		/* Refer to the real descriptor.  */
		l->l_real = &GL(dl_rtld_map);

		/* Copy l_addr and l_ld to avoid a GDB warning with dlmopen().  */
		l->l_addr = l->l_real->l_addr;
		l->l_ld = l->l_real->l_ld;

		/* No need to bump the refcount of the real object, ld.so will
	   never be unloaded.  */
		__close_nocancel(fd);

		/* Add the map for the mirrored object to the object list.  */
		_dl_add_to_namespace_list(l, nsid);

		return l;
	}
#endif

	if (mode & RTLD_NOLOAD)
	{
		/* We are not supposed to load the object unless it is already
	   loaded.  So return now.  */
		/* 我们不应该加载对象，除非它已经加载。所以现在返回。 */
		free(realname);
		__close_nocancel(fd);
		return NULL;
	}

	/* Print debugging message.  */
	/* 打印调试消息。 */
	if (__glibc_unlikely(GLRO(dl_debug_mask) & DL_DEBUG_FILES))
		_dl_debug_printf("file=%s [%lu];  generating link map\n", name, nsid);

	/* This is the ELF header.  We read it in `open_verify'.  */
	/* 这是ELF头。我们在“open_verify”中读取它。 */
	header = (void *)fbp->buf;

	/* Enter the new object in the list of loaded objects.  */
	/* 将新对象输入到已加载对象的列表中。 */
	l = _dl_new_object(realname, name, l_type, loader, mode, nsid);		 // 创建新的link_map结构体，承载新加载的共享对象的信息
	if (__glibc_unlikely(l == NULL))
	{
#ifdef SHARED
	fail_new:
#endif
		errstring = N_("cannot create shared object descriptor");
		goto lose_errno;
	}

	/* Extract the remaining details we need from the ELF header
	   and then read in the program header table.  */
	/* 从ELF头中提取我们需要的其余细节，然后读取程序头表。 */
	l->l_entry = header->e_entry; // 入口地址
	type = header->e_type;		  // 文件类型
	l->l_phnum = header->e_phnum; // 程序头表中的条目数

	maplength = header->e_phnum * sizeof(ElfW(Phdr));	 // maplength为程序头表的大小，即程序头表中的条目数 * 每个条目的大小
	if (header->e_phoff + maplength <= (size_t)fbp->len) // 如果程序头表的偏移量 + 程序头表的大小 <= 文件长度
		phdr = (void *)(fbp->buf + header->e_phoff);	 // 则程序头表在文件中的位置为文件的起始地址 + 程序头表的偏移量
	else
	{
		phdr = alloca(maplength); // 否则，分配maplength大小的空间
		if ((size_t)__pread64_nocancel(fd, (void *)phdr, maplength,
									   header->e_phoff) != maplength)
		{
			errstring = N_("cannot read file data");
			goto lose_errno;
		}
	}

	/* On most platforms presume that PT_GNU_STACK is absent and the stack is
	 * executable.  Other platforms default to a nonexecutable stack and don't
	 * need PT_GNU_STACK to do so.  */
	/* 在大多数平台上，假设PT_GNU_STACK不存在，堆栈是可执行的。其他平台默认为不可执行的堆栈，不需要PT_GNU_STACK来执行此操作。 */
	uint_fast16_t stack_flags = DEFAULT_STACK_PERMS;

	{
		/* Scan the program header table, collecting its load commands.  */
		/* 扫描程序头表，收集其加载命令。 */
		struct loadcmd loadcmds[l->l_phnum]; // loadcmds为加载命令数组，大小为程序头表中的条目数
		size_t nloadcmds = 0;				 // 加载命令的数量
		bool has_holes = false;				 // 是否有空洞
		bool empty_dynamic = false;			 // empty_dynamic为true表示动态段为空
		ElfW(Addr) p_align_max = 0;			 // 最大对齐值

		/* The struct is initialized to zero so this is not necessary:
		l->l_ld = 0;
		l->l_phdr = 0;
		l->l_addr = 0; */
		for (ph = phdr; ph < &phdr[l->l_phnum]; ++ph) // 遍历程序头表，ph为程序头表中的每个条目，每个条目记载了一个段的信息
			switch (ph->p_type)
			{
				/* These entries tell us where to find things once the file's
				   segments are mapped in.  We record the addresses it says
				   verbatim, and later correct for the run-time load address.  */
			/* 这些条目告诉我们在文件段映射后在哪里找到这些条目。我们记录它说的地址，稍后根据运行时加载地址进行更正。 */
			case PT_DYNAMIC: // 若段类型为动态段
				if (ph->p_filesz == 0)
					empty_dynamic = true; /* Usually separate debuginfo.  */ // 通常是单独的debuginfo。
				else
				{
					/* Debuginfo only files from "objcopy --only-keep-debug"
				   contain a PT_DYNAMIC segment with p_filesz == 0.  Skip
				   such a segment to avoid a crash later.  */
					/* 仅包含“objcopy --only-keep-debug”中的debuginfo的文件包含
					具有p_filesz == 0的PT_DYNAMIC段。跳过这样的段以避免以后崩溃。 */
					l->l_ld = (void *)ph->p_vaddr;
					l->l_ldnum = ph->p_memsz / sizeof(ElfW(Dyn));
					l->l_ld_readonly = (ph->p_flags & PF_W) == 0;
				}
				break;

			case PT_PHDR: // 若段类型为程序头表
				l->l_phdr = (void *)ph->p_vaddr;
				break;

			case PT_LOAD: // 若段类型为加载段，加载段用于在内存和文件中根据p_align对齐各段
				/* A load command tells us to map in part of the file.
				   We record the load commands and process them all later.  */
				/* 加载命令告诉我们映射文件的一部分。我们记录加载命令并稍后处理它们。 */
				if (__glibc_unlikely(((ph->p_vaddr - ph->p_offset) & (GLRO(dl_pagesize) - 1)) != 0))
				{
					errstring = N_("ELF load command address/offset not page-aligned");
					goto lose;
				}

				struct loadcmd *c = &loadcmds[nloadcmds++];
				c->mapstart = ALIGN_DOWN(ph->p_vaddr, GLRO(dl_pagesize));			 // mapstart为段在内存中的起始地址
				c->mapend = ALIGN_UP(ph->p_vaddr + ph->p_filesz, GLRO(dl_pagesize)); // mapend为段在内存中的结束地址
				c->dataend = ph->p_vaddr + ph->p_filesz;							 // dataend为段在内存中的结束地址
				c->allocend = ph->p_vaddr + ph->p_memsz;							 // allocend为段在内存中的结束地址
				/* Remember the maximum p_align.  */
				/* 记住最大p_align。 */
				if (powerof2(ph->p_align) && ph->p_align > p_align_max) // 判断p_align是否是2的幂，且大于p_align_max。p_align用于在内存和文件中根据该值对齐各段
					p_align_max = ph->p_align;							// 如果是2的幂，且大于p_align_max，则将p_align_max赋值为ph->p_align
																		// 每个段的p_align都不一样，但是p_align_max是所有段中p_align的最大值，只需要对齐p_align_max即可满足所有段的对齐要求
				c->mapoff = ALIGN_DOWN(ph->p_offset, GLRO(dl_pagesize));

				/* Determine whether there is a gap between the last segment
				   and this one.  */
				/* 确定最后一个段和这个段之间是否有间隙。 */
				// 间隙是由于段的p_align不一样，导致段之间的空间不够对齐，因此需要填充空间
				if (nloadcmds > 1 && c[-1].mapend != c->mapstart) // 若有多个段，且前一个段的结束地址 != 当前段的开始地址
					has_holes = true;							  // 若有间隙，则has_holes为true

					/* Optimize a common case.  */
					/* 优化常见情况。 */
#if (PF_R | PF_W | PF_X) == 7 && (PROT_READ | PROT_WRITE | PROT_EXEC) == 7
				c->prot = (PF_TO_PROT >> ((ph->p_flags & (PF_R | PF_W | PF_X)) * 4)) & 0xf;
#else
				c->prot = 0;
				if (ph->p_flags & PF_R)
					c->prot |= PROT_READ;
				if (ph->p_flags & PF_W)
					c->prot |= PROT_WRITE;
				if (ph->p_flags & PF_X)
					c->prot |= PROT_EXEC;
#endif
				break;

			case PT_TLS: // 若段类型为TLS段
				if (ph->p_memsz == 0)
					/* Nothing to do for an empty segment.  */
					break;

				l->l_tls_blocksize = ph->p_memsz;
				l->l_tls_align = ph->p_align;
				if (ph->p_align == 0)
					l->l_tls_firstbyte_offset = 0;
				else
					l->l_tls_firstbyte_offset = ph->p_vaddr & (ph->p_align - 1);
				l->l_tls_initimage_size = ph->p_filesz;
				/* Since we don't know the load address yet only store the
				   offset.  We will adjust it later.  */
				l->l_tls_initimage = (void *)ph->p_vaddr;

				/* l->l_tls_modid is assigned below, once there is no
				   possibility for failure.  */

				if (l->l_type != lt_library && GL(dl_tls_dtv_slotinfo_list) == NULL)
				{
#ifdef SHARED
					/* We are loading the executable itself when the dynamic
				   linker was executed directly.  The setup will happen
				   later.  */
					/* 当直接执行动态链接器时，我们正在加载可执行文件本身。设置将稍后发生。 */
					assert(l->l_prev == NULL || (mode & __RTLD_AUDIT) != 0);
#else
					assert(false && "TLS not initialized in static application");
#endif
				}
				break;

			case PT_GNU_STACK: // 若段类型为GNU_STACK段，该段用于设置栈的权限
				stack_flags = ph->p_flags;
				break;

			case PT_GNU_RELRO: // 若段类型为GNU_RELRO段，该段用于只读重定位
				l->l_relro_addr = ph->p_vaddr;
				l->l_relro_size = ph->p_memsz;
				break;
			}

		if (__glibc_unlikely(nloadcmds == 0))
		{
			/* This only happens for a bogus object that will be caught with
			   another error below.  But we don't want to go through the
			   calculations below using NLOADCMDS - 1.  */
			/* 这只发生在一个错误的对象上，该对象将在下面的另一个错误中被捕获。但是我们不想使用NLOADCMDS - 1进行下面的计算。 */
			errstring = N_("object file has no loadable segments");
			goto lose;
		}

		/* Align all PT_LOAD segments to the maximum p_align.  */
		/* 将所有PT_LOAD段对齐到最大p_align。 */
		for (size_t i = 0; i < nloadcmds; i++)
			loadcmds[i].mapalign = p_align_max; // 对齐

		/* dlopen of an executable is not valid because it is not possible
		   to perform proper relocations, handle static TLS, or run the
		   ELF constructors.  For PIE, the check needs the dynamic
		   section, so there is another check below.  */
		/* 对可执行文件的dlopen无效，因为不可能执行正确的重定位，处理静态TLS或运行ELF构造函数。
			对于PIE，检查需要动态节，因此下面还有另一个检查。 */
		if (__glibc_unlikely(type != ET_DYN) && __glibc_unlikely((mode & __RTLD_OPENEXEC) == 0))
		{
			/* This object is loaded at a fixed address.  This must never
			   happen for objects loaded with dlopen.  */
			/* 此对象以固定地址加载。这对于使用dlopen加载的对象绝不能发生。 */
			errstring = N_("cannot dynamically load executable");
			goto lose;
		}

		/* This check recognizes most separate debuginfo files.  */
		/* 此检查识别大多数单独的调试信息文件。 */
		if (__glibc_unlikely((l->l_ld == 0 && type == ET_DYN) || empty_dynamic))
		{
			errstring = N_("object file has no dynamic section");
			goto lose;
		}

		/* Length of the sections to be loaded.  */
		/* 要加载的段的长度。 */
		maplength = loadcmds[nloadcmds - 1].allocend - loadcmds[0].mapstart; // maplength = 最后一个段的结束地址 - 第一个段的开始地址

		/* Now process the load commands and map segments into memory.
		   This is responsible for filling in:
		   l_map_start, l_map_end, l_addr, l_contiguous, l_text_end, l_phdr
		 */
		/* 现在处理加载命令并将段映射到内存中。这负责填写：
		l_map_start，l_map_end，l_addr，l_contiguous，l_text_end，l_phdr */
		errstring = _dl_map_segments(l, fd, header, type, loadcmds, nloadcmds,
									 maplength, has_holes, loader); // 映射段到内存
		if (__glibc_unlikely(errstring != NULL))					// 若映射失败
		{
			/* Mappings can be in an inconsistent state: avoid unmap.  */
			/* 映射可能处于不一致的状态：避免取消映射。 */
			l->l_map_start = l->l_map_end = 0; // 将l_map_start和l_map_end置为0
			goto lose;						   // 失败
		}
	}

	if (l->l_ld != 0)
		l->l_ld = (ElfW(Dyn) *)((ElfW(Addr))l->l_ld + l->l_addr);

	elf_get_dynamic_info(l, false, false);

	/* Make sure we are not dlopen'ing an object that has the
	   DF_1_NOOPEN flag set, or a PIE object.  */
	/* 确保我们不会dlopen具有设置DF_1_NOOPEN标志或PIE对象的对象。 */
	if ((__glibc_unlikely(l->l_flags_1 & DF_1_NOOPEN) && (mode & __RTLD_DLOPEN)) || (__glibc_unlikely(l->l_flags_1 & DF_1_PIE) && __glibc_unlikely((mode & __RTLD_OPENEXEC) == 0)))
	{
		if (l->l_flags_1 & DF_1_PIE)
			errstring = N_("cannot dynamically load position-independent executable");
		else
			errstring = N_("shared object cannot be dlopen()ed");
		goto lose;
	}

	if (l->l_phdr == NULL)
	{
		/* The program header is not contained in any of the segments.
	   		We have to allocate memory ourself and copy it over from out
	   		temporary place.  */
	   	/* 程序头不包含在任何段中。我们必须自己分配内存并从临时位置复制它。 */
		ElfW(Phdr) *newp = (ElfW(Phdr) *)malloc(header->e_phnum * sizeof(ElfW(Phdr)));
		if (newp == NULL)
		{
			errstring = N_("cannot allocate memory for program header");
			goto lose_errno;
		}

		l->l_phdr = memcpy(newp, phdr,
						   (header->e_phnum * sizeof(ElfW(Phdr))));
		l->l_phdr_allocated = 1;
	}
	else
		/* Adjust the PT_PHDR value by the runtime load address.  */
		/* 通过运行时加载地址调整PT_PHDR值。 */
		l->l_phdr = (ElfW(Phdr) *)((ElfW(Addr))l->l_phdr + l->l_addr);

	if (__glibc_unlikely((stack_flags & ~GL(dl_stack_flags)) & PF_X))
	{
		/* The stack is presently not executable, but this module
	   		requires that it be executable.  We must change the
	   		protection of the variable which contains the flags used in
	   		the mprotect calls.  */
	   	/* 堆栈目前不可执行，但是此模块要求它可执行。我们必须更改包含在mprotect调用中使用的标志的变量的保护。 */
#ifdef SHARED
		if ((mode & (__RTLD_DLOPEN | __RTLD_AUDIT)) == __RTLD_DLOPEN)
		{
			const uintptr_t p = (uintptr_t)&__stack_prot & -GLRO(dl_pagesize);
			const size_t s = (uintptr_t)(&__stack_prot + 1) - p;

			struct link_map *const m = &GL(dl_rtld_map);
			const uintptr_t relro_end = ((m->l_addr + m->l_relro_addr + m->l_relro_size) & -GLRO(dl_pagesize));
			if (__glibc_likely(p + s <= relro_end))
			{
				/* The variable lies in the region protected by RELRO.  */
				/* 变量位于RELRO保护的区域中。 */
				if (__mprotect((void *)p, s, PROT_READ | PROT_WRITE) < 0)
				{
					errstring = N_("cannot change memory protections");
					goto lose_errno;
				}
				__stack_prot |= PROT_READ | PROT_WRITE | PROT_EXEC;
				__mprotect((void *)p, s, PROT_READ);
			}
			else
				__stack_prot |= PROT_READ | PROT_WRITE | PROT_EXEC;
		}
		else
#endif
			__stack_prot |= PROT_READ | PROT_WRITE | PROT_EXEC;

#ifdef check_consistency
		check_consistency();
#endif

#if PTHREAD_IN_LIBC
		errval = _dl_make_stacks_executable(stack_endp);
#else
		errval = (*GL(dl_make_stack_executable_hook))(stack_endp);
#endif
		if (errval)
		{
			errstring = N_("\
cannot enable executable stack as shared object requires");
			goto lose;
		}
	}

	/* Adjust the address of the TLS initialization image.  */
	/* 调整TLS初始化图像的地址。 */
	if (l->l_tls_initimage != NULL)
		l->l_tls_initimage = (char *)l->l_tls_initimage + l->l_addr;

	/* Process program headers again after load segments are mapped in
	   case processing requires accessing those segments.  Scan program
	   headers backward so that PT_NOTE can be skipped if PT_GNU_PROPERTY
	   exits.  */
	/* 在加载段映射后再次处理程序头，以防处理需要访问这些段。
		向后扫描程序头，以便在PT_GNU_PROPERTY退出时可以跳过PT_NOTE。 */
	for (ph = &l->l_phdr[l->l_phnum]; ph != l->l_phdr; --ph)
		switch (ph[-1].p_type)
		{
		case PT_NOTE:
			_dl_process_pt_note(l, fd, &ph[-1]);
			break;
		case PT_GNU_PROPERTY:
			_dl_process_pt_gnu_property(l, fd, &ph[-1]);
			break;
		}

	/* We are done mapping in the file.  We no longer need the descriptor.  */
	/* 我们完成了文件映射。我们不再需要描述符。 */
	if (__glibc_unlikely(__close_nocancel(fd) != 0))
	{
		errstring = N_("cannot close file descriptor");
		goto lose_errno;
	}
	/* Signal that we closed the file.  */
	/* fd=-1，表明我们关闭了文件。 */
	fd = -1;

	/* Failures before this point are handled locally via lose.
	   There are no more failures in this function until return,
	   to change that the cleanup handling needs to be updated.  */
	/* 此点之前的故障通过lose在本地处理。
		在此函数中没有更多故障，直到返回，为了改变清理处理，需要更新。 */

	/* If this is ET_EXEC, we should have loaded it as lt_executable.  */
	/* 如果这是ET_EXEC，我们应该将其加载为lt_executable。 */
	assert(type != ET_EXEC || l->l_type == lt_executable);

	l->l_entry += l->l_addr;

	if (__glibc_unlikely(GLRO(dl_debug_mask) & DL_DEBUG_FILES))
		_dl_debug_printf("\
  dynamic: 0x%0*lx  base: 0x%0*lx   size: 0x%0*Zx\n\
    entry: 0x%0*lx  phdr: 0x%0*lx  phnum:   %*u\n\n",
						 (int)sizeof(void *) * 2,
						 (unsigned long int)l->l_ld,
						 (int)sizeof(void *) * 2,
						 (unsigned long int)l->l_addr,
						 (int)sizeof(void *) * 2, maplength,
						 (int)sizeof(void *) * 2,
						 (unsigned long int)l->l_entry,
						 (int)sizeof(void *) * 2,
						 (unsigned long int)l->l_phdr,
						 (int)sizeof(void *) * 2, l->l_phnum);

	/* Set up the symbol hash table.  */
	/* 设置符号哈希表。 */
	_dl_setup_hash(l);

	/* If this object has DT_SYMBOLIC set modify now its scope.  We don't
	   have to do this for the main map.  */
	/* 如果此对象具有DT_SYMBOLIC设置，请立即修改其范围。我们不必为主映射执行此操作。 */
	if ((mode & RTLD_DEEPBIND) == 0 && __glibc_unlikely(l->l_info[DT_SYMBOLIC] != NULL) && &l->l_searchlist != l->l_scope[0])
	{
		/* Create an appropriate searchlist.  It contains only this map.
	   This is the definition of DT_SYMBOLIC in SysVr4.  */
	   /* 创建一个适当的搜索列表。它只包含这个映射。这是SysVr4中DT_SYMBOLIC的定义。 */
		l->l_symbolic_searchlist.r_list[0] = l;
		l->l_symbolic_searchlist.r_nlist = 1;

		/* Now move the existing entries one back.  */
		/* 现在将现有条目向后移动一个。 */
		memmove(&l->l_scope[1], &l->l_scope[0],
				(l->l_scope_max - 1) * sizeof(l->l_scope[0]));

		/* Now add the new entry.  */
		/* 现在添加新条目。 */
		l->l_scope[0] = &l->l_symbolic_searchlist;
	}

	/* Remember whether this object must be initialized first.  */
	/* 记住此对象是否必须首先初始化。 */
	if (l->l_flags_1 & DF_1_INITFIRST)
		GL(dl_initfirst) = l;

	/* Finally the file information.  */
	/* 最后是文件信息。 */
	l->l_file_id = id;

#ifdef SHARED
	/* When auditing is used the recorded names might not include the
	   name by which the DSO is actually known.  Add that as well.  */
	/* 使用审核时，记录的名称可能不包括实际已知DSO的名称。也添加。 */
	if (__glibc_unlikely(origname != NULL))
		add_name_to_object(l, origname);
#else
	/* Audit modules only exist when linking is dynamic so ORIGNAME
	   cannot be non-NULL.  */
	/* 审核模块仅在链接是动态的时才存在，因此ORIGNAME不能为非空。 */
	assert(origname == NULL);
#endif

	/* When we profile the SONAME might be needed for something else but
	   loading.  Add it right away.  */
	/* 当我们对SONAME进行配置时，可能需要用于其他用途，但不加载。立即添加。 */
	if (__glibc_unlikely(GLRO(dl_profile) != NULL) && l->l_info[DT_SONAME] != NULL)
		add_name_to_object(l, ((const char *)D_PTR(l, l_info[DT_STRTAB]) + l->l_info[DT_SONAME]->d_un.d_val));

	/* If we have newly loaded libc.so, update the namespace
	   description.  */
	/* 如果我们有新加载的libc.so，请更新命名空间描述。 */
	if (GL(dl_ns)[nsid].libc_map == NULL && l->l_info[DT_SONAME] != NULL && strcmp(((const char *)D_PTR(l, l_info[DT_STRTAB]) + l->l_info[DT_SONAME]->d_un.d_val), LIBC_SO) == 0)
		GL(dl_ns)
		[nsid].libc_map = l;

	/* _dl_close can only eventually undo the module ID assignment (via
	   remove_slotinfo) if this function returns a pointer to a link
	   map.  Therefore, delay this step until all possibilities for
	   failure have been excluded.  */
	/* _dl_close只能最终通过remove_slotinfo撤消模块ID分配（通过remove_slotinfo），
		如果此函数返回指向链接映射的指针。因此，直到排除了所有失败的可能性，才延迟此步骤。 */
	if (l->l_tls_blocksize > 0 && (__glibc_likely(l->l_type == lt_library)
								   	/* If GL(dl_tls_dtv_slotinfo_list) == NULL, then rtld.c did
									  not set up TLS data structures, so don't use them now.  */
									/* 如果GL（dl_tls_dtv_slotinfo_list）== NULL，则rtld.c没有设置TLS数据结构，因此现在不要使用它们。 */
								   || __glibc_likely(GL(dl_tls_dtv_slotinfo_list) != NULL)))
		/* Assign the next available module ID.  */
		/* 分配下一个可用的模块ID。 */
		_dl_assign_tls_modid(l);

#ifdef DL_AFTER_LOAD
	DL_AFTER_LOAD(l);
#endif

	/* Now that the object is fully initialized add it to the object list.  */
	/* 现在，对象已完全初始化，将其添加到对象列表中。 */
	_dl_add_to_namespace_list(l, nsid);

	/* Signal that we are going to add new objects.  */
	/* 表示我们将添加新对象。 */
	if (r->r_state == RT_CONSISTENT)
	{
#ifdef SHARED
		/* Auditing checkpoint: we are going to add new objects.  Since this
		   is called after _dl_add_to_namespace_list the namespace is guaranteed
	   		to not be empty.  */
	   	/* 审计检查点：我们将添加新对象。由于此调用发生在_dl_add_to_namespace_list之后，因此保证命名空间不为空。 */
		if ((mode & __RTLD_AUDIT) == 0)
			_dl_audit_activity_nsid(nsid, LA_ACT_ADD);
#endif

		/* Notify the debugger we have added some objects.  We need to
	   call _dl_debug_initialize in a static program in case dynamic
	   linking has not been used before.  */
	   	/* 通知调试器我们已添加了一些对象。我们需要在静态程序中调用_dl_debug_initialize，以防动态链接之前没有使用过。 */
		r->r_state = RT_ADD;
		_dl_debug_state();
		LIBC_PROBE(map_start, 2, nsid, r);
		make_consistent = true;
	}
	else
		assert(r->r_state == RT_ADD);

#ifdef SHARED
	/* Auditing checkpoint: we have a new object.  */
	/* 审计检查点：我们有一个新对象。 */
	if (!GL(dl_ns)[l->l_ns]._ns_loaded->l_auditing)
		_dl_audit_objopen(l, nsid);
#endif

	return l;
}

/* Print search path.  */
static void
print_search_path(struct r_search_path_elem **list,
				  const char *what, const char *name)
{
	char buf[max_dirnamelen + max_capstrlen];
	int first = 1;

	_dl_debug_printf(" search path=");

	while (*list != NULL && (*list)->what == what) /* Yes, ==.  */
	{
		char *endp = __mempcpy(buf, (*list)->dirname, (*list)->dirnamelen);
		size_t cnt;

		for (cnt = 0; cnt < ncapstr; ++cnt)
			if ((*list)->status[cnt] != nonexisting)
			{
#ifdef SHARED
				char *cp = __mempcpy(endp, capstr[cnt].str, capstr[cnt].len);
				if (cp == buf || (cp == buf + 1 && buf[0] == '/'))
					cp[0] = '\0';
				else
					cp[-1] = '\0';
#else
				*endp = '\0';
#endif

				_dl_debug_printf_c(first ? "%s" : ":%s", buf);
				first = 0;
			}

		++list;
	}

	if (name != NULL)
		_dl_debug_printf_c("\t\t(%s from file %s)\n", what,
						   DSO_FILENAME(name));
	else
		_dl_debug_printf_c("\t\t(%s)\n", what);
}

/* Open a file and verify it is an ELF file for this architecture.  We
   ignore only ELF files for other architectures.  Non-ELF files and
   ELF files with different header information cause fatal errors since
   this could mean there is something wrong in the installation and the
   user might want to know about this.

   If FD is not -1, then the file is already open and FD refers to it.
   In that case, FD is consumed for both successful and error returns.  */
/* 打开一个文件并验证它是一个ELF文件，我们忽略其他架构的ELF文件。
	非ELF文件和具有不同头信息的ELF文件会导致致命错误，因为这可能意味着安装中有问题，
	用户可能想知道这一点。如果FD不是-1，那么文件已经打开，FD指的是它。
	在这种情况下，FD对于成功和错误返回都是有效的。 */
static int
open_verify(const char *name, int fd,
			struct filebuf *fbp, struct link_map *loader,
			int whatcode, int mode, bool *found_other_class, bool free_name)
{
	/* This is the expected ELF header.  */
	// 这是预期的ELF头
#define ELF32_CLASS ELFCLASS32
#define ELF64_CLASS ELFCLASS64
#ifndef VALID_ELF_HEADER
#define VALID_ELF_HEADER(hdr, exp, size) (memcmp(hdr, exp, size) == 0)
#define VALID_ELF_OSABI(osabi) (osabi == ELFOSABI_SYSV)
#define VALID_ELF_ABIVERSION(osabi, ver) (ver == 0)
#elif defined MORE_ELF_HEADER_DATA
	MORE_ELF_HEADER_DATA;
#endif
	static const unsigned char expected[EI_NIDENT] =
		{
			[EI_MAG0] = ELFMAG0,
			[EI_MAG1] = ELFMAG1,
			[EI_MAG2] = ELFMAG2,
			[EI_MAG3] = ELFMAG3,
			[EI_CLASS] = ELFW(CLASS),
			[EI_DATA] = byteorder,
			[EI_VERSION] = EV_CURRENT,
			[EI_OSABI] = ELFOSABI_SYSV,
			[EI_ABIVERSION] = 0};
	static const struct
	{
		ElfW(Word) vendorlen;
		ElfW(Word) datalen;
		ElfW(Word) type;
		char vendor[4];
	} expected_note = {4, 16, 1, "GNU"};
	/* Initialize it to make the compiler happy.  */
	// 初始化
	const char *errstring = NULL;
	int errval = 0;

#ifdef SHARED
	/* Give the auditing libraries a chance.  */
	// 给审计库一个机会
	if (__glibc_unlikely(GLRO(dl_naudit) > 0))
	{
		const char *original_name = name;
		name = _dl_audit_objsearch(name, loader, whatcode);
		if (name == NULL)
			return -1;

		if (fd != -1 && name != original_name && strcmp(name, original_name))
		{
			/* An audit library changed what we're supposed to open,
			   so FD no longer matches it.  */
			// 审计库更改了我们应该打开的内容，因此FD不再匹配它
			__close_nocancel(fd);
			fd = -1;
		}
	}
#endif

	if (fd == -1)
		/* Open the file.  We always open files read-only.  */
		// 打开文件，我们总是只读打开文件
		fd = __open64_nocancel(name, O_RDONLY | O_CLOEXEC); // O_CLOEXEC：执行exec后，关闭文件描述符。__open64_nocancel：直接调用系统调用打开文件

	if (fd != -1)
	{
		ElfW(Ehdr) * ehdr;
		ElfW(Phdr) * phdr, *ph;
		ElfW(Word) * abi_note;
		ElfW(Word) *abi_note_malloced = NULL;
		unsigned int osversion;
		size_t maplength;

		/* We successfully opened the file.  Now verify it is a file
	   we can use.  */
		// 我们成功打开了文件，现在验证它是一个我们可以使用的文件
		__set_errno(0);
		fbp->len = 0;
		assert(sizeof(fbp->buf) > sizeof(ElfW(Ehdr)));
		/* Read in the header.  */
		// 读取头部
		do
		{
			ssize_t retlen = __read_nocancel(fd, fbp->buf + fbp->len,
											 sizeof(fbp->buf) - fbp->len);
			if (retlen <= 0)
				break;
			fbp->len += retlen;
		} while (__glibc_unlikely(fbp->len < sizeof(ElfW(Ehdr))));

		/* This is where the ELF header is loaded.  */
		// 这是ELF头加载的地方
		ehdr = (ElfW(Ehdr) *)fbp->buf;

		/* Now run the tests.  */
		// 现在运行测试
		if (__glibc_unlikely(fbp->len < (ssize_t)sizeof(ElfW(Ehdr))))
		{
			errval = errno;
			errstring = (errval == 0
							 ? N_("file too short")
							 : N_("cannot read file data"));
		lose:
			if (free_name)
			{
				char *realname = (char *)name;
				name = strdupa(realname);
				free(realname);
			}
			__close_nocancel(fd);
			_dl_signal_error(errval, name, NULL, errstring);
		}

		/* See whether the ELF header is what we expect.  */
		// 看看ELF头是否符合我们的预期
		if (__glibc_unlikely(!VALID_ELF_HEADER(ehdr->e_ident, expected, // 验证ELF头
											   EI_ABIVERSION) ||
							 !VALID_ELF_ABIVERSION(ehdr->e_ident[EI_OSABI], // 验证ABI版本
												   ehdr->e_ident[EI_ABIVERSION]) ||
							 memcmp(&ehdr->e_ident[EI_PAD], // 验证填充
									&expected[EI_PAD],
									EI_NIDENT - EI_PAD) != 0))
		{
			/* Something is wrong.  */
			// 出错了
			const Elf32_Word *magp = (const void *)ehdr->e_ident;
			if (*magp !=
#if BYTE_ORDER == LITTLE_ENDIAN
				((ELFMAG0 << (EI_MAG0 * 8)) | (ELFMAG1 << (EI_MAG1 * 8)) | (ELFMAG2 << (EI_MAG2 * 8)) | (ELFMAG3 << (EI_MAG3 * 8)))
#else
				((ELFMAG0 << (EI_MAG3 * 8)) | (ELFMAG1 << (EI_MAG2 * 8)) | (ELFMAG2 << (EI_MAG1 * 8)) | (ELFMAG3 << (EI_MAG0 * 8)))
#endif
			)
				errstring = N_("invalid ELF header");
			else if (ehdr->e_ident[EI_CLASS] != ELFW(CLASS))
			{
				/* This is not a fatal error.  On architectures where
			   32-bit and 64-bit binaries can be run this might
			   happen.  */
				// 这不是致命错误，在32位和64位二进制文件可以运行的架构上可能会发生
				*found_other_class = true;
				goto close_and_out;
			}
#ifdef __arm__
			else if (!VALID_FLOAT_ABI(ehdr->e_flags))
			{
				/* This is not a fatal error.  On architectures where
			   soft-float and hard-float binaries can be run this
			   might happen.  */
				// 这不是致命错误，在可以运行软浮点和硬浮点二进制文件的架构上可能会发生
				goto close_and_out;
			}
#endif
			else if (!__builtin_expect(elf_machine_matches_host(ehdr), 1))
			{
				/* Another non-fatal error, let's skip right past the
				   the libraries obviously built for other machines.  */
				// 另一个非致命错误，让我们跳过显然为其他机器构建的库
				goto close_and_out;
			}
			else if (ehdr->e_ident[EI_DATA] != byteorder)
			{
				if (BYTE_ORDER == BIG_ENDIAN)
					errstring = N_("ELF file data encoding not big-endian");
				else
					errstring = N_("ELF file data encoding not little-endian");
			}
			else if (ehdr->e_ident[EI_VERSION] != EV_CURRENT)
				errstring = N_("ELF file version ident does not match current one");
			/* XXX We should be able so set system specific versions which are
			   allowed here.  */
			// 我们应该能够设置允许的系统特定版本
			else if (!VALID_ELF_OSABI(ehdr->e_ident[EI_OSABI]))
				errstring = N_("ELF file OS ABI invalid");
			else if (!VALID_ELF_ABIVERSION(ehdr->e_ident[EI_OSABI],
										   ehdr->e_ident[EI_ABIVERSION]))
				errstring = N_("ELF file ABI version invalid");
			else if (memcmp(&ehdr->e_ident[EI_PAD], &expected[EI_PAD],
							EI_NIDENT - EI_PAD) != 0)
				errstring = N_("nonzero padding in e_ident");
			else
				/* Otherwise we don't know what went wrong.  */
				// 否则我们不知道出了什么问题
				errstring = N_("internal error");

			goto lose;
		}

		if (__glibc_unlikely(ehdr->e_version != EV_CURRENT))
		{
			errstring = N_("ELF file version does not match current one");
			goto lose;
		}
		if (!__glibc_likely(elf_machine_matches_host(ehdr)))
			goto close_and_out;
		else if (__glibc_unlikely(ehdr->e_type != ET_DYN && ehdr->e_type != ET_EXEC))
		{
			errstring = N_("only ET_DYN and ET_EXEC can be loaded");
			goto lose;
		}
		else if (__glibc_unlikely(ehdr->e_phentsize != sizeof(ElfW(Phdr))))
		{
			errstring = N_("ELF file's phentsize not the expected size");
			goto lose;
		}

		maplength = ehdr->e_phnum * sizeof(ElfW(Phdr));
		if (ehdr->e_phoff + maplength <= (size_t)fbp->len)
			phdr = (void *)(fbp->buf + ehdr->e_phoff);
		else
		{
			phdr = alloca(maplength);
			if ((size_t)__pread64_nocancel(fd, (void *)phdr, maplength,
										   ehdr->e_phoff) != maplength)
			{
			read_error:
				errval = errno;
				errstring = N_("cannot read file data");
				goto lose;
			}
		}

		if (__glibc_unlikely(elf_machine_reject_phdr_p(phdr, ehdr->e_phnum, fbp->buf, fbp->len,
													   loader, fd)))
			goto close_and_out;

		/* Check .note.ABI-tag if present.  */
		for (ph = phdr; ph < &phdr[ehdr->e_phnum]; ++ph)
			if (ph->p_type == PT_NOTE && ph->p_filesz >= 32 && (ph->p_align == 4 || ph->p_align == 8))
			{
				ElfW(Addr) size = ph->p_filesz;

				if (ph->p_offset + size <= (size_t)fbp->len)
					abi_note = (void *)(fbp->buf + ph->p_offset);
				else
				{
					/* Note: __libc_use_alloca is not usable here, because
					   thread info may not have been set up yet.  */
					/* 注意：__libc_use_alloca在这里不可用，因为线程信息可能尚未设置。 */
					if (size < __MAX_ALLOCA_CUTOFF)
						abi_note = alloca(size);
					else
					{
						/* There could be multiple PT_NOTEs.  */
						/* 可能有多个PT_NOTEs。 */
						abi_note_malloced = realloc(abi_note_malloced, size);
						if (abi_note_malloced == NULL)
							goto read_error;

						abi_note = abi_note_malloced;
					}
					if (__pread64_nocancel(fd, (void *)abi_note, size,
										   ph->p_offset) != size)
					{
						free(abi_note_malloced);
						goto read_error;
					}
				}

				while (memcmp(abi_note, &expected_note, sizeof(expected_note)))
				{
					ElfW(Addr) note_size = ELF_NOTE_NEXT_OFFSET(abi_note[0], abi_note[1],
																ph->p_align);

					if (size - 32 < note_size)
					{
						size = 0;
						break;
					}
					size -= note_size;
					abi_note = (void *)abi_note + note_size;
				}

				if (size == 0)
					continue;

				osversion = (abi_note[5] & 0xff) * 65536 + (abi_note[6] & 0xff) * 256 + (abi_note[7] & 0xff);
				if (abi_note[4] != __ABI_TAG_OS || (GLRO(dl_osversion) && GLRO(dl_osversion) < osversion))
				{
				close_and_out:
					__close_nocancel(fd);
					__set_errno(ENOENT);
					fd = -1;
				}

				break;
			}
		free(abi_note_malloced);
	}

	return fd;
}

/* Try to open NAME in one of the directories in *DIRSP.
   Return the fd, or -1.  If successful, fill in *REALNAME
   with the malloc'd full directory name.  If it turns out
   that none of the directories in *DIRSP exists, *DIRSP is
   replaced with (void *) -1, and the old value is free()d
   if MAY_FREE_DIRS is true.  */
/* 尝试在*DIRSP中的一个目录中打开NAME。返回fd，或-1。如果成功，用malloc的完整目录名填充*REALNAME。
   如果发现*DIRSP中没有一个目录存在，则用(void *) -1替换*DIRSP，并且如果MAY_FREE_DIRS为真，则释放旧值。 */
static int
open_path(const char *name, size_t namelen, int mode,
		  struct r_search_path_struct *sps, char **realname,
		  struct filebuf *fbp, struct link_map *loader, int whatcode,
		  bool *found_other_class)
{
	struct r_search_path_elem **dirs = sps->dirs;
	char *buf;
	int fd = -1;
	const char *current_what = NULL;
	int any = 0;

	if (__glibc_unlikely(dirs == NULL))
		/* We're called before _dl_init_paths when loading the main executable
		   given on the command line when rtld is run directly.  */
		/* 我们在直接运行rtld时在命令行上给出的主可执行文件加载之前调用_dl_init_paths。 */
		return -1;

	buf = alloca(max_dirnamelen + max_capstrlen + namelen);
	do
	{
		struct r_search_path_elem *this_dir = *dirs;
		size_t buflen = 0;
		size_t cnt;
		char *edp;
		int here_any = 0;
		int err;

		/* If we are debugging the search for libraries print the path
	   now if it hasn't happened now.  */
		/* 如果我们正在调试搜索库，请打印路径，如果现在还没有发生。 */
		if (__glibc_unlikely(GLRO(dl_debug_mask) & DL_DEBUG_LIBS) && current_what != this_dir->what) // 如果当前what不等于this_dir->what
		{
			current_what = this_dir->what;
			print_search_path(dirs, current_what, this_dir->where);
		}

		edp = (char *)__mempcpy(buf, this_dir->dirname, this_dir->dirnamelen); // 将this_dir->dirname拷贝到buf中
		for (cnt = 0; fd == -1 && cnt < ncapstr; ++cnt)						   // 遍历capstr
		{
			/* Skip this directory if we know it does not exist.  */
			// 如果我们知道该目录不存在，则跳过该目录。
			if (this_dir->status[cnt] == nonexisting)
				continue;

#ifdef SHARED
			buflen =
				((char *)__mempcpy(__mempcpy(edp, capstr[cnt].str,
											 capstr[cnt].len),
								   name, namelen) -
				 buf);
#else
			buflen = (char *)__mempcpy(edp, name, namelen) - buf; // 将name拷贝到edp中
#endif

			/* Print name we try if this is wanted.  */
			// 如果需要，打印我们尝试的名称。
			if (__glibc_unlikely(GLRO(dl_debug_mask) & DL_DEBUG_LIBS))
				_dl_debug_printf("  trying file=%s\n", buf); // 打印尝试的文件

			fd = open_verify(buf, -1, fbp, loader, whatcode, mode,
							 found_other_class, false); // 打开文件并验证
			if (this_dir->status[cnt] == unknown)
			{
				if (fd != -1)
					this_dir->status[cnt] = existing;
				/* Do not update the directory information when loading
			   auditing code.  We must try to disturb the program as
			   little as possible.  */
				// 加载审核代码时不要更新目录信息。我们必须尽可能地干扰程序。
				else if (loader == NULL || GL(dl_ns)[loader->l_ns]._ns_loaded->l_auditing == 0)
				{
					/* We failed to open machine dependent library.  Let's
					   test whether there is any directory at all.  */
					// 我们无法打开机器相关的库。让我们测试是否有任何目录。
					struct __stat64_t64 st;

					buf[buflen - namelen - 1] = '\0';

					if (__stat64_time64(buf, &st) != 0 || !S_ISDIR(st.st_mode))
						/* The directory does not exist or it is no directory.  */
						// 该目录不存在或不是目录。
						this_dir->status[cnt] = nonexisting;
					else
						this_dir->status[cnt] = existing;
				}
			}

			/* Remember whether we found any existing directory.  */
			// 记住我们是否找到了任何现有目录。
			here_any |= this_dir->status[cnt] != nonexisting;

			if (fd != -1 && __glibc_unlikely(mode & __RTLD_SECURE) && __libc_enable_secure)
			{
				/* This is an extra security effort to make sure nobody can
			   preload broken shared objects which are in the trusted
			   directories and so exploit the bugs.  */
				// 这是额外的安全措施，以确保没有人可以预加载位于受信任目录中的损坏共享对象，从而利用错误。
				struct __stat64_t64 st;

				if (__fstat64_time64(fd, &st) != 0 || (st.st_mode & S_ISUID) == 0)
				{
					/* The shared object cannot be tested for being SUID
					   or this bit is not set.  In this case we must not
					   use this object.  */
					// 无法测试共享对象是否为SUID，或者未设置此位。在这种情况下，我们不能使用此对象。
					__close_nocancel(fd);
					fd = -1;
					/* We simply ignore the file, signal this by setting
					   the error value which would have been set by `open'.  */
					// 我们只需忽略该文件，通过设置open设置的错误值来发出信号。
					errno = ENOENT;
				}
			}
		}

		if (fd != -1)
		{
			*realname = (char *)malloc(buflen); // 分配内存
			if (*realname != NULL)
			{
				memcpy(*realname, buf, buflen); // 拷贝buf到*realname
				return fd;
			}
			else
			{
				/* No memory for the name, we certainly won't be able
			   to load and link it.  */
				// 没有内存用于名称，我们肯定无法加载和链接它。
				__close_nocancel(fd);
				return -1;
			}
		}
		if (here_any && (err = errno) != ENOENT && err != EACCES)
			/* The file exists and is readable, but something went wrong.  */
			// 文件存在且可读，但出现了错误。
			return -1;

		/* Remember whether we found anything.  */
		// 记住我们是否找到了任何东西。
		any |= here_any;
	} while (*++dirs != NULL); // 遍历dirs

	/* Remove the whole path if none of the directories exists.  */
	// 如果没有目录存在，则删除整个路径。
	if (__glibc_unlikely(!any))
	{
		/* Paths which were allocated using the minimal malloc() in ld.so
	   must not be freed using the general free() in libc.  */
		// 使用ld.so中的最小malloc()分配的路径不能使用libc中的通用free()释放。
		if (sps->malloced)	 // 如果sps->malloced为1，说明sps是通过malloc分配的
			free(sps->dirs); // 释放sps->dirs

		/* __rtld_search_dirs and __rtld_env_path_list are
	   attribute_relro, therefore avoid writing to them.  */
		// __rtld_search_dirs和__rtld_env_path_list是attribute_relro，因此避免写入它们。
		if (sps != &__rtld_search_dirs && sps != &__rtld_env_path_list) // 如果sps不是__rtld_search_dirs和__rtld_env_path_list
			sps->dirs = (void *)-1;										// 将sps->dirs设置为(void *) -1
	}

	return -1;
}

/* Map in the shared object file NAME.  */
// 从文件中加载共享对象
struct link_map *
_dl_map_object(struct link_map *loader, const char *name,		// loader为加载器，name为共享对象名称
			   int type, int trace_mode, int mode, Lmid_t nsid) // type为共享对象类型，trace_mode为跟踪模式，mode为模式，nsid为命名空间id
{
	int fd;
	const char *origname = NULL;
	char *realname;
	char *name_copy;
	struct link_map *l;
	struct filebuf fb;

	assert(nsid >= 0);
	assert(nsid < GL(dl_nns));

	/* Look for this name among those already loaded.  */
	// 查找已经加载的共享对象
	for (l = GL(dl_ns)[nsid]._ns_loaded; l; l = l->l_next) // 遍历已经加载的共享对象
	{
		/* If the requested name matches the soname of a loaded object,
	   use that object.  Elide this check for names that have not
	   yet been opened.  */
		// 如果请求的名称与已加载对象的soname匹配，则使用该对象。对于尚未打开的名称，省略此检查。
		if (__glibc_unlikely((l->l_faked | l->l_removed) != 0))
			continue;
		if (!_dl_name_match_p(name, l))
		{
			const char *soname;

			if (__glibc_likely(l->l_soname_added) || l->l_info[DT_SONAME] == NULL) // 如果l_soname_added为1或者l_info[DT_SONAME]为NULL，意思是已经加载过了
				continue;

			soname = ((const char *)D_PTR(l, l_info[DT_STRTAB]) + l->l_info[DT_SONAME]->d_un.d_val); // 获取soname
			if (strcmp(name, soname) != 0)
#ifdef __arm__
				if (strcmp(name, "ld-linux.so.3") || strcmp(soname, "ld-linux-armhf.so.3"))
#endif
					continue;

			/* We have a match on a new name -- cache it.  */
			// 我们在新名称上有一个匹配——缓存它。
			add_name_to_object(l, name); // 将name添加到l的名称列表中
			l->l_soname_added = 1;		 // 设置l_soname_added为1，表示已经加载过了，如果再次遇到那么在上面的if中会跳过
		}

		/* We have a match.  */
		return l;
	}

	/* Display information if we are debugging.  */
	// 如果我们正在调试，则显示信息。
	if (__glibc_unlikely(GLRO(dl_debug_mask) & DL_DEBUG_FILES) && loader != NULL)
		_dl_debug_printf((mode & __RTLD_CALLMAP) == 0
							 ? "\nfile=%s [%lu];  needed by %s [%lu]\n"
							 : "\nfile=%s [%lu];  dynamically loaded by %s [%lu]\n",
						 name, nsid, DSO_FILENAME(loader->l_name), loader->l_ns);

#ifdef SHARED
	/* Give the auditing libraries a chance to change the name before we
	   try anything.  */
	// 在我们尝试任何事情之前，让审计库有机会更改名称。
	if (__glibc_unlikely(GLRO(dl_naudit) > 0))
	{
		const char *before = name;
		name = _dl_audit_objsearch(name, loader, LA_SER_ORIG);
		if (name == NULL)
		{
			fd = -1;
			goto no_file;
		}
		if (before != name && strcmp(before, name) != 0)
			origname = before;
	}
#endif

	/* Will be true if we found a DSO which is of the other ELF class.  */
	// 如果我们找到了另一个ELF类的DSO，则为真。
	/* DSO是动态共享对象，ELF是可执行和可链接格式 */
	bool found_other_class = false;

	if (strchr(name, '/') == NULL) // 如果name中不包含/，说明name是一个文件名，而不是路径
	{
		/* Search for NAME in several places.  */
		// 在几个地方搜索NAME。

		size_t namelen = strlen(name) + 1;

		if (__glibc_unlikely(GLRO(dl_debug_mask) & DL_DEBUG_LIBS)) // 如果是调试模式
			_dl_debug_printf("find library=%s [%lu]; searching\n", name, nsid);

		fd = -1;

		/* When the object has the RUNPATH information we don't use any
	   RPATHs.  */
		// 当对象具有RUNPATH信息时，我们不使用任何RPATH。
		if (loader == NULL || loader->l_info[DT_RUNPATH] == NULL) // 如果loader为NULL或者loader的DT_RUNPATH为NULL（DT_RUNPATH是一个动态数组，包含了搜索路径，这个数组是以NULL结尾的）
		{
			/* This is the executable's map (if there is one).  Make sure that
			   we do not look at it twice.  */
			// 这是可执行文件的映射（如果有的话）。确保我们不会看两次。
			struct link_map *main_map = GL(dl_ns)[LM_ID_BASE]._ns_loaded; // 获取基本命名空间的已加载的共享对象
			bool did_main_map = false;									  // 标记是否已经加载过了

			/* First try the DT_RPATH of the dependent object that caused NAME
			   to be loaded.  Then that object's dependent, and on up.  */
			// 首先尝试导致加载NAME的依赖对象的DT_RPATH。然后是该对象的依赖对象，以此类推。
			for (l = loader; l; l = l->l_loader)						 // 遍历loader的依赖对象
				if (cache_rpath(l, &l->l_rpath_dirs, DT_RPATH, "RPATH")) // 如果l的DT_RPATH不为NULL
				{
					fd = open_path(name, namelen, mode, // 尝试打开name
								   &l->l_rpath_dirs,
								   &realname, &fb, loader, LA_SER_RUNPATH,
								   &found_other_class);
					if (fd != -1)
						break;

					did_main_map |= l == main_map; // 标记是否已经加载过了
				}

			/* If dynamically linked, try the DT_RPATH of the executable
			   itself.  NB: we do this for lookups in any namespace.  */
			// 如果动态链接，请尝试可执行文件本身的DT_RPATH。注意：我们对任何命名空间中的查找都这样做。
			if (fd == -1 && !did_main_map							 // 如果还没有加载过
				&& main_map != NULL && main_map->l_type != lt_loaded // 如果main_map不为NULL且main_map的类型不为lt_loaded，意思是main_map还没有加载过，main_map是可执行文件，而不是共享对象
				&& cache_rpath(main_map, &main_map->l_rpath_dirs, DT_RPATH,
							   "RPATH"))
				fd = open_path(name, namelen, mode, // 尝试打开name
							   &main_map->l_rpath_dirs,
							   &realname, &fb, loader ?: main_map, LA_SER_RUNPATH,
							   &found_other_class);

			/* Also try DT_RUNPATH in the executable for LD_AUDIT dlopen
			   call.  */
			// 也尝试可执行文件中的DT_RUNPATH以进行LD_AUDIT dlopen调用。
			if (__glibc_unlikely(mode & __RTLD_AUDIT)				  // 如果是__RTLD_AUDIT模式
				&& fd == -1 && !did_main_map						  // 如果还没有加载过
				&& main_map != NULL && main_map->l_type != lt_loaded) // 如果main_map不为NULL且main_map的类型不为lt_loaded，意思是main_map还没有加载过，main_map是可执行文件，而不是共享对象
			{
				struct r_search_path_struct l_rpath_dirs;
				l_rpath_dirs.dirs = NULL;
				if (cache_rpath(main_map, &l_rpath_dirs, // 如果main_map的DT_RUNPATH不为NULL，那么将DT_RUNPATH的值存储到l_rpath_dirs中
								DT_RUNPATH, "RUNPATH"))
					fd = open_path(name, namelen, mode, &l_rpath_dirs, // 尝试打开name
								   &realname, &fb, loader ?: main_map,
								   LA_SER_RUNPATH, &found_other_class);
			}
		}

		/* Try the LD_LIBRARY_PATH environment variable.  */
		// 尝试LD_LIBRARY_PATH环境变量。
		if (fd == -1 && __rtld_env_path_list.dirs != (void *)-1)
			fd = open_path(name, namelen, mode, &__rtld_env_path_list, // 尝试打开name
						   &realname, &fb,
						   loader ?: GL(dl_ns)[LM_ID_BASE]._ns_loaded,
						   LA_SER_LIBPATH, &found_other_class);

		/* Look at the RUNPATH information for this binary.  */
		// 查看此二进制文件的RUNPATH信息。
		if (fd == -1 && loader != NULL && cache_rpath(loader, &loader->l_runpath_dirs, // 如果loader的DT_RUNPATH不为NULL，那么将DT_RUNPATH的值存储到loader->l_runpath_dirs中
													  DT_RUNPATH, "RUNPATH"))
			fd = open_path(name, namelen, mode, // 尝试打开name
						   &loader->l_runpath_dirs, &realname, &fb, loader,
						   LA_SER_RUNPATH, &found_other_class);

		if (fd == -1) // 如果还没有加载过（如果已经加载过了，那么fd就不为-1了），此时要打开的name有可能是一个路径（因为上面的if都是尝试打开name，而不是路径）
		{
			realname = _dl_sysdep_open_object(name, namelen, &fd); // 尝试打开name，_dl_sysdep_open_object和open_path的区别是_dl_sysdep_open_object不会尝试打开LD_LIBRARY_PATH环境变量中的路径
			if (realname != NULL)
			{
				fd = open_verify(realname, fd, // 验证打开的文件是否是ELF文件
								 &fb, loader ?: GL(dl_ns)[nsid]._ns_loaded,
								 LA_SER_CONFIG, mode, &found_other_class,
								 false);
				if (fd == -1)
					free(realname);
			}
		}

#ifdef USE_LDCONFIG
		if (fd == -1 && (__glibc_likely((mode & __RTLD_SECURE) == 0) || !__libc_enable_secure) && __glibc_likely(GLRO(dl_inhibit_cache) == 0))
		{
			/* Check the list of libraries in the file /etc/ld.so.cache,
			   for compatibility with Linux's ldconfig program.  */
			// 检查文件/etc/ld.so.cache中的库列表，以与Linux的ldconfig程序兼容。
			char *cached = _dl_load_cache_lookup(name); // 尝试从缓存中加载name

			if (cached != NULL)
			{
				// XXX Correct to unconditionally default to namespace 0?
				// XXX 无条件默认为命名空间0是否正确？
				l = (loader
						 ?: GL(dl_ns)[LM_ID_BASE]._ns_loaded
#ifdef SHARED
							?
							: &GL(dl_rtld_map)
#endif
				);

				/* If the loader has the DF_1_NODEFLIB flag set we must not
			   use a cache entry from any of these directories.  */
				// 如果加载器设置了DF_1_NODEFLIB标志，则不能使用这些目录中的任何缓存条目。
				if (__glibc_unlikely(l->l_flags_1 & DF_1_NODEFLIB)) // 如果l的l_flags_1的DF_1_NODEFLIB位为1
				{
					const char *dirp = system_dirs;
					unsigned int cnt = 0;

					do
					{
						if (memcmp(cached, dirp, system_dirs_len[cnt]) == 0) // 如果cached和dirp的system_dirs_len[cnt]长度的字符串相等
						{
							/* The prefix matches.  Don't use the entry.  */
							// 前缀匹配。不要使用该条目。
							free(cached);
							cached = NULL;
							break;
						}

						dirp += system_dirs_len[cnt] + 1;
						++cnt;
					} while (cnt < nsystem_dirs_len);
				}

				if (cached != NULL)
				{
					fd = open_verify(cached, -1,
									 &fb, loader ?: GL(dl_ns)[nsid]._ns_loaded,
									 LA_SER_CONFIG, mode, &found_other_class,
									 false);
					if (__glibc_likely(fd != -1))
						realname = cached;
					else
						free(cached);
				}
			}
		}
#endif

		/* Finally, try the default path.  */
		// 最后，尝试默认路径。（默认路径是/etc/ld.so.conf中的路径，此前我们尝试的都是LD_LIBRARY_PATH环境变量中的路径）
		if (fd == -1 && ((l = loader ?: GL(dl_ns)[nsid]._ns_loaded) == NULL	 // 如果loader为NULL或者loader的l_flags_1的DF_1_NODEFLIB位为0
						 || __glibc_likely(!(l->l_flags_1 & DF_1_NODEFLIB))) // 如果l为NULL或者l的l_flags_1的DF_1_NODEFLIB位为0
			&& __rtld_search_dirs.dirs != (void *)-1)						 // 如果__rtld_search_dirs.dirs不为-1
			fd = open_path(name, namelen, mode, &__rtld_search_dirs,		 // 尝试打开name
						   &realname, &fb, l, LA_SER_DEFAULT, &found_other_class);

		/* Add another newline when we are tracing the library loading.  */
		// 当我们跟踪库加载时，添加另一个换行符。（仅用于调试信息的美观）
		if (__glibc_unlikely(GLRO(dl_debug_mask) & DL_DEBUG_LIBS)) // 如果是调试模式
			_dl_debug_printf("\n");
	}
	else
	{
		/* The path may contain dynamic string tokens.  */
		// 路径可能包含动态字符串令牌。
		realname = (loader
						? expand_dynamic_string_token(loader, name)
						: __strdup(name)); // 如果loader不为NULL，那么尝试将name中的动态字符串令牌替换为实际的值，如果loader为NULL，那么直接复制name
		if (realname == NULL)
			fd = -1;
		else
		{
			fd = open_verify(realname, -1, &fb,
							 loader ?: GL(dl_ns)[nsid]._ns_loaded, 0, mode,
							 &found_other_class, true);
			if (__glibc_unlikely(fd == -1))
				free(realname);
		}
	}

#ifdef SHARED
no_file:
#endif
	/* In case the LOADER information has only been provided to get to
	   the appropriate RUNPATH/RPATH information we do not need it
	   anymore.  */
	// 如果LOADER信息仅用于获取适当的RUNPATH / RPATH信息，我们不再需要它。
	if (mode & __RTLD_CALLMAP)
		loader = NULL;

	if (__glibc_unlikely(fd == -1))
	{
		if (trace_mode && __glibc_likely((GLRO(dl_debug_mask) & DL_DEBUG_PRELINK) == 0)) // 如果是调试模式
		{
			/* We haven't found an appropriate library.  But since we
			   are only interested in the list of libraries this isn't
			   so severe.  Fake an entry with all the information we
			   have.  */
			// 我们没有找到合适的库。但是，由于我们只对库列表感兴趣，因此这并不严重。使用我们拥有的所有信息伪造一个条目。
			static const Elf_Symndx dummy_bucket = STN_UNDEF;

			/* Allocate a new object map.  */
			// 分配一个新的对象映射。
			if ((name_copy = __strdup(name)) == NULL || (l = _dl_new_object(name_copy, name, type, loader,
																			mode, nsid)) == NULL) // 如果name_copy为NULL或者_dl_new_object返回NULL，那么报错
			{
				free(name_copy); // 释放name_copy
				_dl_signal_error(ENOMEM, name, NULL,
								 N_("cannot create shared object descriptor"));
			}
			/* Signal that this is a faked entry.  */
			// 表示这是一个伪造的条目。
			l->l_faked = 1;
			/* Since the descriptor is initialized with zero we do not
			   have do this here.
			l->l_reserved = 0; */
			l->l_buckets = &dummy_bucket;
			l->l_nbuckets = 1;
			l->l_relocated = 1;

			/* Enter the object in the object list.  */
			// 将对象输入对象列表。
			_dl_add_to_namespace_list(l, nsid); // 将l添加到命名空间nsid的对象列表中

			return l;
		}
		else if (found_other_class) // 如果找到了另一个ELF类的DSO
			_dl_signal_error(0, name, NULL,
							 ELFW(CLASS) == ELFCLASS32
								 ? N_("wrong ELF class: ELFCLASS64")
								 : N_("wrong ELF class: ELFCLASS32"));
		else
			_dl_signal_error(errno, name, NULL,
							 N_("cannot open shared object file"));
	}

	void *stack_end = __libc_stack_end;
	return _dl_map_object_from_fd(name, origname, fd, &fb, realname, loader,
								  type, mode, &stack_end, nsid); // 根据fd将共享对象加载到内存中
}

struct add_path_state
{
	bool counting;
	unsigned int idx;
	Dl_serinfo *si;
	char *allocptr;
};

static void
add_path(struct add_path_state *p, const struct r_search_path_struct *sps,
		 unsigned int flags)
{
	if (sps->dirs != (void *)-1)
	{
		struct r_search_path_elem **dirs = sps->dirs;
		do
		{
			const struct r_search_path_elem *const r = *dirs++;
			if (p->counting)
			{
				p->si->dls_cnt++;
				p->si->dls_size += MAX(2, r->dirnamelen);
			}
			else
			{
				Dl_serpath *const sp = &p->si->dls_serpath[p->idx++];
				sp->dls_name = p->allocptr;
				if (r->dirnamelen < 2)
					*p->allocptr++ = r->dirnamelen ? '/' : '.';
				else
					p->allocptr = __mempcpy(p->allocptr,
											r->dirname, r->dirnamelen - 1);
				*p->allocptr++ = '\0';
				sp->dls_flags = flags;
			}
		} while (*dirs != NULL);
	}
}

void _dl_rtld_di_serinfo(struct link_map *loader, Dl_serinfo *si, bool counting)
{
	if (counting)
	{
		si->dls_cnt = 0;
		si->dls_size = 0;
	}

	struct add_path_state p =
		{
			.counting = counting,
			.idx = 0,
			.si = si,
			.allocptr = (char *)&si->dls_serpath[si->dls_cnt]};

#define add_path(p, sps, flags) add_path(p, sps, 0) /* XXX */

	/* When the object has the RUNPATH information we don't use any RPATHs.  */
	if (loader->l_info[DT_RUNPATH] == NULL)
	{
		/* First try the DT_RPATH of the dependent object that caused NAME
	   to be loaded.  Then that object's dependent, and on up.  */

		struct link_map *l = loader;
		do
		{
			if (cache_rpath(l, &l->l_rpath_dirs, DT_RPATH, "RPATH"))
				add_path(&p, &l->l_rpath_dirs, XXX_RPATH);
			l = l->l_loader;
		} while (l != NULL);

		/* If dynamically linked, try the DT_RPATH of the executable itself.  */
		if (loader->l_ns == LM_ID_BASE)
		{
			l = GL(dl_ns)[LM_ID_BASE]._ns_loaded;
			if (l != NULL && l->l_type != lt_loaded && l != loader)
				if (cache_rpath(l, &l->l_rpath_dirs, DT_RPATH, "RPATH"))
					add_path(&p, &l->l_rpath_dirs, XXX_RPATH);
		}
	}

	/* Try the LD_LIBRARY_PATH environment variable.  */
	add_path(&p, &__rtld_env_path_list, XXX_ENV);

	/* Look at the RUNPATH information for this binary.  */
	if (cache_rpath(loader, &loader->l_runpath_dirs, DT_RUNPATH, "RUNPATH"))
		add_path(&p, &loader->l_runpath_dirs, XXX_RUNPATH);

	/* XXX
	   Here is where ld.so.cache gets checked, but we don't have
	   a way to indicate that in the results for Dl_serinfo.  */

	/* Finally, try the default path.  */
	if (!(loader->l_flags_1 & DF_1_NODEFLIB))
		add_path(&p, &__rtld_search_dirs, XXX_default);

	if (counting)
		/* Count the struct size before the string area, which we didn't
		   know before we completed dls_cnt.  */
		si->dls_size += (char *)&si->dls_serpath[si->dls_cnt] - (char *)si;
}
