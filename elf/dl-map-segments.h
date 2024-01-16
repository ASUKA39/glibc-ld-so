/* Map in a shared object's segments.  Generic version.
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

#include <dl-load.h>

/* Map a segment and align it properly.  */
/* 映射一个段并对齐它。 */
// 在_dl_map_segments中调用
static __always_inline ElfW(Addr)
    _dl_map_segment(const struct loadcmd *c, ElfW(Addr) mappref,
                    const size_t maplength, int fd)
{
  if (__glibc_likely(c->mapalign <= GLRO(dl_pagesize)))   // 如果段对齐 <= 页大小
    return (ElfW(Addr))__mmap((void *)mappref, maplength, c->prot,    // 调用mmap系统调用将段映射到内存
                              MAP_COPY | MAP_FILE, fd, c->mapoff);

  /* If the segment alignment > the page size, allocate enough space to
     ensure that the segment can be properly aligned.  */
  /* 如果段对齐 > 页大小，则分配足够的空间以确保段可以正确对齐。 */
  ElfW(Addr) maplen = (maplength >= c->mapalign // 如果maplength >= mapalign，maplen = maplength，否则maplen = maplength + mapalign
                           ? (maplength + c->mapalign)
                           : (2 * c->mapalign));
  ElfW(Addr) map_start = (ElfW(Addr))__mmap((void *)mappref, maplen,    // 调用mmap系统调用将段映射到内存
                                            PROT_NONE,
                                            MAP_ANONYMOUS | MAP_PRIVATE,
                                            -1, 0);
  if (__glibc_unlikely((void *)map_start == MAP_FAILED))
    return map_start;

  ElfW(Addr) map_start_aligned = ALIGN_UP(map_start, c->mapalign);
  map_start_aligned = (ElfW(Addr))__mmap((void *)map_start_aligned,
                                         maplength, c->prot,
                                         MAP_COPY | MAP_FILE | MAP_FIXED,
                                         fd, c->mapoff);
  if (__glibc_unlikely((void *)map_start_aligned == MAP_FAILED))
    __munmap((void *)map_start, maplen);
  else
  {
    /* Unmap the unused regions.  */
    /* 取消映射未使用的区域。 */
    ElfW(Addr) delta = map_start_aligned - map_start;
    if (delta)
      __munmap((void *)map_start, delta);
    ElfW(Addr) map_end = map_start_aligned + maplength;
    map_end = ALIGN_UP(map_end, GLRO(dl_pagesize));
    delta = map_start + maplen - map_end;
    if (delta)
      __munmap((void *)map_end, delta);
  }

  return map_start_aligned;
}

/* This implementation assumes (as does the corresponding implementation
   of _dl_unmap_segments, in dl-unmap-segments.h) that shared objects
   are always laid out with all segments contiguous (or with gaps
   between them small enough that it's preferable to reserve all whole
   pages inside the gaps with PROT_NONE mappings rather than permitting
   other use of those parts of the address space).  */
/* 此实现假定（与 dl-unmap-segments.h 中的 _dl_unmap_segments 的相应实现一样），
   共享对象总是以所有段连续的方式布局（或者在它们之间的间隙足够小，以至于最好保留间隙内
   所有整页的 PROT_NONE 映射，而不是允许地址空间的这些部分的其他用途）。 */
static __always_inline const char *
_dl_map_segments(struct link_map *l, int fd,
                 const ElfW(Ehdr) * header, int type,               // ELF头部、共享库类型
                 const struct loadcmd loadcmds[], size_t nloadcmds, // 加载命令
                 const size_t maplength, bool has_holes,            // 映射长度、是否有空洞
                 struct link_map *loader)                           // 需要加载的动态库的link_map
{
  const struct loadcmd *c = loadcmds;

  if (__glibc_likely(type == ET_DYN))   // 如果是动态库
  {
    /* This is a position-independent shared object.  We can let the
       kernel map it anywhere it likes, but we must have space for all
       the segments in their specified positions relative to the first.
       So we map the first segment without MAP_FIXED, but with its
       extent increased to cover all the segments.  Then we remove
       access from excess portion, and there is known sufficient space
       there to remap from the later segments.

       As a refinement, sometimes we have an address that we would
       prefer to map such objects at; but this is only a preference,
       the OS can do whatever it likes. */
    /* 这是一个位置无关的共享对象。我们可以让内核将其映射到任何位置，但是我们必须为所有段
       在其相对于第一个段的指定位置上保留空间。因此，我们将第一个段映射到一个没有
       MAP_FIXED 的地址，但是其范围扩展到覆盖所有段。然后我们从多余的部分删除访问权限，
       并且已知在那里有足够的空间从后面的段重新映射。

       作为一个细节，有时我们有一个地址，我们希望在这个地址上映射这样的对象；但是这只是
       一个偏好，操作系统可以做任何它想做的事情。 */
    ElfW(Addr) mappref                                // 计算出的映射的首选地址（绝对地址）
        = (ELF_PREFERRED_ADDRESS(loader, maplength,   // mappref = ELF_PREFERRED_ADDRESS - MAP_BASE_ADDR，得到相对于基地址的偏移量
                                 c->mapstart & GLRO(dl_use_load_bias)) - // 是否使用加载偏移
           MAP_BASE_ADDR(l));                                             // 加载器的基地址，似乎是历史包袱，但对于大多数平台而言实际宏定义为0，所以实际mappref计算出的就是绝对地址

    /* Remember which part of the address space this object uses.  */
    /* 记录该对象使用的地址空间的哪一部分。 */
    l->l_map_start = _dl_map_segment(c, mappref, maplength, fd); // 调用_dl_map_segment映射段到内存，返回映射的首地址到l_map_start
    if (__glibc_unlikely((void *)l->l_map_start == MAP_FAILED))  // 映射失败与否
      return DL_MAP_SEGMENTS_ERROR_MAP_SEGMENT;

    l->l_map_end = l->l_map_start + maplength; // 记录映射的结束地址
    l->l_addr = l->l_map_start - c->mapstart;  // 记录映射的起始地址

    if (has_holes) // 如果映射空间存在空洞
    {
      /* Change protection on the excess portion to disallow all access;
         the portions we do not remap later will be inaccessible as if
         unallocated.  Then jump into the normal segment-mapping loop to
         handle the portion of the segment past the end of the file
         mapping.  */
      /* 将多余部分的保护更改为禁止所有访问；我们稍后不重新映射的部分将无法访问，就像未分配一样。
         然后跳转到正常的段映射循环中，以处理超出文件映射结束的段的部分。 */
      if (__glibc_unlikely(loadcmds[nloadcmds - 1].mapstart <
                           c->mapend))
        return N_("ELF load command address/offset not page-aligned");
      if (__glibc_unlikely(__mprotect((caddr_t)(l->l_addr + c->mapend), // 使用mprotect系统调用将空洞更改为禁止访问
                                      loadcmds[nloadcmds - 1].mapstart - c->mapend,
                                      PROT_NONE) < 0))
        return DL_MAP_SEGMENTS_ERROR_MPROTECT;
    }

    l->l_contiguous = 1; // 表示映射是连续的，没有空洞

    goto postmap;
  }

  /* Remember which part of the address space this object uses.  */
  /* 记录该对象使用的地址空间的哪一部分。 */
  l->l_map_start = c->mapstart + l->l_addr;  // 记录映射的起始地址
  l->l_map_end = l->l_map_start + maplength; // 记录映射的结束地址
  l->l_contiguous = !has_holes;              // 记录映射是否连续（是否存在空洞）

  while (c < &loadcmds[nloadcmds]) // 遍历加载命令
  {
    if (c->mapend > c->mapstart
        /* Map the segment contents from the file.  */
        /* 从文件映射段内容。 */
        && (__mmap((void *)(l->l_addr + c->mapstart), // 调用mmap系统调用将段映射到内存
                   c->mapend - c->mapstart, c->prot,
                   MAP_FIXED | MAP_COPY | MAP_FILE,
                   fd, c->mapoff) == MAP_FAILED))
      return DL_MAP_SEGMENTS_ERROR_MAP_SEGMENT;

  postmap:
    _dl_postprocess_loadcmd(l, header, c); // 调用_dl_postprocess_loadcmd处理加载命令

    if (c->allocend > c->dataend) // 如果段的分配结束地址大于数据结束地址，如果是表示中间存在空洞
    {
      /* Extra zero pages should appear at the end of this segment,
         after the data mapped from the file.   */
      /* 零页应该出现在该段的末尾，在从文件映射的数据之后。 */
      ElfW(Addr) zero, zeroend, zeropage;

      zero = l->l_addr + c->dataend;
      zeroend = l->l_addr + c->allocend;
      zeropage = ((zero + GLRO(dl_pagesize) - 1) & ~(GLRO(dl_pagesize) - 1));

      if (zeroend < zeropage)
        /* All the extra data is in the last page of the segment.
           We can just zero it.  */
        /* 所有额外的数据都在段的最后一页中。我们可以将其置零。 */
        zeropage = zeroend;

      if (zeropage > zero)
      {
        /* Zero the final part of the last page of the segment.  */
        /* 将段的最后一页的最后一部分置零。 */
        if (__glibc_unlikely((c->prot & PROT_WRITE) == 0))
        {
          /* Dag nab it.  */
          if (__mprotect((caddr_t)(zero & ~(GLRO(dl_pagesize) - 1)),
                         GLRO(dl_pagesize), c->prot | PROT_WRITE) < 0) // 使用mprotect系统调用将空洞更改为禁止访问
            return DL_MAP_SEGMENTS_ERROR_MPROTECT;
        }
        memset((void *)zero, '\0', zeropage - zero);
        if (__glibc_unlikely((c->prot & PROT_WRITE) == 0))
          __mprotect((caddr_t)(zero & ~(GLRO(dl_pagesize) - 1)), // 使用mprotect系统调用将空洞更改为禁止访问
                     GLRO(dl_pagesize), c->prot);
      }

      if (zeroend > zeropage) // 如果段的分配结束地址大于数据结束地址，如果是表示中间存在空洞
      {
        /* Map the remaining zero pages in from the zero fill FD.  */
        /* 从零填充 FD 中映射剩余的零页。 */
        caddr_t mapat;
        mapat = __mmap((caddr_t)zeropage, zeroend - zeropage, // 调用mmap系统调用将空洞映射到内存
                       c->prot, MAP_ANON | MAP_PRIVATE | MAP_FIXED,
                       -1, 0);
        if (__glibc_unlikely(mapat == MAP_FAILED))
          return DL_MAP_SEGMENTS_ERROR_MAP_ZERO_FILL;
      }
    }

    ++c;
  }

  /* Notify ELF_PREFERRED_ADDRESS that we have to load this one
     fixed.  */
  /* 通知 ELF_PREFERRED_ADDRESS 我们必须固定加载这个。 */
  ELF_FIXED_ADDRESS(loader, c->mapstart);

  return NULL;
}
