/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2008 - 2011 Red Hat, Inc.
 */

#ifndef __NM_GLIB_H__
#define __NM_GLIB_H__


#include <gio/gio.h>
#include <string.h>

#ifdef __clang__

#undef G_GNUC_BEGIN_IGNORE_DEPRECATIONS
#undef G_GNUC_END_IGNORE_DEPRECATIONS

#define G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")

#define G_GNUC_END_IGNORE_DEPRECATIONS \
    _Pragma("clang diagnostic pop")

#endif

/* g_assert_cmpmem() is only available since glib 2.46. */
#if !GLIB_CHECK_VERSION (2, 45, 7)
#define g_assert_cmpmem(m1, l1, m2, l2) G_STMT_START {\
                                             gconstpointer __m1 = m1, __m2 = m2; \
                                             int __l1 = l1, __l2 = l2; \
                                             if (__l1 != __l2) \
                                               g_assertion_message_cmpnum (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, \
                                                                           #l1 " (len(" #m1 ")) == " #l2 " (len(" #m2 "))", __l1, "==", __l2, 'i'); \
                                             else if (memcmp (__m1, __m2, __l1) != 0) \
                                               g_assertion_message (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, \
                                                                    "assertion failed (" #m1 " == " #m2 ")"); \
                                        } G_STMT_END
#endif

/* Rumtime check for glib version. First do a compile time check which
 * (if satisfied) shortcuts the runtime check. */
#define nm_glib_check_version(major, minor, micro) \
    (   GLIB_CHECK_VERSION ((major), (minor), (micro)) \
     || (   (   glib_major_version > (major)) \
         || (   glib_major_version == (major) \
             && glib_minor_version > (minor)) \
         || (   glib_major_version == (major) \
             && glib_minor_version == (minor) \
             && glib_micro_version >= (micro))))

#endif  /* __NM_GLIB_H__ */
