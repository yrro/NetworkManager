/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager audit support
 *
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
 * Copyright 2016 Red Hat, Inc.
 */

#include "nm-default.h"

#include <sys/mount.h>
#include <sched.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "nm-platform-utils.h"
#include "nmp-object.h"

#include "test-common.h"

#define SIGNAL_DATA_FMT "'%s-%s' ifindex %d%s%s%s (%d times received)"
#define SIGNAL_DATA_ARG(data) (data)->name, nm_platform_signal_change_type_to_string ((data)->change_type), (data)->ifindex, (data)->ifname ? " ifname '" : "", (data)->ifname ? (data)->ifname : "", (data)->ifname ? "'" : "", (data)->received_count

/*****************************************************************************/

gboolean
nmtstp_is_root_test (void)
{
	NM_PRAGMA_WARNING_DISABLE("-Wtautological-compare")
	return (SETUP == nm_linux_platform_setup);
	NM_PRAGMA_WARNING_REENABLE
}

gboolean
nmtstp_is_sysfs_writable (void)
{
	return    !nmtstp_is_root_test ()
	       || (access ("/sys/devices", W_OK) == 0);
}

static void
_init_platform (NMPlatform **platform, gboolean external_command)
{
	g_assert (platform);
	if (!*platform)
		*platform = NM_PLATFORM_GET;
	g_assert (NM_IS_PLATFORM (*platform));

	if (external_command)
		g_assert (NM_IS_LINUX_PLATFORM (*platform));
}

/*****************************************************************************/

SignalData *
add_signal_full (const char *name, NMPlatformSignalChangeType change_type, GCallback callback, int ifindex, const char *ifname)
{
	SignalData *data = g_new0 (SignalData, 1);

	data->name = name;
	data->change_type = change_type;
	data->received_count = 0;
	data->handler_id = g_signal_connect (NM_PLATFORM_GET, name, callback, data);
	data->ifindex = ifindex;
	data->ifname = ifname;

	g_assert (data->handler_id > 0);

	return data;
}

void
_accept_signal (const char *file, int line, const char *func, SignalData *data)
{
	_LOGD ("NMPlatformSignalAssert: %s:%d, %s(): Accepting signal one time: "SIGNAL_DATA_FMT, file, line, func, SIGNAL_DATA_ARG (data));
	if (data->received_count != 1)
		g_error ("NMPlatformSignalAssert: %s:%d, %s(): failure to accept signal one time: "SIGNAL_DATA_FMT, file, line, func, SIGNAL_DATA_ARG (data));
	data->received_count = 0;
}

void
_accept_signals (const char *file, int line, const char *func, SignalData *data, int min, int max)
{
	_LOGD ("NMPlatformSignalAssert: %s:%d, %s(): Accepting signal [%d,%d] times: "SIGNAL_DATA_FMT, file, line, func, min, max, SIGNAL_DATA_ARG (data));
	if (data->received_count < min || data->received_count > max)
		g_error ("NMPlatformSignalAssert: %s:%d, %s(): failure to accept signal [%d,%d] times: "SIGNAL_DATA_FMT, file, line, func, min, max, SIGNAL_DATA_ARG (data));
	data->received_count = 0;
}

void
_ensure_no_signal (const char *file, int line, const char *func, SignalData *data)
{
	_LOGD ("NMPlatformSignalAssert: %s:%d, %s(): Accepting signal 0 times: "SIGNAL_DATA_FMT, file, line, func, SIGNAL_DATA_ARG (data));
	if (data->received_count > 0)
		g_error ("NMPlatformSignalAssert: %s:%d, %s(): failure to accept signal 0 times: "SIGNAL_DATA_FMT, file, line, func, SIGNAL_DATA_ARG (data));
}

void
_accept_or_wait_signal (const char *file, int line, const char *func, SignalData *data)
{
	_LOGD ("NMPlatformSignalAssert: %s:%d, %s(): accept-or-wait signal: "SIGNAL_DATA_FMT, file, line, func, SIGNAL_DATA_ARG (data));
	if (data->received_count == 0) {
		data->loop = g_main_loop_new (NULL, FALSE);
		g_main_loop_run (data->loop);
		g_clear_pointer (&data->loop, g_main_loop_unref);
	}

	_accept_signal (file, line, func, data);
}

void
_wait_signal (const char *file, int line, const char *func, SignalData *data)
{
	_LOGD ("NMPlatformSignalAssert: %s:%d, %s(): wait signal: "SIGNAL_DATA_FMT, file, line, func, SIGNAL_DATA_ARG (data));
	if (data->received_count)
		g_error ("NMPlatformSignalAssert: %s:%d, %s(): failure to wait for signal: "SIGNAL_DATA_FMT, file, line, func, SIGNAL_DATA_ARG (data));

	data->loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (data->loop);
	g_clear_pointer (&data->loop, g_main_loop_unref);

	_accept_signal (file, line, func, data);
}

void
_free_signal (const char *file, int line, const char *func, SignalData *data)
{
	_LOGD ("NMPlatformSignalAssert: %s:%d, %s(): free signal: "SIGNAL_DATA_FMT, file, line, func, SIGNAL_DATA_ARG (data));
	if (data->received_count != 0)
		g_error ("NMPlatformSignalAssert: %s:%d, %s(): failure to free non-accepted signal: "SIGNAL_DATA_FMT, file, line, func, SIGNAL_DATA_ARG (data));

	g_signal_handler_disconnect (NM_PLATFORM_GET, data->handler_id);
	g_free (data);
}

void
link_callback (NMPlatform *platform, NMPObjectType obj_type, int ifindex, NMPlatformLink *received, NMPlatformSignalChangeType change_type, SignalData *data)
{
	GArray *links;
	NMPlatformLink *cached;
	int i;

	g_assert (received);
	g_assert_cmpint (received->ifindex, ==, ifindex);
	g_assert (data && data->name);
	g_assert_cmpstr (data->name, ==, NM_PLATFORM_SIGNAL_LINK_CHANGED);

	if (data->ifindex && data->ifindex != received->ifindex)
		return;
	if (data->ifname && g_strcmp0 (data->ifname, nm_platform_link_get_name (NM_PLATFORM_GET, ifindex)) != 0)
		return;
	if (change_type != data->change_type)
		return;

	if (data->loop) {
		_LOGD ("Quitting main loop.");
		g_main_loop_quit (data->loop);
	}

	data->received_count++;
	_LOGD ("Received signal '%s-%s' ifindex %d ifname '%s' %dth time.", data->name, nm_platform_signal_change_type_to_string (data->change_type), ifindex, received->name, data->received_count);

	if (change_type == NM_PLATFORM_SIGNAL_REMOVED)
		g_assert (!nm_platform_link_get_name (NM_PLATFORM_GET, ifindex));
	else
		g_assert (nm_platform_link_get_name (NM_PLATFORM_GET, ifindex));

	/* Check the data */
	g_assert (received->ifindex > 0);
	links = nm_platform_link_get_all (NM_PLATFORM_GET);
	for (i = 0; i < links->len; i++) {
		cached = &g_array_index (links, NMPlatformLink, i);
		if (cached->ifindex == received->ifindex) {
			g_assert_cmpint (nm_platform_link_cmp (cached, received), ==, 0);
			g_assert (!memcmp (cached, received, sizeof (*cached)));
			if (data->change_type == NM_PLATFORM_SIGNAL_REMOVED)
				g_error ("Deleted link still found in the local cache.");
			g_array_unref (links);
			return;
		}
	}
	g_array_unref (links);

	if (data->change_type != NM_PLATFORM_SIGNAL_REMOVED)
		g_error ("Added/changed link not found in the local cache.");
}

/*****************************************************************************/

static int
_sort_routes (gconstpointer p_a, gconstpointer p_b, gpointer user_data)
{
	gboolean is_v4 = GPOINTER_TO_INT (user_data);

	if (is_v4)
		return nm_platform_ip4_route_cmp (p_a, p_b);
	else
		return nm_platform_ip6_route_cmp (p_a, p_b);
}

const NMPlatformIPXRoute **
nmtstp_ip_route_get_by_destination (NMPlatform *platform,
                                    gboolean is_v4,
                                    int ifindex,
                                    const NMIPAddr *network,
                                    guint8 plen,
                                    guint32 metric,
                                    const NMIPAddr *gateway,
                                    guint *out_len)
{
	gs_unref_array GArray *routes = NULL;
	GPtrArray *result = NULL;
	gs_unref_hashtable GHashTable *check_dupes = NULL;
	NMIPAddr network_clean;
	guint i;

	g_assert (ifindex >= 0);
	g_assert (plen >= 0 && plen <= (is_v4 ? 32 : 128));

	NM_SET_OUT (out_len, 0);

	_init_platform (&platform, FALSE);

	check_dupes = g_hash_table_new ((GHashFunc) nmp_object_id_hash, (GEqualFunc) nmp_object_id_equal);
	result = g_ptr_array_new ();

	network = nm_utils_ipx_address_clear_host_address (is_v4 ? AF_INET : AF_INET6,
	                                                   &network_clean,
	                                                   network ?: &nm_ip_addr_zero,
	                                                   plen);

	if (!is_v4)
		metric = nm_utils_ip6_route_metric_normalize (metric);

	if (is_v4)
		routes = nm_platform_ip4_route_get_all (platform, ifindex, NM_PLATFORM_GET_ROUTE_FLAGS_WITH_RTPROT_KERNEL);
	else
		routes = nm_platform_ip6_route_get_all (platform, ifindex, NM_PLATFORM_GET_ROUTE_FLAGS_WITH_RTPROT_KERNEL);

	for (i = 0; routes && i < routes->len; i++) {
		const NMPlatformIPXRoute *r_i = is_v4
		                                ? (NMPlatformIPXRoute *) &g_array_index (routes, NMPlatformIP4Route, i)
		                                : (NMPlatformIPXRoute *) &g_array_index (routes, NMPlatformIP6Route, i);
		const NMPlatformIPXRoute *r_2;
		const NMPObject *o_2;

		g_assert (r_i->rx.ifindex == ifindex);

		if (   r_i->rx.plen != plen
		    || r_i->rx.metric != metric)
			continue;

		if (is_v4) {
			if (r_i->r4.network != *((guint32 *) network))
				continue;
			if (   gateway
			    && r_i->r4.gateway != *((guint32 *) gateway))
				continue;
		} else {
			if (!IN6_ARE_ADDR_EQUAL (&r_i->r6.network, network))
				continue;
			if (   gateway
			    && !IN6_ARE_ADDR_EQUAL (&r_i->r6.gateway, gateway))
				continue;
		}

		r_2 = is_v4
		     ? (NMPlatformIPXRoute *) nm_platform_ip4_route_get (platform, &r_i->r4)
		     : (NMPlatformIPXRoute *) nm_platform_ip6_route_get (platform, &r_i->r6);
		g_assert (r_2);
		g_assert (   ( is_v4 && nm_platform_ip4_route_cmp (&r_i->r4, &r_2->r4) == 0)
		          || (!is_v4 && nm_platform_ip6_route_cmp (&r_i->r6, &r_2->r6) == 0));

		o_2 = NMP_OBJECT_UP_CAST (r_2);
		g_assert (NMP_OBJECT_IS_VALID (o_2));
		g_assert (NMP_OBJECT_GET_TYPE (o_2) == (is_v4 ? NMP_OBJECT_TYPE_IP4_ROUTE : NMP_OBJECT_TYPE_IP6_ROUTE));

		g_ptr_array_add (result, (gpointer) r_2);
		if (!nm_g_hash_table_add (check_dupes, (gpointer) o_2))
			g_assert_not_reached ();
	}

	/* check whether the multi-index of the platform cache agrees... */
	if (NM_IS_LINUX_PLATFORM (platform)) {
		const NMPlatformObject *const *routes_cached;
		NMPCacheId cache_id;
		guint len;

		if (is_v4)
			nmp_cache_id_init_routes_by_destination_ip4 (&cache_id, network->addr4, plen, metric);
		else
			nmp_cache_id_init_routes_by_destination_ip6 (&cache_id, &network->addr6, plen, metric);

		routes_cached = nm_linux_platform_lookup (platform, &cache_id, &len);

		if (len)
			g_assert (routes_cached && routes_cached[len] == NULL);
		else
			g_assert (!routes_cached);

		for (i =0; routes_cached && i < len; i++) {
			const NMPObject *o;
			const NMPObject *o_2;

			g_assert (routes_cached [i]);
			o = NMP_OBJECT_UP_CAST (routes_cached [i]);
			g_assert (NMP_OBJECT_IS_VALID (o));
			g_assert (NMP_OBJECT_GET_TYPE (o) == (is_v4 ? NMP_OBJECT_TYPE_IP4_ROUTE : NMP_OBJECT_TYPE_IP6_ROUTE));

			if (gateway) {
				if (   ( is_v4 && o->ip4_route.gateway != *((guint32 *) gateway))
				    || (!is_v4 && !IN6_ARE_ADDR_EQUAL (&o->ip6_route.gateway, gateway)))
					continue;
			}

			o_2 = g_hash_table_lookup (check_dupes, o);
			g_assert (o_2);
			g_assert (o_2 == o);

			if (!g_hash_table_remove (check_dupes, o))
				g_assert_not_reached ();
		}

		g_assert (g_hash_table_size (check_dupes) == 0);
	}

	if (result->len > 0) {
		g_ptr_array_sort_with_data (result, _sort_routes, GINT_TO_POINTER (!!is_v4));
		NM_SET_OUT (out_len, result->len);
		g_ptr_array_add (result, NULL);
		return (gpointer) g_ptr_array_free (result, FALSE);
	}
	g_ptr_array_unref (result);
	return NULL;
}


gboolean
nmtstp_ip4_route_exists (const char *ifname, guint32 network, guint8 plen, guint32 metric, const guint32 *gateway)
{
	gs_free char *arg_network = NULL;
	const char *argv[] = {
		NULL,
		"route",
		"list",
		"dev",
		ifname,
		"exact",
		NULL,
		NULL,
	};
	int exit_status;
	gs_free char *std_out = NULL, *std_err = NULL;
	char *out;
	gboolean success;
	gs_free_error GError *error = NULL;
	gs_free char *metric_pattern = NULL;
	gs_free char *via_pattern = NULL;

	g_assert (ifname && nm_utils_iface_valid_name (ifname));
	g_assert (!strstr (ifname, " metric "));
	g_assert (plen >= 0 && plen <= 32);

	if (!nmtstp_is_root_test ()) {
		/* If we don't test against linux-platform, we don't actually configure any
		 * routes in the system. */
		return -1;
	}

	argv[0] = nm_utils_file_search_in_paths ("ip", NULL,
	                                         (const char *[]) { "/sbin", "/usr/sbin", NULL },
	                                         G_FILE_TEST_IS_EXECUTABLE, NULL, NULL, NULL);
	argv[6] = arg_network = g_strdup_printf ("%s/%d", nm_utils_inet4_ntop (network, NULL), plen);

	if (!argv[0]) {
		/* Hm. There is no 'ip' binary. Return *unknown* */
		return -1;
	}

	success = g_spawn_sync (NULL,
	                        (char **) argv,
	                        (char *[]) { NULL },
	                        0,
	                        NULL,
	                        NULL,
	                        &std_out,
	                        &std_err,
	                        &exit_status,
	                        &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert_cmpstr (std_err, ==, "");
	g_assert (std_out);

	metric_pattern = g_strdup_printf (" metric %u", metric);
	via_pattern = gateway ? g_strdup_printf (" via %s", nm_utils_inet4_ntop (*gateway, NULL)) : NULL;
	out = std_out;
	while (out) {
		char *eol = strchr (out, '\n');
		gs_free char *line = eol ? g_strndup (out, eol - out) : g_strdup (out);
		const char *p;

		out = eol ? &eol[1] : NULL;
		if (!line[0])
			continue;

		if (metric == 0) {
			if (strstr (line, " metric "))
				continue;
		} else {
			p = strstr (line, metric_pattern);
			if (!p || !NM_IN_SET (p[strlen (metric_pattern)], ' ', '\0'))
				continue;
		}

		if (gateway) {
			if (*gateway == 0) {
				if (strstr (line, " via "))
					continue;
			} else {
				p = strstr (line, via_pattern);
				if (!p || !NM_IN_SET (p[strlen (via_pattern)], ' ', '\0'))
					continue;
			}
		}
		return TRUE;
	}
	return FALSE;
}

const NMPlatformIP4Route *
_nmtstp_assert_ip4_route_exists (const char *file,
                                 guint line,
                                 const char *func,
                                 NMPlatform *platform,
                                 gboolean exists,
                                 const char *ifname,
                                 guint32 network,
                                 guint8 plen,
                                 guint32 metric,
                                 const guint32 *gateway)
{
	int ifindex;
	gboolean exists_checked;
	char s_buf[NM_UTILS_INET_ADDRSTRLEN];
	gs_free const NMPlatformIP4Route **routes = NULL;
	guint len;

	_init_platform (&platform, FALSE);

	/* Check for existance of the route by spawning iproute2. Do this because platform
	 * code might be entirely borked, but we expect ip-route to give a correct result.
	 * If the ip command cannot be found, we accept this as success. */
	exists_checked = nmtstp_ip4_route_exists (ifname, network, plen, metric, gateway);
	if (exists_checked != -1 && !exists_checked != !exists) {
		g_error ("[%s:%u] %s(): We expect the ip4 route %s/%d%s metric %u %s, but it %s",
		         file, line, func,
		         nm_utils_inet4_ntop (network, NULL), plen,
		         gateway ? nm_sprintf_bufa (100, " gateway %s", nm_utils_inet4_ntop (*gateway, s_buf)) : " no-gateway",
		         metric,
		         exists ? "to exist" : "not to exist",
		         exists ? "doesn't" : "does");
	}

	ifindex = nm_platform_link_get_ifindex (platform, ifname);
	g_assert (ifindex > 0);

	routes = (gpointer) nmtstp_ip_route_get_by_destination (platform, TRUE, ifindex, (NMIPAddr *) &network,
	                                                        plen, metric, (NMIPAddr *) gateway, &len);
	if (routes) {
		if (!exists) {
			g_error ("[%s:%u] %s(): The ip4 route %s/%d via %s metric %u %s, but platform thinks %s",
			         file, line, func,
			         nm_utils_inet4_ntop (network, NULL),
			         plen,
			         nm_utils_inet4_ntop (gateway ? *gateway : 0, s_buf),
			         metric,
			         exists ? "exists" : "does not exist",
			         exists ? "it doesn't" : "it does");
		}
		g_assert (len == 1);
		return routes[0];
	} else {
		if (exists) {
			g_error ("[%s:%u] %s(): The ip4 route %s/%d via %s metric %u %s, but platform thinks %s",
			         file, line, func,
			         nm_utils_inet4_ntop (network, NULL),
			         plen,
			         nm_utils_inet4_ntop (gateway ? *gateway : 0, s_buf),
			         metric,
			         exists ? "exists" : "does not exist",
			         exists ? "it doesn't" : "it does");
		}
		return NULL;
	}
}

/*****************************************************************************/

int
nmtstp_run_command (const char *format, ...)
{
	int result;
	gs_free char *command = NULL;
	va_list ap;

	va_start (ap, format);
	command = g_strdup_vprintf (format, ap);
	va_end (ap);

	_LOGD ("Running command: %s", command);
	result = system (command);
	_LOGD ("Command finished: result=%d", result);

	return result;
}

/*****************************************************************************/

typedef struct {
	GMainLoop *loop;
	guint signal_counts;
	guint id;
} WaitForSignalData;

static void
_wait_for_signal_cb (NMPlatform *platform,
                     NMPObjectType obj_type,
                     int ifindex,
                     NMPlatformLink *plink,
                     NMPlatformSignalChangeType change_type,
                     gpointer user_data)
{
	WaitForSignalData *data = user_data;

	data->signal_counts++;
	nm_clear_g_source (&data->id);
	g_main_loop_quit (data->loop);
}

static gboolean
_wait_for_signal_timeout (gpointer user_data)
{
	WaitForSignalData *data = user_data;

	g_assert (data->id);
	data->id = 0;
	g_main_loop_quit (data->loop);
	return G_SOURCE_REMOVE;
}

guint
nmtstp_wait_for_signal (NMPlatform *platform, guint timeout_ms)
{
	WaitForSignalData data = { 0 };
	gulong id_link, id_ip4_address, id_ip6_address, id_ip4_route, id_ip6_route;

	_init_platform (&platform, FALSE);

	data.loop = g_main_loop_new (NULL, FALSE);

	id_link        = g_signal_connect (platform, NM_PLATFORM_SIGNAL_LINK_CHANGED, G_CALLBACK (_wait_for_signal_cb), &data);
	id_ip4_address = g_signal_connect (platform, NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED, G_CALLBACK (_wait_for_signal_cb), &data);
	id_ip6_address = g_signal_connect (platform, NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED, G_CALLBACK (_wait_for_signal_cb), &data);
	id_ip4_route   = g_signal_connect (platform, NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED, G_CALLBACK (_wait_for_signal_cb), &data);
	id_ip6_route   = g_signal_connect (platform, NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED, G_CALLBACK (_wait_for_signal_cb), &data);

	if (timeout_ms != 0)
		data.id = g_timeout_add (timeout_ms, _wait_for_signal_timeout, &data);

	g_main_loop_run (data.loop);

	g_assert (!data.id);
	g_assert (nm_clear_g_signal_handler (platform, &id_link));
	g_assert (nm_clear_g_signal_handler (platform, &id_ip4_address));
	g_assert (nm_clear_g_signal_handler (platform, &id_ip6_address));
	g_assert (nm_clear_g_signal_handler (platform, &id_ip4_route));
	g_assert (nm_clear_g_signal_handler (platform, &id_ip6_route));

	g_clear_pointer (&data.loop, g_main_loop_unref);

	/* return the number of signals, or 0 if timeout was reached .*/
	return data.signal_counts;
}

guint
nmtstp_wait_for_signal_until (NMPlatform *platform, gint64 until_ms)
{
	gint64 now;
	guint signal_counts;

	while (TRUE) {
		now = nm_utils_get_monotonic_timestamp_ms ();

		if (until_ms < now)
			return 0;

		signal_counts = nmtstp_wait_for_signal (platform, MAX (1, until_ms - now));
		if (signal_counts)
			return signal_counts;
	}
}

const NMPlatformLink *
nmtstp_wait_for_link (NMPlatform *platform, const char *ifname, NMLinkType expected_link_type, guint timeout_ms)
{
	return nmtstp_wait_for_link_until (platform, ifname, expected_link_type, nm_utils_get_monotonic_timestamp_ms () + (gint64) timeout_ms);
}

const NMPlatformLink *
nmtstp_wait_for_link_until (NMPlatform *platform, const char *ifname, NMLinkType expected_link_type, gint64 until_ms)
{
	const NMPlatformLink *plink;
	gint64 now;

	_init_platform (&platform, FALSE);

	while (TRUE) {
		now = nm_utils_get_monotonic_timestamp_ms ();

		plink = nm_platform_link_get_by_ifname (platform, ifname);
		if (   plink
		    && (expected_link_type == NM_LINK_TYPE_NONE || plink->type == expected_link_type))
			return plink;

		if (until_ms < now)
			return NULL;

		nmtstp_wait_for_signal (platform, MAX (1, until_ms - now));
	}
}

const NMPlatformLink *
nmtstp_assert_wait_for_link (NMPlatform *platform, const char *ifname, NMLinkType expected_link_type, guint timeout_ms)
{
	return nmtstp_assert_wait_for_link_until (platform, ifname, expected_link_type, nm_utils_get_monotonic_timestamp_ms () + (gint64) timeout_ms);
}

const NMPlatformLink *
nmtstp_assert_wait_for_link_until (NMPlatform *platform, const char *ifname, NMLinkType expected_link_type, gint64 until_ms)
{
	const NMPlatformLink *plink;

	plink = nmtstp_wait_for_link_until (platform, ifname, expected_link_type, until_ms);
	g_assert (plink);
	return plink;
}

/*****************************************************************************/

static const void *
_wait_for_ip_route_until (NMPlatform *platform, int is_v4, int ifindex, const NMIPAddr *network, guint8 plen, guint32 metric, const NMIPAddr *gateway, gint64 until_ms)
{
	gint64 now;

	_init_platform (&platform, FALSE);

	while (TRUE) {
		gs_free const NMPlatformIPXRoute **routes = NULL;

		now = nm_utils_get_monotonic_timestamp_ms ();

		routes = nmtstp_ip_route_get_by_destination (platform, is_v4, ifindex, network, plen, metric, gateway, NULL);
		if (routes)
			return routes[0];

		if (until_ms < now)
			return NULL;

		nmtstp_wait_for_signal (platform, MAX (1, until_ms - now));
	}
}

const NMPlatformIP4Route *
nmtstp_wait_for_ip4_route (NMPlatform *platform, int ifindex, guint32 network, guint8 plen, guint32 metric, guint32 gateway, guint timeout_ms)
{
	return _wait_for_ip_route_until (platform, TRUE, ifindex, (NMIPAddr *) &network, plen, metric, (NMIPAddr *) &gateway, nm_utils_get_monotonic_timestamp_ms () + (gint64) timeout_ms);
}

const NMPlatformIP4Route *
nmtstp_wait_for_ip4_route_until (NMPlatform *platform, int ifindex, guint32 network, guint8 plen, guint32 metric, guint32 gateway, gint64 until_ms)
{
	return _wait_for_ip_route_until (platform, TRUE, ifindex, (NMIPAddr *) &network, plen, metric, (NMIPAddr *) &gateway, until_ms);
}

const NMPlatformIP6Route *
nmtstp_wait_for_ip6_route (NMPlatform *platform, int ifindex, const struct in6_addr *network, guint8 plen, guint32 metric, const struct in6_addr *gateway, guint timeout_ms)
{
	return _wait_for_ip_route_until (platform, FALSE, ifindex, (NMIPAddr *) network, plen, metric, (NMIPAddr *) gateway, nm_utils_get_monotonic_timestamp_ms () + (gint64) timeout_ms);
}

const NMPlatformIP6Route *
nmtstp_wait_for_ip6_route_until (NMPlatform *platform, int ifindex, const struct in6_addr *network, guint8 plen, guint32 metric, const struct in6_addr *gateway, gint64 until_ms)
{
	return _wait_for_ip_route_until (platform, FALSE, ifindex, (NMIPAddr *) network, plen, metric, (NMIPAddr *) gateway, until_ms);
}

/*****************************************************************************/

int
nmtstp_run_command_check_external_global (void)
{
	if (!nmtstp_is_root_test ())
		return FALSE;
	switch (nmtst_get_rand_int () % 3) {
	case 0:
		return -1;
	case 1:
		return FALSE;
	default:
		return TRUE;
	}
}

gboolean
nmtstp_run_command_check_external (int external_command)
{
	if (external_command != -1) {
		g_assert (NM_IN_SET (external_command, FALSE, TRUE));
		g_assert (!external_command || nmtstp_is_root_test ());
		return !!external_command;
	}
	if (!nmtstp_is_root_test ())
		return FALSE;
	return (nmtst_get_rand_int () % 2) == 0;
}

/*****************************************************************************/

#define CHECK_LIFETIME_MAX_DIFF    2

gboolean
nmtstp_ip_address_check_lifetime (const NMPlatformIPAddress *addr,
                                  gint64 now,
                                  guint32 expected_lifetime,
                                  guint32 expected_preferred)
{
	gint64 offset;
	int i;

	g_assert (addr);

	if (now == -1)
		now = nm_utils_get_monotonic_timestamp_s ();
	g_assert (now > 0);

	g_assert (expected_preferred <= expected_lifetime);

	if (   expected_lifetime == NM_PLATFORM_LIFETIME_PERMANENT
	    && expected_lifetime == NM_PLATFORM_LIFETIME_PERMANENT) {
		return    addr->timestamp == 0
		       && addr->lifetime == NM_PLATFORM_LIFETIME_PERMANENT
		       && addr->preferred == NM_PLATFORM_LIFETIME_PERMANENT;
	}

	if (addr->timestamp == 0)
		return FALSE;

	offset = (gint64) now - addr->timestamp;

	for (i = 0; i < 2; i++) {
		guint32 lft = i ? expected_lifetime : expected_preferred;
		guint32 adr = i ? addr->lifetime : addr->preferred;

		if (lft == NM_PLATFORM_LIFETIME_PERMANENT) {
			if (adr != NM_PLATFORM_LIFETIME_PERMANENT)
				return FALSE;
		} else {
			if (   adr - offset <= lft - CHECK_LIFETIME_MAX_DIFF
			    || adr - offset >= lft + CHECK_LIFETIME_MAX_DIFF)
				return FALSE;
		}
	}
	return TRUE;
}

void
nmtstp_ip_address_assert_lifetime (const NMPlatformIPAddress *addr,
                                   gint64 now,
                                   guint32 expected_lifetime,
                                   guint32 expected_preferred)
{
	gint64 n = now;
	gint64 offset;
	int i;

	g_assert (addr);

	if (now == -1)
		now = nm_utils_get_monotonic_timestamp_s ();
	g_assert (now > 0);

	g_assert (expected_preferred <= expected_lifetime);

	if (   expected_lifetime == NM_PLATFORM_LIFETIME_PERMANENT
	    && expected_lifetime == NM_PLATFORM_LIFETIME_PERMANENT) {
		g_assert_cmpint (addr->timestamp, ==, 0);
		g_assert_cmpint (addr->lifetime, ==, NM_PLATFORM_LIFETIME_PERMANENT);
		g_assert_cmpint (addr->preferred, ==, NM_PLATFORM_LIFETIME_PERMANENT);
		return;
	}

	g_assert_cmpint (addr->timestamp, >, 0);
	g_assert_cmpint (addr->timestamp, <=, now);

	offset = (gint64) now - addr->timestamp;
	g_assert_cmpint (offset, >=, 0);

	for (i = 0; i < 2; i++) {
		guint32 lft = i ? expected_lifetime : expected_preferred;
		guint32 adr = i ? addr->lifetime : addr->preferred;

		if (lft == NM_PLATFORM_LIFETIME_PERMANENT)
			g_assert_cmpint (adr, ==, NM_PLATFORM_LIFETIME_PERMANENT);
		else {
			g_assert_cmpint (adr, <=, lft);
			g_assert_cmpint (offset, <=, adr);
			g_assert_cmpint (adr - offset, <=, lft + CHECK_LIFETIME_MAX_DIFF);
			g_assert_cmpint (adr - offset, >=, lft - CHECK_LIFETIME_MAX_DIFF);
		}
	}

	g_assert (nmtstp_ip_address_check_lifetime (addr, n, expected_lifetime, expected_preferred));
}

/*****************************************************************************/

static void
_ip_address_add (NMPlatform *platform,
                 gboolean external_command,
                 gboolean is_v4,
                 int ifindex,
                 const NMIPAddr *address,
                 guint8 plen,
                 const NMIPAddr *peer_address,
                 guint32 lifetime,
                 guint32 preferred,
                 guint32 flags,
                 const char *label)
{
	gint64 end_time;

	external_command = nmtstp_run_command_check_external (external_command);

	_init_platform (&platform, external_command);

	if (external_command) {
		const char *ifname;
		gs_free char *s_valid = NULL;
		gs_free char *s_preferred = NULL;
		gs_free char *s_label = NULL;
		char b1[NM_UTILS_INET_ADDRSTRLEN], b2[NM_UTILS_INET_ADDRSTRLEN];

		ifname = nm_platform_link_get_name (platform, ifindex);
		g_assert (ifname);

		if (lifetime != NM_PLATFORM_LIFETIME_PERMANENT)
			s_valid = g_strdup_printf (" valid_lft %d", lifetime);
		if (preferred != NM_PLATFORM_LIFETIME_PERMANENT)
			s_preferred = g_strdup_printf (" preferred_lft %d", preferred);
		if (label)
			s_label = g_strdup_printf ("%s:%s", ifname, label);

		if (is_v4) {
			char s_peer[100];

			g_assert (flags == 0);

			if (   peer_address->addr4 != address->addr4
			    || nmtst_get_rand_int () % 2) {
				/* If the peer is the same as the local address, we can omit it. The result should be identical */
				g_snprintf (s_peer, sizeof (s_peer), " peer %s", nm_utils_inet4_ntop (peer_address->addr4, b2));
			} else
				s_peer[0] = '\0';

			nmtstp_run_command_check ("ip address change %s%s/%d dev %s%s%s%s",
			                          nm_utils_inet4_ntop (address->addr4, b1),
			                          s_peer,
			                          plen,
			                          ifname,
			                          s_valid ?: "",
			                          s_preferred ?: "",
			                          s_label ?: "");
		} else {
			g_assert (label == NULL);

			/* flags not implemented (yet) */
			g_assert (flags == 0);
			nmtstp_run_command_check ("ip address change %s%s%s/%d dev %s%s%s%s",
			                          nm_utils_inet6_ntop (&address->addr6, b1),
			                          !IN6_IS_ADDR_UNSPECIFIED (&peer_address->addr6) ? " peer " : "",
			                          !IN6_IS_ADDR_UNSPECIFIED (&peer_address->addr6) ? nm_utils_inet6_ntop (&peer_address->addr6, b2) : "",
			                          plen,
			                          ifname,
			                          s_valid ?: "",
			                          s_preferred ?: "",
			                          s_label ?: "");
		}
	} else {
		gboolean success;

		if (is_v4) {
			success = nm_platform_ip4_address_add (platform,
			                                       ifindex,
			                                       address->addr4,
			                                       plen,
			                                       peer_address->addr4,
			                                       lifetime,
			                                       preferred,
			                                       flags,
			                                       label);
		} else {
			g_assert (label == NULL);
			success = nm_platform_ip6_address_add (platform,
			                                       ifindex,
			                                       address->addr6,
			                                       plen,
			                                       peer_address->addr6,
			                                       lifetime,
			                                       preferred,
			                                       flags);
		}
		g_assert (success);
	}

	/* Let's wait until we see the address. */
	end_time = nm_utils_get_monotonic_timestamp_ms () + 250;
	do {

		if (external_command)
			nm_platform_process_events (platform);

		/* let's wait until we see the address as we added it. */
		if (is_v4) {
			const NMPlatformIP4Address *a;

			g_assert (flags == 0);
			a = nm_platform_ip4_address_get (platform, ifindex, address->addr4, plen, peer_address->addr4);
			if (   a
			    && a->peer_address == peer_address->addr4
			    && nmtstp_ip_address_check_lifetime ((NMPlatformIPAddress*) a, -1, lifetime, preferred)
			    && strcmp (a->label, label ?: "") == 0)
				break;
		} else {
			const NMPlatformIP6Address *a;

			g_assert (label == NULL);
			g_assert (flags == 0);

			a = nm_platform_ip6_address_get (platform, ifindex, address->addr6, plen);
			if (   a
			    && !memcmp (nm_platform_ip6_address_get_peer (a),
			                (IN6_IS_ADDR_UNSPECIFIED (&peer_address->addr6) || IN6_ARE_ADDR_EQUAL (&address->addr6, &peer_address->addr6))
			                    ? &address->addr6 : &peer_address->addr6,
			                sizeof (struct in6_addr))
			    && nmtstp_ip_address_check_lifetime ((NMPlatformIPAddress*) a, -1, lifetime, preferred))
				break;
		}

		/* for internal command, we expect not to reach this line.*/
		g_assert (external_command);

		nmtstp_assert_wait_for_signal_until (platform, end_time);
	} while (TRUE);
}

void
nmtstp_ip4_address_add (NMPlatform *platform,
                        gboolean external_command,
                        int ifindex,
                        in_addr_t address,
                        guint8 plen,
                        in_addr_t peer_address,
                        guint32 lifetime,
                        guint32 preferred,
                        guint32 flags,
                        const char *label)
{
	_ip_address_add (platform,
	                 external_command,
	                 TRUE,
	                 ifindex,
	                 (NMIPAddr *) &address,
	                 plen,
	                 (NMIPAddr *) &peer_address,
	                 lifetime,
	                 preferred,
	                 flags,
	                 label);
}

void
nmtstp_ip6_address_add (NMPlatform *platform,
                        gboolean external_command,
                        int ifindex,
                        struct in6_addr address,
                        guint8 plen,
                        struct in6_addr peer_address,
                        guint32 lifetime,
                        guint32 preferred,
                        guint32 flags)
{
	_ip_address_add (platform,
	                 external_command,
	                 FALSE,
	                 ifindex,
	                 (NMIPAddr *) &address,
	                 plen,
	                 (NMIPAddr *) &peer_address,
	                 lifetime,
	                 preferred,
	                 flags,
	                 NULL);
}

/*****************************************************************************/

static void
_ip_address_del (NMPlatform *platform,
                 gboolean external_command,
                 gboolean is_v4,
                 int ifindex,
                 const NMIPAddr *address,
                 guint8 plen,
                 const NMIPAddr *peer_address)
{
	gint64 end_time;

	external_command = nmtstp_run_command_check_external (external_command);

	_init_platform (&platform, external_command);

	if (external_command) {
		const char *ifname;
		char b1[NM_UTILS_INET_ADDRSTRLEN], b2[NM_UTILS_INET_ADDRSTRLEN];
		int success;
		gboolean had_address;

		ifname = nm_platform_link_get_name (platform, ifindex);
		g_assert (ifname);

		/* let's wait until we see the address as we added it. */
		if (is_v4)
			had_address = !!nm_platform_ip4_address_get (platform, ifindex, address->addr4, plen, peer_address->addr4);
		else
			had_address = !!nm_platform_ip6_address_get (platform, ifindex, address->addr6, plen);

		if (is_v4) {
			success = nmtstp_run_command ("ip address delete %s%s%s/%d dev %s",
			                              nm_utils_inet4_ntop (address->addr4, b1),
			                              peer_address->addr4 != address->addr4 ? " peer " : "",
			                              peer_address->addr4 != address->addr4 ? nm_utils_inet4_ntop (peer_address->addr4, b2) : "",
			                              plen,
			                              ifname);
		} else {
			g_assert (!peer_address);
			success = nmtstp_run_command ("ip address delete %s/%d dev %s",
			                              nm_utils_inet6_ntop (&address->addr6, b1),
			                              plen,
			                              ifname);
		}
		g_assert (success == 0 || !had_address);
	} else {
		gboolean success;

		if (is_v4) {
			success = nm_platform_ip4_address_delete (platform,
			                                          ifindex,
			                                          address->addr4,
			                                          plen,
			                                          peer_address->addr4);
		} else {
			g_assert (!peer_address);
			success = nm_platform_ip6_address_delete (platform,
			                                          ifindex,
			                                          address->addr6,
			                                          plen);
		}
		g_assert (success);
	}

	/* Let's wait until we get the result */
	end_time = nm_utils_get_monotonic_timestamp_ms () + 250;
	do {
		if (external_command)
			nm_platform_process_events (platform);

		/* let's wait until we see the address as we added it. */
		if (is_v4) {
			const NMPlatformIP4Address *a;

			a = nm_platform_ip4_address_get (platform, ifindex, address->addr4, plen, peer_address->addr4);
			if (!a)
				break;
		} else {
			const NMPlatformIP6Address *a;

			a = nm_platform_ip6_address_get (platform, ifindex, address->addr6, plen);
			if (!a)
				break;
		}

		/* for internal command, we expect not to reach this line.*/
		g_assert (external_command);

		nmtstp_assert_wait_for_signal_until (platform, end_time);
	} while (TRUE);
}

void
nmtstp_ip4_address_del (NMPlatform *platform,
                        gboolean external_command,
                        int ifindex,
                        in_addr_t address,
                        guint8 plen,
                        in_addr_t peer_address)
{
	_ip_address_del (platform,
	                 external_command,
	                 TRUE,
	                 ifindex,
	                 (NMIPAddr *) &address,
	                 plen,
	                 (NMIPAddr *) &peer_address);
}

void
nmtstp_ip6_address_del (NMPlatform *platform,
                        gboolean external_command,
                        int ifindex,
                        struct in6_addr address,
                        guint8 plen)
{
	_ip_address_del (platform,
	                 external_command,
	                 FALSE,
	                 ifindex,
	                 (NMIPAddr *) &address,
	                 plen,
	                 NULL);
}

/*****************************************************************************/

static gconstpointer
_ip_route_add (NMPlatform *platform,
               gboolean external_command,
               gboolean is_v4,
               const NMPlatformIPXRoute *route)
{
	gint64 end_time;
	char s_network[NM_UTILS_INET_ADDRSTRLEN];
	char s_gateway[NM_UTILS_INET_ADDRSTRLEN];
	char s_pref_src[NM_UTILS_INET_ADDRSTRLEN];
	const NMPlatformLink *pllink;
	NMPObject obj_normalized;
	const NMPlatformIPXRoute *route_orig;
	guint i, len;

	g_assert (route);
	g_assert (route->rx.ifindex > 0);

	external_command = nmtstp_run_command_check_external (external_command);

	_init_platform (&platform, external_command);

	route_orig = route;
	if (is_v4)
		nmp_object_stackinit_id_ip4_route (&obj_normalized, &route->r4, NM_PLATFORM_IP_ROUTE_ID_TYPE_ID);
	else
		nmp_object_stackinit_id_ip6_route (&obj_normalized, &route->r6, NM_PLATFORM_IP_ROUTE_ID_TYPE_ID);
	route = &obj_normalized.ipx_route;

	pllink = nmtstp_link_get (platform, route->rx.ifindex, NULL);
	g_assert (pllink);

	if (external_command) {
		s_network[0] = '\0';
		s_gateway[0] = '\0';
		s_pref_src[0] = '\0';
		if (is_v4) {
			nm_utils_inet4_ntop (route->r4.network, s_network);
			if (route->r4.gateway)
				nm_utils_inet4_ntop (route->r4.gateway, s_gateway);
			if (route->r4.pref_src)
				nm_utils_inet4_ntop (route->r4.pref_src, s_pref_src);
		} else {
			nm_utils_inet6_ntop (&route->r6.network, s_network);
			if (!IN6_IS_ADDR_UNSPECIFIED (&route->r6.gateway))
				nm_utils_inet6_ntop (&route->r6.gateway, s_gateway);
		}

		nmtstp_run_command_check ("ip route append %s/%u%s dev '%s' metric %u proto %u%s%s",
		                          s_network,
		                          route->rx.plen,
		                          s_gateway[0] ? nm_sprintf_bufa (100, " via %s", s_gateway) : "",
		                          pllink->name,
		                          route->rx.metric,
		                          nmp_utils_ip_config_source_coerce_to_rtprot (route->r4.rt_source),
		                          s_pref_src[0] ? nm_sprintf_bufa (100, " src %s", s_pref_src) : "",
		                          route->rx.mss ? nm_sprintf_bufa (100, " advmss %u", route->rx.mss) : "");
	} else {
		gboolean success;

		if (is_v4)
			success = nm_platform_ip4_route_add (platform, &route_orig->r4);
		else
			success = nm_platform_ip6_route_add (platform, &route_orig->r6);
		g_assert (success);
	}

	/* Let's wait until we see the address. */
	end_time = nm_utils_get_monotonic_timestamp_ms () + 250;
	do {
		gs_free const NMPlatformIPXRoute **routes = NULL;

		if (external_command)
			nm_platform_process_events (platform);

		/* let's wait until we see the address as we added it. */
		routes = nmtstp_ip_route_get_by_destination (platform, is_v4, route->rx.ifindex,
		                                             (NMIPAddr *) route->rx.network_ptr,
		                                             route->rx.plen,
		                                             route->rx.metric,
		                                             is_v4 ? (NMIPAddr *) &route->r4.gateway : (NMIPAddr *) &route->r6.gateway,
		                                             &len);
		for (i = 0; i < len; i++) {
			const NMPObject *o2;

			o2 = NMP_OBJECT_UP_CAST (routes[i]);
			if (nmp_object_equal (o2, &obj_normalized))
				return &o2->ipx_route;
		}

		/* for internal command, we expect not to reach this line.*/
		g_assert (external_command);

		nmtstp_assert_wait_for_signal_until (platform, end_time);
	} while (TRUE);
}

const NMPlatformIP4Route *
nmtstp_ip4_route_add (NMPlatform *platform, gboolean external_command,
                      const NMPlatformIP4Route *route)
{
	return _ip_route_add (platform, external_command, TRUE, (const NMPlatformIPXRoute *) route);
}

const NMPlatformIP6Route *
nmtstp_ip6_route_add (NMPlatform *platform, gboolean external_command,
                      const NMPlatformIP6Route *route)
{
	return _ip_route_add (platform, external_command, FALSE, (const NMPlatformIPXRoute *) route);
}

/*****************************************************************************/

#define _assert_pllink(platform, success, pllink, name, type) \
	G_STMT_START { \
		const NMPlatformLink *_pllink = (pllink); \
		\
		if ((success)) { \
			g_assert (_pllink); \
			g_assert (_pllink == nmtstp_link_get_typed (platform, _pllink->ifindex, (name), (type))); \
		} else { \
			g_assert (!_pllink); \
			g_assert (!nmtstp_link_get (platform, 0, (name))); \
		} \
	} G_STMT_END

const NMPlatformLink *
nmtstp_link_dummy_add (NMPlatform *platform,
                       gboolean external_command,
                       const char *name)
{
	const NMPlatformLink *pllink = NULL;
	gboolean success;

	g_assert (nm_utils_iface_valid_name (name));

	external_command = nmtstp_run_command_check_external (external_command);

	_init_platform (&platform, external_command);

	if (external_command) {
		success = !nmtstp_run_command ("ip link add %s type dummy",
		                                name);
		if (success)
			pllink = nmtstp_assert_wait_for_link (platform, name, NM_LINK_TYPE_DUMMY, 100);
	} else
		success = nm_platform_link_dummy_add (platform, name, &pllink) == NM_PLATFORM_ERROR_SUCCESS;

	g_assert (success);
	_assert_pllink (platform, success, pllink, name, NM_LINK_TYPE_DUMMY);
	return pllink;
}

const NMPlatformLink *
nmtstp_link_gre_add (NMPlatform *platform,
                     gboolean external_command,
                     const char *name,
                     const NMPlatformLnkGre *lnk)
{
	const NMPlatformLink *pllink = NULL;
	gboolean success;
	char buffer[INET_ADDRSTRLEN];

	g_assert (nm_utils_iface_valid_name (name));

	external_command = nmtstp_run_command_check_external (external_command);

	_init_platform (&platform, external_command);

	if (external_command) {
		gs_free char *dev = NULL;

		if (lnk->parent_ifindex)
			dev = g_strdup_printf ("dev %s", nm_platform_link_get_name (platform, lnk->parent_ifindex));

		success = !nmtstp_run_command ("ip tunnel add %s mode gre %s local %s remote %s ttl %u tos %02x %s",
		                                name,
		                                dev ? dev : "",
		                                nm_utils_inet4_ntop (lnk->local, NULL),
		                                nm_utils_inet4_ntop (lnk->remote, buffer),
		                                lnk->ttl,
		                                lnk->tos,
		                                lnk->path_mtu_discovery ? "pmtudisc" : "nopmtudisc");
		if (success)
			pllink = nmtstp_assert_wait_for_link (platform, name, NM_LINK_TYPE_GRE, 100);
	} else
		success = nm_platform_link_gre_add (platform, name, lnk, &pllink) == NM_PLATFORM_ERROR_SUCCESS;

	_assert_pllink (platform, success, pllink, name, NM_LINK_TYPE_GRE);

	return pllink;
}

const NMPlatformLink *
nmtstp_link_ip6tnl_add (NMPlatform *platform,
                        gboolean external_command,
                        const char *name,
                        const NMPlatformLnkIp6Tnl *lnk)
{
	const NMPlatformLink *pllink = NULL;
	gboolean success;
	char buffer[INET6_ADDRSTRLEN];

	g_assert (nm_utils_iface_valid_name (name));

	external_command = nmtstp_run_command_check_external (external_command);

	_init_platform (&platform, external_command);

	if (external_command) {
		gs_free char *dev = NULL;
		const char *mode;

		if (lnk->parent_ifindex)
			dev = g_strdup_printf ("dev %s", nm_platform_link_get_name (platform, lnk->parent_ifindex));

		switch (lnk->proto) {
		case IPPROTO_IPIP:
			mode = "ipip6";
			break;
		case IPPROTO_IPV6:
			mode = "ip6ip6";
			break;
		default:
			g_assert_not_reached ();
		}

		success = !nmtstp_run_command ("ip -6 tunnel add %s mode %s %s local %s remote %s ttl %u tclass %02x encaplimit %u flowlabel %x",
		                                name,
		                                mode,
		                                dev,
		                                nm_utils_inet6_ntop (&lnk->local, NULL),
		                                nm_utils_inet6_ntop (&lnk->remote, buffer),
		                                lnk->ttl,
		                                lnk->tclass,
		                                lnk->encap_limit,
		                                lnk->flow_label);
		if (success)
			pllink = nmtstp_assert_wait_for_link (platform, name, NM_LINK_TYPE_IP6TNL, 100);
	} else
		success = nm_platform_link_ip6tnl_add (platform, name, lnk, &pllink) == NM_PLATFORM_ERROR_SUCCESS;

	_assert_pllink (platform, success, pllink, name, NM_LINK_TYPE_IP6TNL);

	return pllink;
}

const NMPlatformLink *
nmtstp_link_ipip_add (NMPlatform *platform,
                      gboolean external_command,
                      const char *name,
                      const NMPlatformLnkIpIp *lnk)
{
	const NMPlatformLink *pllink = NULL;
	gboolean success;
	char buffer[INET_ADDRSTRLEN];

	g_assert (nm_utils_iface_valid_name (name));

	external_command = nmtstp_run_command_check_external (external_command);

	_init_platform (&platform, external_command);

	if (external_command) {
		gs_free char *dev = NULL;

		if (lnk->parent_ifindex)
			dev = g_strdup_printf ("dev %s", nm_platform_link_get_name (platform, lnk->parent_ifindex));

		success = !nmtstp_run_command ("ip tunnel add %s mode ipip %s local %s remote %s ttl %u tos %02x %s",
		                                name,
		                                dev,
		                                nm_utils_inet4_ntop (lnk->local, NULL),
		                                nm_utils_inet4_ntop (lnk->remote, buffer),
		                                lnk->ttl,
		                                lnk->tos,
		                                lnk->path_mtu_discovery ? "pmtudisc" : "nopmtudisc");
		if (success)
			pllink = nmtstp_assert_wait_for_link (platform, name, NM_LINK_TYPE_IPIP, 100);
	} else
		success = nm_platform_link_ipip_add (platform, name, lnk, &pllink) == NM_PLATFORM_ERROR_SUCCESS;

	_assert_pllink (platform, success, pllink, name, NM_LINK_TYPE_IPIP);

	return pllink;
}

const NMPlatformLink *
nmtstp_link_macvlan_add (NMPlatform *platform,
                         gboolean external_command,
                         const char *name,
                         int parent,
                         const NMPlatformLnkMacvlan *lnk)
{
	const NMPlatformLink *pllink = NULL;
	gboolean success;
	NMLinkType link_type;

	g_assert (nm_utils_iface_valid_name (name));

	external_command = nmtstp_run_command_check_external (external_command);

	_init_platform (&platform, external_command);

	link_type = lnk->tap ? NM_LINK_TYPE_MACVTAP : NM_LINK_TYPE_MACVLAN;

	if (external_command) {
		const char *dev;
		char *modes[] = {
				[MACVLAN_MODE_BRIDGE]   = "bridge",
				[MACVLAN_MODE_VEPA]     = "vepa",
				[MACVLAN_MODE_PRIVATE]  = "private",
				[MACVLAN_MODE_PASSTHRU] = "passthru",
		};

		dev = nm_platform_link_get_name (platform, parent);
		g_assert (dev);
		g_assert_cmpint (lnk->mode, <, G_N_ELEMENTS (modes));

		success = !nmtstp_run_command ("ip link add name %s link %s type %s mode %s %s",
		                                name,
		                                dev,
		                                lnk->tap ? "macvtap" : "macvlan",
		                                modes[lnk->mode],
		                                lnk->no_promisc ? "nopromisc" : "");
		if (success)
			pllink = nmtstp_assert_wait_for_link (platform, name, link_type, 100);
	} else
		success = nm_platform_link_macvlan_add (platform, name, parent, lnk, &pllink) == NM_PLATFORM_ERROR_SUCCESS;

	_assert_pllink (platform, success, pllink, name, link_type);

	return pllink;
}

const NMPlatformLink *
nmtstp_link_sit_add (NMPlatform *platform,
                     gboolean external_command,
                     const char *name,
                     const NMPlatformLnkSit *lnk)
{
	const NMPlatformLink *pllink = NULL;
	gboolean success;
	char buffer[INET_ADDRSTRLEN];

	g_assert (nm_utils_iface_valid_name (name));

	external_command = nmtstp_run_command_check_external (external_command);

	_init_platform (&platform, external_command);

	if (external_command) {
		const char *dev = "";

		if (lnk->parent_ifindex) {
			const char *parent_name;

			parent_name = nm_platform_link_get_name (platform, lnk->parent_ifindex);
			g_assert (parent_name);
			dev = nm_sprintf_bufa (100, " dev %s", parent_name);
		}

		success = !nmtstp_run_command ("ip tunnel add %s mode sit%s local %s remote %s ttl %u tos %02x %s",
		                                name,
		                                dev,
		                                nm_utils_inet4_ntop (lnk->local, NULL),
		                                nm_utils_inet4_ntop (lnk->remote, buffer),
		                                lnk->ttl,
		                                lnk->tos,
		                                lnk->path_mtu_discovery ? "pmtudisc" : "nopmtudisc");
		if (success)
			pllink = nmtstp_assert_wait_for_link (platform, name, NM_LINK_TYPE_SIT, 100);
	} else
		success = nm_platform_link_sit_add (platform, name, lnk, &pllink) == NM_PLATFORM_ERROR_SUCCESS;

	_assert_pllink (platform, success, pllink, name, NM_LINK_TYPE_SIT);

	return pllink;
}

const NMPlatformLink *
nmtstp_link_vxlan_add (NMPlatform *platform,
                       gboolean external_command,
                       const char *name,
                       const NMPlatformLnkVxlan *lnk)
{
	const NMPlatformLink *pllink = NULL;
	NMPlatformError plerr;
	int err;

	g_assert (nm_utils_iface_valid_name (name));

	external_command = nmtstp_run_command_check_external (external_command);

	_init_platform (&platform, external_command);

	if (external_command) {
		gs_free char *dev = NULL;
		gs_free char *local = NULL, *remote = NULL;

		if (lnk->parent_ifindex)
			dev = g_strdup_printf ("dev %s", nm_platform_link_get_name (platform, lnk->parent_ifindex));

		if (lnk->local)
			local = g_strdup_printf ("%s", nm_utils_inet4_ntop (lnk->local, NULL));
		else if (memcmp (&lnk->local6, &in6addr_any, sizeof (in6addr_any)))
			local = g_strdup_printf ("%s", nm_utils_inet6_ntop (&lnk->local6, NULL));

		if (lnk->group)
			remote = g_strdup_printf ("%s", nm_utils_inet4_ntop (lnk->group, NULL));
		else if (memcmp (&lnk->group6, &in6addr_any, sizeof (in6addr_any)))
			remote = g_strdup_printf ("%s", nm_utils_inet6_ntop (&lnk->group6, NULL));

		err = nmtstp_run_command ("ip link add %s type vxlan id %u %s local %s group %s ttl %u tos %02x dstport %u srcport %u %u ageing %u",
		                          name,
		                          lnk->id,
		                          dev ? dev : "",
		                          local,
		                          remote,
		                          lnk->ttl,
		                          lnk->tos,
		                          lnk->dst_port,
		                          lnk->src_port_min, lnk->src_port_max,
		                          lnk->ageing);
		/* Older versions of iproute2 don't support adding vxlan devices.
		 * On failure, fallback to using platform code. */
		if (err == 0)
			pllink = nmtstp_assert_wait_for_link (platform, name, NM_LINK_TYPE_VXLAN, 100);
		else
			_LOGI ("Adding vxlan device via iproute2 failed. Assume iproute2 is not up to the task.");
	}
	if (!pllink) {
		plerr = nm_platform_link_vxlan_add (platform, name, lnk, &pllink);
		g_assert_cmpint (plerr, ==, NM_PLATFORM_ERROR_SUCCESS);
		g_assert (pllink);
	}

	g_assert_cmpint (pllink->type, ==, NM_LINK_TYPE_VXLAN);
	g_assert_cmpstr (pllink->name, ==, name);
	return pllink;
}

/*****************************************************************************/

const NMPlatformLink *
nmtstp_link_get_typed (NMPlatform *platform,
                       int ifindex,
                       const char *name,
                       NMLinkType link_type)
{
	const NMPlatformLink *pllink = NULL;

	_init_platform (&platform, FALSE);

	if (ifindex > 0) {
		pllink = nm_platform_link_get (platform, ifindex);

		if (pllink) {
			g_assert_cmpint (pllink->ifindex, ==, ifindex);
			if (name)
				g_assert_cmpstr (name, ==, pllink->name);
		} else {
			if (name)
				g_assert (!nm_platform_link_get_by_ifname (platform, name));
		}
	} else {
		g_assert (name);

		pllink = nm_platform_link_get_by_ifname (platform, name);

		if (pllink)
			g_assert_cmpstr (name, ==, pllink->name);
	}

	g_assert (!name || nm_utils_iface_valid_name (name));

	if (pllink && link_type != NM_LINK_TYPE_NONE)
		g_assert_cmpint (pllink->type, ==, link_type);

	return pllink;
}

const NMPlatformLink *
nmtstp_link_get (NMPlatform *platform,
                 int ifindex,
                 const char *name)
{
	return nmtstp_link_get_typed (platform, ifindex, name, NM_LINK_TYPE_NONE);
}

/*****************************************************************************/

void
nmtstp_link_del (NMPlatform *platform,
                 gboolean external_command,
                 int ifindex,
                 const char *name)
{
	gint64 end_time;
	const NMPlatformLink *pllink;
	gboolean success;
	gs_free char *name_copy = NULL;

	external_command = nmtstp_run_command_check_external (external_command);

	_init_platform (&platform, external_command);

	pllink = nmtstp_link_get (platform, ifindex, name);

	g_assert (pllink);

	name = name_copy = g_strdup (pllink->name);
	ifindex = pllink->ifindex;

	if (external_command) {
		nmtstp_run_command_check ("ip link delete %s", name);
	} else {
		success = nm_platform_link_delete (platform, ifindex);
		g_assert (success);
	}

	/* Let's wait until we get the result */
	end_time = nm_utils_get_monotonic_timestamp_ms () + 250;
	do {
		if (external_command)
			nm_platform_process_events (platform);

		if (!nm_platform_link_get (platform, ifindex)) {
			g_assert (!nm_platform_link_get_by_ifname (platform, name));
			break;
		}

		/* for internal command, we expect not to reach this line.*/
		g_assert (external_command);

		nmtstp_assert_wait_for_signal_until (platform, end_time);
	} while (TRUE);
}

/*****************************************************************************/

void
nmtstp_link_set_updown (NMPlatform *platform,
                        gboolean external_command,
                        int ifindex,
                        gboolean up)
{
	const NMPlatformLink *plink;
	gint64 end_time;

	external_command = nmtstp_run_command_check_external (external_command);

	_init_platform (&platform, external_command);

	if (external_command) {
		const char *ifname;

		ifname = nm_platform_link_get_name (platform, ifindex);
		g_assert (ifname);

		nmtstp_run_command_check ("ip link set %s %s",
		                          ifname,
		                          up ? "up" : "down");
	} else {
		if (up)
			g_assert (nm_platform_link_set_up (platform, ifindex, NULL));
		else
			g_assert (nm_platform_link_set_down (platform, ifindex));
	}

	/* Let's wait until we get the result */
	end_time = nm_utils_get_monotonic_timestamp_ms () + 250;
	do {
		if (external_command)
			nm_platform_process_events (platform);

		/* let's wait until we see the address as we added it. */
		plink = nm_platform_link_get (platform, ifindex);
		g_assert (plink);

		if (NM_FLAGS_HAS (plink->n_ifi_flags, IFF_UP) == !!up)
			break;

		/* for internal command, we expect not to reach this line.*/
		g_assert (external_command);

		nmtstp_assert_wait_for_signal_until (platform, end_time);
	} while (TRUE);
}

/*****************************************************************************/

struct _NMTstpNamespaceHandle {
	pid_t pid;
	int pipe_fd;
};

NMTstpNamespaceHandle *
nmtstp_namespace_create (int unshare_flags, GError **error)
{
	NMTstpNamespaceHandle *ns_handle;
	int e;
	int errsv;
	pid_t pid, pid2;
	int pipefd_c2p[2];
	int pipefd_p2c[2];
	ssize_t r;

	e = pipe (pipefd_c2p);
	if (e != 0) {
		errsv = errno;
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "pipe() failed with %d (%s)", errsv, strerror (errsv));
		return FALSE;
	}

	e = pipe (pipefd_p2c);
	if (e != 0) {
		errsv = errno;
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "pipe() failed with %d (%s)", errsv, strerror (errsv));
		close (pipefd_c2p[0]);
		close (pipefd_c2p[1]);
		return FALSE;
	}

	pid = fork ();
	if (pid < 0) {
		errsv = errno;
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "fork() failed with %d (%s)", errsv, strerror (errsv));
		close (pipefd_c2p[0]);
		close (pipefd_c2p[1]);
		close (pipefd_p2c[0]);
		close (pipefd_p2c[1]);
		return FALSE;
	}

	if (pid == 0) {
		char read_buf[1];

		close (pipefd_c2p[0]); /* close read-end */
		close (pipefd_p2c[1]); /* close write-end */

		if (unshare (unshare_flags) != 0) {
			errsv = errno;
			if (errsv == 0)
				errsv = -1;
		} else
			errsv = 0;

		/* sync with parent process and send result. */
		do {
			r = write (pipefd_c2p[1], &errsv, sizeof (errsv));
		} while (r < 0 && errno == EINTR);
		if (r != sizeof (errsv)) {
			errsv = errno;
			if (errsv == 0)
				errsv = -2;
		}
		close (pipefd_c2p[1]);

		/* wait until parent process terminates (or kills us). */
		if (errsv == 0) {
			do {
				r = read (pipefd_p2c[0], read_buf, sizeof (read_buf));
			} while (r < 0 && errno == EINTR);
		}
		close (pipefd_p2c[0]);
		_exit (0);
	}

	close (pipefd_c2p[1]); /* close write-end */
	close (pipefd_p2c[0]); /* close read-end */

	/* sync with child process. */
	do {
		r = read (pipefd_c2p[0], &errsv, sizeof (errsv));
	} while (r < 0 && errno == EINTR);

	close (pipefd_c2p[0]);

	if (   r != sizeof (errsv)
	    || errsv != 0) {
		int status;

		if (r != sizeof (errsv)) {
			g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
			             "child process failed for unknown reason");
		} else {
			g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
			             "child process signaled failure %d (%s)", errsv, strerror (errsv));
		}
		close (pipefd_p2c[1]);
		kill (pid, SIGKILL);
		do {
			pid2 = waitpid (pid, &status, 0);
		} while (pid2 == -1 && errno == EINTR);
		return FALSE;
	}

	ns_handle = g_new0 (NMTstpNamespaceHandle, 1);
	ns_handle->pid = pid;
	ns_handle->pipe_fd = pipefd_p2c[1];
	return ns_handle;
}

pid_t
nmtstp_namespace_handle_get_pid (NMTstpNamespaceHandle *ns_handle)
{
	g_return_val_if_fail (ns_handle, 0);
	g_return_val_if_fail (ns_handle->pid > 0, 0);

	return ns_handle->pid;
}

void
nmtstp_namespace_handle_release (NMTstpNamespaceHandle *ns_handle)
{
	pid_t pid;
	int status;

	if (!ns_handle)
		return;

	g_return_if_fail (ns_handle->pid > 0);

	close (ns_handle->pipe_fd);
	ns_handle->pipe_fd = 0;

	kill (ns_handle->pid, SIGKILL);

	do {
		pid = waitpid (ns_handle->pid, &status, 0);
	} while (pid == -1 && errno == EINTR);
	ns_handle->pid = 0;

	g_free (ns_handle);
}

int
nmtstp_namespace_get_fd_for_process (pid_t pid, const char *ns_name)
{
	char p[1000];

	g_return_val_if_fail (pid > 0, 0);
	g_return_val_if_fail (ns_name && ns_name[0] && strlen (ns_name) < 50, 0);

	nm_sprintf_buf (p, "/proc/%lu/ns/%s", (long unsigned) pid, ns_name);

	return open(p, O_RDONLY);
}

/*****************************************************************************/

NMTST_DEFINE();

static gboolean
unshare_user (void)
{
	FILE *f;
	uid_t uid = geteuid ();
	gid_t gid = getegid ();

	/* Already a root? */
	if (gid == 0 && uid == 0)
		return TRUE;

	/* Become a root in new user NS. */
	if (unshare (CLONE_NEWUSER) != 0)
		return FALSE;

	/* Since Linux 3.19 we have to disable setgroups() in order to map users.
	 * Just proceed if the file is not there. */
	f = fopen ("/proc/self/setgroups", "w");
	if (f) {
		fprintf (f, "deny");
		fclose (f);
	}

	/* Map current UID to root in NS to be created. */
	f = fopen ("/proc/self/uid_map", "w");
	if (!f)
		return FALSE;
	fprintf (f, "0 %d 1", uid);
	fclose (f);

	/* Map current GID to root in NS to be created. */
	f = fopen ("/proc/self/gid_map", "w");
	if (!f)
		return FALSE;
	fprintf (f, "0 %d 1", gid);
	fclose (f);

	return TRUE;
}

int
main (int argc, char **argv)
{
	int result;
	const char *program = *argv;

	_nmtstp_init_tests (&argc, &argv);

	if (   nmtstp_is_root_test ()
	    && (geteuid () != 0 || getegid () != 0)) {
		if (   g_getenv ("NMTST_FORCE_REAL_ROOT")
		    || !unshare_user ()) {
			/* Try to exec as sudo, this function does not return, if a sudo-cmd is set. */
			nmtst_reexec_sudo ();

#ifdef REQUIRE_ROOT_TESTS
			g_print ("Fail test: requires root privileges (%s)\n", program);
			return EXIT_FAILURE;
#else
			g_print ("Skipping test: requires root privileges (%s)\n", program);
			return g_test_run ();
#endif
		}
	}

	if (nmtstp_is_root_test () && !g_getenv ("NMTST_NO_UNSHARE")) {
		int errsv;

		if (unshare (CLONE_NEWNET | CLONE_NEWNS) != 0) {
			errsv = errno;
			g_error ("unshare(CLONE_NEWNET|CLONE_NEWNS) failed with %s (%d)", strerror (errsv), errsv);
		}

		/* Mount our /sys instance, so that gudev sees only our devices.
		 * Needs to be read-only, because we don't run udev. */
		mount (NULL, "/sys", "sysfs", MS_SLAVE, NULL);
		if (mount ("sys", "/sys", "sysfs", MS_RDONLY, NULL) != 0) {
			errsv = errno;
			g_error ("mount(\"/sys\") failed with %s (%d)", strerror (errsv), errsv);
		}

		/* Create a writable /sys/devices tree. This makes it possible to run tests
		 * that modify values via sysfs (such as bridge forward delay). */
		if (mount ("sys", "/sys/devices", "sysfs", 0, NULL) != 0) {
			errsv = errno;
			g_error ("mount(\"/sys/devices\") failed with %s (%d)", strerror (errsv), errsv);
		}
		if (mount (NULL, "/sys/devices", "sysfs", MS_REMOUNT, NULL) != 0) {
			/* Read-write remount failed. Never mind, we're probably just a root in
			 * our user NS. */
			if (umount ("/sys/devices") != 0) {
				errsv = errno;
				g_error ("umount(\"/sys/devices\") failed with  %s (%d)", strerror (errsv), errsv);
			}
		} else {
			if (mount ("/sys/devices/devices", "/sys/devices", "sysfs", MS_BIND, NULL) != 0) {
				errsv = errno;
				g_error ("mount(\"/sys\") failed with %s (%d)", strerror (errsv), errsv);
			}
		}
	}

	SETUP ();

	_nmtstp_setup_tests ();

	result = g_test_run ();

	nm_platform_link_delete (NM_PLATFORM_GET, nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME));

	g_object_unref (NM_PLATFORM_GET);
	return result;
}
