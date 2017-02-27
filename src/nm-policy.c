/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2004 - 2013 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-policy.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>

#include "NetworkManagerUtils.h"
#include "nm-act-request.h"
#include "devices/nm-device.h"
#include "nm-default-route-manager.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-connection.h"
#include "platform/nm-platform.h"
#include "dns/nm-dns-manager.h"
#include "vpn/nm-vpn-manager.h"
#include "nm-auth-utils.h"
#include "nm-firewall-manager.h"
#include "nm-dispatcher.h"
#include "nm-utils.h"
#include "nm-core-internal.h"
#include "nm-manager.h"
#include "settings/nm-settings.h"
#include "settings/nm-settings-connection.h"
#include "nm-dhcp4-config.h"
#include "nm-dhcp6-config.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMPolicy,
	PROP_MANAGER,
	PROP_SETTINGS,
	PROP_DEFAULT_IP4_DEVICE,
	PROP_DEFAULT_IP6_DEVICE,
	PROP_ACTIVATING_IP4_DEVICE,
	PROP_ACTIVATING_IP6_DEVICE,
);

typedef struct {
	NMManager *manager;
	NMFirewallManager *firewall_manager;
	GSList *pending_activation_checks;

	GHashTable *devices;

	GSList *pending_secondaries;

	gulong fw_started_id;

	NMSettings *settings;

	NMDevice *default_device4, *activating_device4;
	NMDevice *default_device6, *activating_device6;

	GResolver *resolver;
	GInetAddress *lookup_addr;
	GCancellable *lookup_cancellable;
	NMDnsManager *dns_manager;
	gulong config_changed_id;

	guint reset_retries_id;  /* idle handler for resetting the retries count */

	guint schedule_activate_all_id; /* idle handler for schedule_activate_all(). */

	char *orig_hostname; /* hostname at NM start time */
	char *cur_hostname;  /* hostname we want to assign */

	GArray *ip6_prefix_delegations; /* pool of ip6 prefixes delegated to all devices */
} NMPolicyPrivate;

struct _NMPolicy {
	GObject parent;
	NMPolicyPrivate _priv;
};

struct _NMPolicyClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMPolicy, nm_policy, G_TYPE_OBJECT)

#define NM_POLICY_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMPolicy, NM_IS_POLICY)

static NMPolicy *
_PRIV_TO_SELF (NMPolicyPrivate *priv)
{
	NMPolicy *self;

	nm_assert (priv);

	self = (NMPolicy *) (((char *) priv) - G_STRUCT_OFFSET (NMPolicy, _priv));

	nm_assert (NM_IS_POLICY (self));
	return self;
}

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME    "policy"
#define _NMLOG(level, domain, ...) \
    G_STMT_START { \
        nm_log ((level), (domain), \
                "%s" _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                _NMLOG_PREFIX_NAME": " \
                _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
    } G_STMT_END

/*****************************************************************************/

static void schedule_activate_all (NMPolicy *self);

/*****************************************************************************/

typedef struct {
	NMPlatformIP6Address prefix;
	NMDevice *device;             /* The requesting ("uplink") device */
	guint64 next_subnet;          /* Cache of the next subnet number to be
	                               * assigned from this prefix */
	GHashTable *subnets;          /* ifindex -> NMPlatformIP6Address */
} IP6PrefixDelegation;

static void
_clear_ip6_subnet (gpointer key, gpointer value, gpointer user_data)
{
	NMPlatformIP6Address *subnet = value;
	NMDevice *device = nm_manager_get_device_by_ifindex (nm_manager_get (),
	                                                     GPOINTER_TO_INT (key));

	if (device) {
		/* We can not remove a subnet we already started announcing.
		 * Just un-prefer it. */
		subnet->preferred = 0;
		nm_device_use_ip6_subnet (device, subnet);
	}
	g_slice_free (NMPlatformIP6Address, subnet);
}

static void
clear_ip6_prefix_delegation (gpointer data)
{
	IP6PrefixDelegation *delegation = data;

	_LOGD (LOGD_IP6, "ipv6-pd: undelegating prefix %s/%d",
	       nm_utils_inet6_ntop (&delegation->prefix.address, NULL),
	       delegation->prefix.plen);

	g_hash_table_foreach (delegation->subnets, _clear_ip6_subnet, NULL);
	g_hash_table_destroy (delegation->subnets);
}

static void
expire_ip6_delegations (NMPolicy *self)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	IP6PrefixDelegation *delegation = NULL;
	guint i;

	for (i = 0; i < priv->ip6_prefix_delegations->len; i++) {
		delegation = &g_array_index (priv->ip6_prefix_delegations,
		                             IP6PrefixDelegation, i);
		if (delegation->prefix.timestamp + delegation->prefix.lifetime < now)
			g_array_remove_index_fast (priv->ip6_prefix_delegations, i);
	}
}

/*
 * Try to obtain a new subnet for a particular active connection from given
 * delegated prefix, possibly reusing the existing subnet.
 * Return value of FALSE indicates no more subnets are available from
 * this prefix (and other prefix should be used -- and requested if necessary).
 */
static gboolean
ip6_subnet_from_delegation (IP6PrefixDelegation *delegation, NMDevice *device)
{
	NMPlatformIP6Address *subnet;
	int ifindex = nm_device_get_ifindex (device);

	subnet = g_hash_table_lookup (delegation->subnets, GINT_TO_POINTER (ifindex));
	if (!subnet) {
		/* Check for out-of-prefixes condition. */
		if (delegation->next_subnet >= (1 << (64 - delegation->prefix.plen))) {
			_LOGD (LOGD_IP6, "ipv6-pd: no more prefixes in %s/%d",
			       nm_utils_inet6_ntop (&delegation->prefix.address, NULL),
			       delegation->prefix.plen);
			return FALSE;
		}

		/* Allocate a new subnet. */
		subnet = g_slice_new0 (NMPlatformIP6Address);
		g_hash_table_insert (delegation->subnets, GINT_TO_POINTER (ifindex), subnet);

		subnet->plen = 64;
		subnet->address.s6_addr32[0] =   delegation->prefix.address.s6_addr32[0]
		                               | htonl (delegation->next_subnet >> 32);
		subnet->address.s6_addr32[1] =   delegation->prefix.address.s6_addr32[1]
		                               | htonl (delegation->next_subnet);

		/* Out subnet pool management is pretty unsophisticated. We only add
		 * the subnets and index them by ifindex. That keeps the implementation
		 * simple and the dead entries make it easy to reuse the same subnet on
		 * subsequent activations. On the other hand they may waste the subnet
		 * space. */
		delegation->next_subnet++;
	}

	subnet->timestamp = delegation->prefix.timestamp;
	subnet->lifetime = delegation->prefix.lifetime;
	subnet->preferred = delegation->prefix.preferred;

	_LOGD (LOGD_IP6, "ipv6-pd: %s allocated from a /%d prefix on %s",
	       nm_utils_inet6_ntop (&subnet->address, NULL),
	       delegation->prefix.plen,
	       nm_device_get_iface (device));

	nm_device_use_ip6_subnet (device, subnet);

	return TRUE;
}

/*
 * Try to obtain a subnet from each prefix delegated to given requesting
 * ("uplink") device and assign it to the downlink device.
 * Requests a new prefix if no subnet could be found.
 */
static void
ip6_subnet_from_device (NMPolicy *self, NMDevice *from_device, NMDevice *device)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	IP6PrefixDelegation *delegation = NULL;
	gboolean got_subnet = FALSE;
	guint have_prefixes = 0;
	guint i;

	expire_ip6_delegations (self);

	for (i = 0; i < priv->ip6_prefix_delegations->len; i++) {
		delegation = &g_array_index (priv->ip6_prefix_delegations,
		                             IP6PrefixDelegation, i);

		if (delegation->device != from_device)
			continue;

		if (ip6_subnet_from_delegation (delegation, device))
			got_subnet = TRUE;
		have_prefixes++;
	}

	if (!got_subnet) {
		_LOGI (LOGD_IP6, "ipv6-pd: none of %u prefixes of %s can be shared on %s",
		       have_prefixes, nm_device_get_iface (from_device),
		       nm_device_get_iface (device));
		nm_device_request_ip6_prefixes (from_device, have_prefixes + 1);
	}
}

static void
ip6_remove_device_prefix_delegations (NMPolicy *self, NMDevice *device)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	IP6PrefixDelegation *delegation = NULL;
	guint i;

	for (i = 0; i < priv->ip6_prefix_delegations->len; i++) {
		delegation = &g_array_index (priv->ip6_prefix_delegations,
		                             IP6PrefixDelegation, i);
		if (delegation->device == device)
			g_array_remove_index_fast (priv->ip6_prefix_delegations, i);
	}
}

static void
device_ip6_prefix_delegated (NMDevice *device,
                             NMPlatformIP6Address *prefix,
                             gpointer user_data)
{
	NMPolicyPrivate *priv = user_data;
	NMPolicy *self = _PRIV_TO_SELF (priv);
	IP6PrefixDelegation *delegation = NULL;
	const GSList *connections, *iter;
	guint i;

	_LOGI (LOGD_IP6, "ipv6-pd: received a prefix %s/%d from %s",
	       nm_utils_inet6_ntop (&prefix->address, NULL),
	       prefix->plen,
	       nm_device_get_iface (device));

	expire_ip6_delegations (self);

	for (i = 0; i < priv->ip6_prefix_delegations->len; i++) {
		/* Look for an already known prefix to update. */
		delegation = &g_array_index (priv->ip6_prefix_delegations, IP6PrefixDelegation, i);
		if (IN6_ARE_ADDR_EQUAL (&delegation->prefix.address, &prefix->address))
			break;
	}

	if (i == priv->ip6_prefix_delegations->len) {
		/* Allocate a delegation delegation for new prefix. */
		g_array_set_size (priv->ip6_prefix_delegations, i + 1);
		delegation = &g_array_index (priv->ip6_prefix_delegations, IP6PrefixDelegation, i);
		delegation->subnets = g_hash_table_new (NULL, NULL);
		delegation->next_subnet = 0;
	}

	delegation->device = device;
	delegation->prefix = *prefix;

	/* The newly activated connections are added to the list beginning,
	 * so traversing it from the beginning makes it likely for newly
	 * activated connections that have no subnet assigned to be served
	 * first. That is a simple yet fair policy, which is good. */
	connections = nm_manager_get_active_connections (priv->manager);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMDevice *to_device = nm_active_connection_get_device (iter->data);

		if (nm_device_needs_ip6_subnet (to_device))
			ip6_subnet_from_delegation (delegation, to_device);
	}
}

static void
device_ip6_subnet_needed (NMDevice *device,
                          gpointer user_data)
{
	NMPolicyPrivate *priv = user_data;
	NMPolicy *self = _PRIV_TO_SELF (priv);

	_LOGD (LOGD_IP6, "ipv6-pd: %s needs a subnet",
	       nm_device_get_iface (device));

	if (!priv->default_device6) {
		/* We request the prefixes when the default IPv6 device is set. */
		_LOGI (LOGD_IP6, "ipv6-pd: no device to obtain a subnet to share on %s from",
		       nm_device_get_iface (device));
		return;
	}
	ip6_subnet_from_device (self, priv->default_device6, device);
	nm_device_copy_ip6_dns_config (device, priv->default_device6);
}

/*****************************************************************************/

static NMDevice *
get_best_ip4_device (NMPolicy *self, gboolean fully_activated)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);

	return nm_default_route_manager_ip4_get_best_device (nm_default_route_manager_get (),
	                                                     nm_manager_get_devices (priv->manager),
	                                                     fully_activated,
	                                                     priv->default_device4);
}

static NMDevice *
get_best_ip6_device (NMPolicy *self, gboolean fully_activated)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);

	return nm_default_route_manager_ip6_get_best_device (nm_default_route_manager_get (),
	                                                     nm_manager_get_devices (priv->manager),
	                                                     fully_activated,
	                                                     priv->default_device6);
}

#define FALLBACK_HOSTNAME4 "localhost.localdomain"

static void
settings_set_hostname_cb (const char *hostname,
                          gboolean result,
                          gpointer user_data)
{
	int ret = 0;

	if (!result) {
		ret = sethostname (hostname, strlen (hostname));
		if (ret != 0) {
			int errsv = errno;

			_LOGW (LOGD_DNS, "couldn't set the system hostname to '%s': (%d) %s",
			       hostname, errsv, strerror (errsv));
			if (errsv == EPERM)
				_LOGW (LOGD_DNS, "you should use hostnamed when systemd hardening is in effect!");
		}
	}

	if (!ret)
		nm_dispatcher_call (DISPATCHER_ACTION_HOSTNAME, NULL, NULL, NULL, NULL, NULL, NULL);
}

#define HOST_NAME_BUFSIZE (HOST_NAME_MAX + 2)

static char *
_get_hostname (NMPolicy *self, char **hostname)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	char *buf;

	g_assert (hostname && *hostname == NULL);

	/* try to get the hostname via dbus... */
	if (nm_settings_get_transient_hostname (priv->settings, hostname)) {
		_LOGT (LOGD_DNS, "gethostname: \"%s\" (from dbus)", *hostname);
		return *hostname;
	}

	/* ...or retrieve it by yourself */
	buf = g_malloc (HOST_NAME_BUFSIZE);
	if (gethostname (buf, HOST_NAME_BUFSIZE -1) != 0) {
		int errsv = errno;

		_LOGT (LOGD_DNS, "gethostname: couldn't get the system hostname: (%d) %s",
		       errsv, g_strerror (errsv));
		g_free (buf);
		return NULL;
	}

	/* the name may be truncated... */
	buf[HOST_NAME_BUFSIZE - 1] = '\0';
	if (strlen (buf) >= HOST_NAME_BUFSIZE -1) {
		_LOGT (LOGD_DNS, "gethostname: system hostname too long: \"%s\"", buf);
		g_free (buf);
		return NULL;
	}

	_LOGT (LOGD_DNS, "gethostname: \"%s\"", buf);
	*hostname = buf;
	return *hostname;
}

static void
_set_hostname (NMPolicy *self,
               const char *new_hostname,
               const char *msg)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	gs_free char *old_hostname = NULL;
	const char *name;

	/* The incoming hostname *can* be NULL, which will get translated to
	 * 'localhost.localdomain' or such in the hostname policy code, but we
	 * keep cur_hostname = NULL in the case because we need to know that
	 * there was no valid hostname to start with.
	 */

	/* Clear lookup addresses if we have a hostname, so that we don't
	 * restart the reverse lookup thread later.
	 */
	if (new_hostname)
		g_clear_object (&priv->lookup_addr);

	/* Update the DNS only if the hostname isn't actually
	 * going to change.
	 */
	if (!nm_streq0 (priv->cur_hostname, new_hostname)) {
		g_free (priv->cur_hostname);
		priv->cur_hostname = g_strdup (new_hostname);

		/* Notify the DNS manager of the hostname change so that the domain part, if
		 * present, can be added to the search list.
		 */
		nm_dns_manager_set_hostname (priv->dns_manager, priv->cur_hostname);
	}

	 /* Finally, set kernel hostname */
	if (!new_hostname)
		name = FALLBACK_HOSTNAME4;
	else if (!new_hostname[0]) {
		g_warn_if_reached ();
		name = FALLBACK_HOSTNAME4;
	} else
		name = new_hostname;

	/* Don't set the hostname if it isn't actually changing */
	if (   _get_hostname (self, &old_hostname)
	    && (nm_streq (name, old_hostname)))
			return;

	_LOGI (LOGD_DNS, "setting system hostname to '%s' (%s)", name, msg);

	/* Ask NMSettings to update the transient hostname using its
	 * systemd-hostnamed proxy */
	nm_settings_set_transient_hostname (priv->settings,
	                                    name,
	                                    settings_set_hostname_cb,
	                                    NULL);
}

static void
lookup_callback (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	NMPolicy *self = (NMPolicy *) user_data;
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	const char *hostname;
	GError *error = NULL;

	hostname = g_resolver_lookup_by_address_finish (G_RESOLVER (source), result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		/* Don't touch policy; it may have been freed already */
		g_error_free (error);
		return;
	}

	if (hostname)
		_set_hostname (self, hostname, "from address lookup");
	else {
		_set_hostname (self, NULL, error->message);
		g_error_free (error);
	}

	g_clear_object (&priv->lookup_cancellable);
}

static void
update_system_hostname (NMPolicy *self, NMDevice *best4, NMDevice *best6)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	char *configured_hostname = NULL;
	const char *dhcp_hostname, *p;
	NMIP4Config *ip4_config;
	NMIP6Config *ip6_config;

	g_return_if_fail (self != NULL);

	if (priv->lookup_cancellable) {
		g_cancellable_cancel (priv->lookup_cancellable);
		g_clear_object (&priv->lookup_cancellable);
	}

	/* Hostname precedence order:
	 *
	 * 1) a configured hostname (from settings)
	 * 2) automatic hostname from the default device's config (DHCP, VPN, etc)
	 * 3) the original hostname when NM started
	 * 4) reverse-DNS of the best device's IPv4 address
	 *
	 */

	/* Try a persistent hostname first */
	g_object_get (G_OBJECT (priv->manager), NM_MANAGER_HOSTNAME, &configured_hostname, NULL);
	if (configured_hostname && nm_utils_is_specific_hostname (configured_hostname)) {
		_set_hostname (self, configured_hostname, "from system configuration");
		g_free (configured_hostname);
		return;
	}
	g_free (configured_hostname);

	/* Try automatically determined hostname from the best device's IP config */
	if (!best4)
		best4 = get_best_ip4_device (self, TRUE);
	if (!best6)
		best6 = get_best_ip6_device (self, TRUE);

	if (!best4 && !best6) {
		/* No best device; fall back to original hostname or if there wasn't
		 * one, 'localhost.localdomain'
		 */
		_set_hostname (self, priv->orig_hostname, "no default device");
		return;
	}

	if (best4) {
		NMDhcp4Config *dhcp4_config;

		/* Grab a hostname out of the device's DHCP4 config */
		dhcp4_config = nm_device_get_dhcp4_config (best4);
		if (dhcp4_config) {
			p = dhcp_hostname = nm_dhcp4_config_get_option (dhcp4_config, "host_name");
			if (dhcp_hostname && strlen (dhcp_hostname)) {
				/* Sanity check; strip leading spaces */
				while (*p) {
					if (!g_ascii_isspace (*p++)) {
						_set_hostname (self, p-1, "from DHCPv4");
						return;
					}
				}
				_LOGW (LOGD_DNS, "DHCPv4-provided hostname '%s' looks invalid; ignoring it",
				       dhcp_hostname);
			}
		}
	} else if (best6) {
		NMDhcp6Config *dhcp6_config;

		/* Grab a hostname out of the device's DHCP6 config */
		dhcp6_config = nm_device_get_dhcp6_config (best6);
		if (dhcp6_config) {
			p = dhcp_hostname = nm_dhcp6_config_get_option (dhcp6_config, "host_name");
			if (dhcp_hostname && strlen (dhcp_hostname)) {
				/* Sanity check; strip leading spaces */
				while (*p) {
					if (!g_ascii_isspace (*p++)) {
						_set_hostname (self, p-1, "from DHCPv6");
						return;
					}
				}
				_LOGW (LOGD_DNS, "DHCPv6-provided hostname '%s' looks invalid; ignoring it",
				       dhcp_hostname);
			}
		}
	}

	/* If no automatically-configured hostname, try using the hostname from
	 * when NM started up.
	 */
	if (priv->orig_hostname) {
		_set_hostname (self, priv->orig_hostname, "from system startup");
		return;
	}

	/* No configured hostname, no automatically determined hostname, and no
	 * bootup hostname. Start reverse DNS of the current IPv4 or IPv6 address.
	 */
	ip4_config = best4 ? nm_device_get_ip4_config (best4) : NULL;
	ip6_config = best6 ? nm_device_get_ip6_config (best6) : NULL;

	if (ip4_config && nm_ip4_config_get_num_addresses (ip4_config) > 0) {
		const NMPlatformIP4Address *addr4;

		addr4 = nm_ip4_config_get_address (ip4_config, 0);
		g_clear_object (&priv->lookup_addr);
		priv->lookup_addr = g_inet_address_new_from_bytes ((guint8 *) &addr4->address,
		                                                   G_SOCKET_FAMILY_IPV4);
	} else if (ip6_config && nm_ip6_config_get_num_addresses (ip6_config) > 0) {
		const NMPlatformIP6Address *addr6;

		addr6 = nm_ip6_config_get_address (ip6_config, 0);
		g_clear_object (&priv->lookup_addr);
		priv->lookup_addr = g_inet_address_new_from_bytes ((guint8 *) &addr6->address,
		                                                   G_SOCKET_FAMILY_IPV6);
	} else {
		/* No valid IP config; fall back to localhost.localdomain */
		_set_hostname (self, NULL, "no IP config");
		return;
	}

	priv->lookup_cancellable = g_cancellable_new ();
	g_resolver_lookup_by_address_async (priv->resolver,
	                                    priv->lookup_addr,
	                                    priv->lookup_cancellable,
	                                    lookup_callback, self);
}

static void
update_default_ac (NMPolicy *self,
                   NMActiveConnection *best,
                   void (*set_active_func)(NMActiveConnection*, gboolean))
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	const GSList *connections, *iter;

	/* Clear the 'default[6]' flag on all active connections that aren't the new
	 * default active connection.  We'll set the new default after; this ensures
	 * we don't ever have two marked 'default[6]' simultaneously.
	 */
	connections = nm_manager_get_active_connections (priv->manager);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		if (NM_ACTIVE_CONNECTION (iter->data) != best)
			set_active_func (NM_ACTIVE_CONNECTION (iter->data), FALSE);
	}

	/* Mark new default active connection */
	if (best)
		set_active_func (best, TRUE);
}

static NMIP4Config *
get_best_ip4_config (NMPolicy *self,
                     gboolean ignore_never_default,
                     const char **out_ip_iface,
                     NMActiveConnection **out_ac,
                     NMDevice **out_device,
                     NMVpnConnection **out_vpn)
{
	return nm_default_route_manager_ip4_get_best_config (nm_default_route_manager_get (),
	                                                     ignore_never_default,
	                                                     out_ip_iface,
	                                                     out_ac,
	                                                     out_device,
	                                                     out_vpn);
}

static void
update_ip4_dns (NMPolicy *self, NMDnsManager *dns_mgr)
{
	NMIP4Config *ip4_config;
	const char *ip_iface = NULL;
	NMVpnConnection *vpn = NULL;
	NMDnsIPConfigType dns_type = NM_DNS_IP_CONFIG_TYPE_BEST_DEVICE;

	ip4_config = get_best_ip4_config (self, TRUE, &ip_iface, NULL, NULL, &vpn);
	if (ip4_config) {
		if (vpn)
			dns_type = NM_DNS_IP_CONFIG_TYPE_VPN;

		/* Tell the DNS manager this config is preferred by re-adding it with
		 * a different IP config type.
		 */
		nm_dns_manager_add_ip4_config (dns_mgr, ip_iface, ip4_config, dns_type);
	}
}

static void
update_ip4_routing (NMPolicy *self, gboolean force_update)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	NMDevice *best = NULL, *default_device;
	NMConnection *connection = NULL;
	NMVpnConnection *vpn = NULL;
	NMActiveConnection *best_ac = NULL;
	const char *ip_iface = NULL;

	/* Note that we might have an IPv4 VPN tunneled over an IPv6-only device,
	 * so we can get (vpn != NULL && best == NULL).
	 */
	if (!get_best_ip4_config (self, FALSE, &ip_iface, &best_ac, &best, &vpn)) {
		gboolean changed;

		changed = (priv->default_device4 != NULL);
		priv->default_device4 = NULL;
		if (changed)
			_notify (self, PROP_DEFAULT_IP4_DEVICE);

		return;
	}
	g_assert ((best || vpn) && best_ac);

	if (!force_update && best && (best == priv->default_device4))
		return;

	if (best) {
		const GSList *connections, *iter;

		connections = nm_manager_get_active_connections (priv->manager);
		for (iter = connections; iter; iter = g_slist_next (iter)) {
			NMActiveConnection *active = iter->data;

			if (   NM_IS_VPN_CONNECTION (active)
			    && nm_vpn_connection_get_ip4_config (NM_VPN_CONNECTION (active))
			    && !nm_active_connection_get_device (active))
				nm_active_connection_set_device (active, best);
		}
	}

	if (vpn)
		default_device = nm_active_connection_get_device (NM_ACTIVE_CONNECTION (vpn));
	else
		default_device = best;

	update_default_ac (self, best_ac, nm_active_connection_set_default);

	if (default_device == priv->default_device4)
		return;

	priv->default_device4 = default_device;
	connection = nm_active_connection_get_applied_connection (best_ac);
	_LOGI (LOGD_CORE, "set '%s' (%s) as default for IPv4 routing and DNS",
	       nm_connection_get_id (connection), ip_iface);
	_notify (self, PROP_DEFAULT_IP4_DEVICE);
}

static NMIP6Config *
get_best_ip6_config (NMPolicy *self,
                     gboolean ignore_never_default,
                     const char **out_ip_iface,
                     NMActiveConnection **out_ac,
                     NMDevice **out_device,
                     NMVpnConnection **out_vpn)
{
	return nm_default_route_manager_ip6_get_best_config (nm_default_route_manager_get (),
	                                                     ignore_never_default,
	                                                     out_ip_iface,
	                                                     out_ac,
	                                                     out_device,
	                                                     out_vpn);
}

static void
update_ip6_dns_delegation (NMPolicy *self)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	const GSList *connections, *iter;

	connections = nm_manager_get_active_connections (priv->manager);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMDevice *device = nm_active_connection_get_device (iter->data);

		if (device && nm_device_needs_ip6_subnet (device))
			nm_device_copy_ip6_dns_config (device, priv->default_device6);
	}
}

static void
update_ip6_dns (NMPolicy *self, NMDnsManager *dns_mgr)
{
	NMIP6Config *ip6_config;
	const char *ip_iface = NULL;
	NMVpnConnection *vpn = NULL;
	NMDnsIPConfigType dns_type = NM_DNS_IP_CONFIG_TYPE_BEST_DEVICE;

	ip6_config = get_best_ip6_config (self, TRUE, &ip_iface, NULL, NULL, &vpn);
	if (ip6_config) {
		if (vpn)
			dns_type = NM_DNS_IP_CONFIG_TYPE_VPN;

		/* Tell the DNS manager this config is preferred by re-adding it with
		 * a different IP config type.
		 */
		nm_dns_manager_add_ip6_config (dns_mgr, ip_iface, ip6_config, dns_type);
	}

	update_ip6_dns_delegation (self);
}

static void
update_ip6_prefix_delegation (NMPolicy *self)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	const GSList *connections, *iter;

	/* There's new default IPv6 connection, try to get a prefix for everyone. */
	connections = nm_manager_get_active_connections (priv->manager);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMDevice *device = nm_active_connection_get_device (iter->data);

		if (device && nm_device_needs_ip6_subnet (device))
			ip6_subnet_from_device (self, priv->default_device6, device);
	}
}

static void
update_ip6_routing (NMPolicy *self, gboolean force_update)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	NMDevice *best = NULL, *default_device6;
	NMConnection *connection = NULL;
	NMVpnConnection *vpn = NULL;
	NMActiveConnection *best_ac = NULL;
	const char *ip_iface = NULL;

	/* Note that we might have an IPv6 VPN tunneled over an IPv4-only device,
	 * so we can get (vpn != NULL && best == NULL).
	 */
	if (!get_best_ip6_config (self, FALSE, &ip_iface, &best_ac, &best, &vpn)) {
		gboolean changed;

		changed = (priv->default_device6 != NULL);
		priv->default_device6 = NULL;
		if (changed)
			_notify (self, PROP_DEFAULT_IP6_DEVICE);

		return;
	}
	g_assert ((best || vpn) && best_ac);

	if (!force_update && best && (best == priv->default_device6))
		return;

	if (best) {
		const GSList *connections, *iter;

		connections = nm_manager_get_active_connections (priv->manager);
		for (iter = connections; iter; iter = g_slist_next (iter)) {
			NMActiveConnection *active = iter->data;

			if (   NM_IS_VPN_CONNECTION (active)
			    && nm_vpn_connection_get_ip6_config (NM_VPN_CONNECTION (active))
			    && !nm_active_connection_get_device (active))
				nm_active_connection_set_device (active, best);
		}
	}

	if (vpn)
		default_device6 = nm_active_connection_get_device (NM_ACTIVE_CONNECTION (vpn));
	else
		default_device6 = best;

	update_default_ac (self, best_ac, nm_active_connection_set_default6);

	if (default_device6 == priv->default_device6)
		return;
	priv->default_device6 = default_device6;

	update_ip6_prefix_delegation (self);

	connection = nm_active_connection_get_applied_connection (best_ac);
	_LOGI (LOGD_CORE, "set '%s' (%s) as default for IPv6 routing and DNS",
	       nm_connection_get_id (connection), ip_iface);
	_notify (self, PROP_DEFAULT_IP6_DEVICE);
}

static void
update_routing_and_dns (NMPolicy *self, gboolean force_update)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);

	nm_dns_manager_begin_updates (priv->dns_manager, __func__);

	update_ip4_dns (self, priv->dns_manager);
	update_ip6_dns (self, priv->dns_manager);

	update_ip4_routing (self, force_update);
	update_ip6_routing (self, force_update);

	/* Update the system hostname */
	update_system_hostname (self, priv->default_device4, priv->default_device6);

	nm_dns_manager_end_updates (priv->dns_manager, __func__);
}

static void
check_activating_devices (NMPolicy *self)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	GObject *object = G_OBJECT (self);
	NMDevice *best4, *best6 = NULL;

	best4 = get_best_ip4_device (self, FALSE);
	best6 = get_best_ip6_device (self, FALSE);

	g_object_freeze_notify (object);

	if (best4 != priv->activating_device4) {
		priv->activating_device4 = best4;
		_notify (self, PROP_ACTIVATING_IP4_DEVICE);
	}
	if (best6 != priv->activating_device6) {
		priv->activating_device6 = best6;
		_notify (self, PROP_ACTIVATING_IP6_DEVICE);
	}

	g_object_thaw_notify (object);
}

typedef struct {
	NMPolicy *policy;
	NMDevice *device;
	guint autoactivate_id;
} ActivateData;

static void
activate_data_free (ActivateData *data)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (data->policy);

	nm_device_remove_pending_action (data->device, NM_PENDING_ACTION_AUTOACTIVATE, TRUE);
	priv->pending_activation_checks = g_slist_remove (priv->pending_activation_checks, data);

	if (data->autoactivate_id)
		g_source_remove (data->autoactivate_id);
	g_object_unref (data->device);

	g_slice_free (ActivateData, data);
}

static void
auto_activate_device (NMPolicy *self,
                      NMDevice *device)
{
	NMPolicyPrivate *priv;
	NMSettingsConnection *best_connection;
	gs_free char *specific_object = NULL;
	gs_free NMSettingsConnection **connections = NULL;
	guint i, len;

	nm_assert (NM_IS_POLICY (self));
	nm_assert (NM_IS_DEVICE (device));

	priv = NM_POLICY_GET_PRIVATE (self);

	// FIXME: if a device is already activating (or activated) with a connection
	// but another connection now overrides the current one for that device,
	// deactivate the device and activate the new connection instead of just
	// bailing if the device is already active
	if (nm_device_get_act_request (device))
		return;

	connections = nm_manager_get_activatable_connections (priv->manager, &len, TRUE);
	if (!connections[0])
		return;

	/* Find the first connection that should be auto-activated */
	best_connection = NULL;
	for (i = 0; i < len; i++) {
		NMSettingsConnection *candidate = NM_SETTINGS_CONNECTION (connections[i]);

		if (!nm_settings_connection_can_autoconnect (candidate))
			continue;
		if (nm_device_can_auto_connect (device, (NMConnection *) candidate, &specific_object)) {
			best_connection = candidate;
			break;
		}
	}

	if (best_connection) {
		GError *error = NULL;
		NMAuthSubject *subject;

		_LOGI (LOGD_DEVICE, "auto-activating connection '%s'",
		       nm_settings_connection_get_id (best_connection));
		subject = nm_auth_subject_new_internal ();
		if (!nm_manager_activate_connection (priv->manager,
		                                     best_connection,
		                                     NULL,
		                                     specific_object,
		                                     device,
		                                     subject,
		                                     &error)) {
			_LOGI (LOGD_DEVICE, "connection '%s' auto-activation failed: (%d) %s",
			       nm_settings_connection_get_id (best_connection),
			       error->code,
			       error->message);
			g_error_free (error);
		}
		g_object_unref (subject);
	}
}

static gboolean
auto_activate_device_cb (gpointer user_data)
{
	ActivateData *data = user_data;

	g_assert (data);
	g_assert (NM_IS_POLICY (data->policy));
	g_assert (NM_IS_DEVICE (data->device));

	data->autoactivate_id = 0;
	auto_activate_device (data->policy, data->device);
	activate_data_free (data);
	return G_SOURCE_REMOVE;
}

static ActivateData *
find_pending_activation (GSList *list, NMDevice *device)
{
	GSList *iter;

	for (iter = list; iter; iter = g_slist_next (iter)) {
		if (((ActivateData *) iter->data)->device == device)
			return iter->data;
	}
	return NULL;
}

/*****************************************************************************/

typedef struct {
	NMDevice *device;
	GSList *secondaries;
} PendingSecondaryData;

static PendingSecondaryData *
pending_secondary_data_new (NMDevice *device, GSList *secondaries)
{
	PendingSecondaryData *data;

	data = g_slice_new (PendingSecondaryData);
	data->device = g_object_ref (device);
	data->secondaries = secondaries;
	return data;
}

static void
pending_secondary_data_free (PendingSecondaryData *data)
{
	g_object_unref (data->device);
	g_slist_free_full (data->secondaries, g_object_unref);
	g_slice_free (PendingSecondaryData, data);
}

static void
process_secondaries (NMPolicy *self,
                     NMActiveConnection *active,
                     gboolean connected)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	GSList *iter, *iter2, *next, *next2;

	/* Loop through devices waiting for secondary connections to activate */
	for (iter = priv->pending_secondaries; iter; iter = next) {
		PendingSecondaryData *secondary_data = (PendingSecondaryData *) iter->data;
		NMDevice *item_device = secondary_data->device;

		next = g_slist_next (iter);

		/* Look for 'active' in each device's secondary connections list */
		for (iter2 = secondary_data->secondaries; iter2; iter2 = next2) {
			NMActiveConnection *secondary_active = NM_ACTIVE_CONNECTION (iter2->data);

			next2 = g_slist_next (iter2);

			if (active != secondary_active)
				continue;

			if (connected) {
				_LOGD (LOGD_DEVICE, "secondary connection '%s' succeeded; active path '%s'",
				       nm_active_connection_get_settings_connection_id (active),
				       nm_exported_object_get_path (NM_EXPORTED_OBJECT (active)));

				/* Secondary connection activated */
				secondary_data->secondaries = g_slist_remove (secondary_data->secondaries, secondary_active);
				g_object_unref (secondary_active);
				if (!secondary_data->secondaries) {
					/* No secondary UUID remained -> remove the secondary data item */
					priv->pending_secondaries = g_slist_remove (priv->pending_secondaries, secondary_data);
					pending_secondary_data_free (secondary_data);
					if (nm_device_get_state (item_device) == NM_DEVICE_STATE_SECONDARIES)
						nm_device_state_changed (item_device, NM_DEVICE_STATE_ACTIVATED, NM_DEVICE_STATE_REASON_NONE);
					break;
				}
			} else {
				_LOGD (LOGD_DEVICE, "secondary connection '%s' failed; active path '%s'",
				       nm_active_connection_get_settings_connection_id (active),
				       nm_exported_object_get_path (NM_EXPORTED_OBJECT (active)));

				/* Secondary connection failed -> do not watch other connections */
				priv->pending_secondaries = g_slist_remove (priv->pending_secondaries, secondary_data);
				pending_secondary_data_free (secondary_data);
				if (   nm_device_get_state (item_device) == NM_DEVICE_STATE_SECONDARIES
				    || nm_device_get_state (item_device) == NM_DEVICE_STATE_ACTIVATED)
					nm_device_state_changed (item_device, NM_DEVICE_STATE_FAILED,
					                                      NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED);
				break;
			}
		}
	}
}

static void
hostname_changed (NMManager *manager, GParamSpec *pspec, gpointer user_data)
{
	NMPolicyPrivate *priv = user_data;
	NMPolicy *self = _PRIV_TO_SELF (priv);

	update_system_hostname (self, NULL, NULL);
}

static void
reset_autoconnect_all (NMPolicy *self, NMDevice *device)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	gs_free NMSettingsConnection **connections = NULL;
	guint i;

	if (device) {
		_LOGD (LOGD_DEVICE, "re-enabling autoconnect for all connections on %s",
		       nm_device_get_iface (device));
	} else
		_LOGD (LOGD_DEVICE, "re-enabling autoconnect for all connections");

	connections = nm_settings_get_connections_sorted (priv->settings, NULL);
	for (i = 0; connections[i]; i++) {
		NMSettingsConnection *connection = connections[i];

		if (!device || nm_device_check_connection_compatible (device, NM_CONNECTION (connection))) {
			nm_settings_connection_reset_autoconnect_retries (connection);
			nm_settings_connection_set_autoconnect_blocked_reason (connection, NM_DEVICE_STATE_REASON_NONE);
		}
	}
}

static void
reset_autoconnect_for_failed_secrets (NMPolicy *self)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	gs_free NMSettingsConnection **connections = NULL;
	guint i;

	_LOGD (LOGD_DEVICE, "re-enabling autoconnect for all connections with failed secrets");

	connections = nm_settings_get_connections_sorted (priv->settings, NULL);
	for (i = 0; connections[i]; i++) {
		NMSettingsConnection *connection = connections[i];

		if (nm_settings_connection_get_autoconnect_blocked_reason (connection) == NM_DEVICE_STATE_REASON_NO_SECRETS) {
			nm_settings_connection_reset_autoconnect_retries (connection);
			nm_settings_connection_set_autoconnect_blocked_reason (connection, NM_DEVICE_STATE_REASON_NONE);
		}
	}
}

static void
block_autoconnect_for_device (NMPolicy *self, NMDevice *device)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	gs_free NMSettingsConnection **connections = NULL;
	guint i;

	_LOGD (LOGD_DEVICE, "blocking autoconnect for all connections on %s",
	       nm_device_get_iface (device));

	/* NMDevice keeps its own autoconnect-able-ness state; we only need to
	 * explicitly block connections for software devices, where the NMDevice
	 * might be destroyed and recreated later.
	 */
	if (!nm_device_is_software (device))
		return;

	connections = nm_settings_get_connections_sorted (priv->settings, NULL);
	for (i = 0; connections[i]; i++) {
		NMSettingsConnection *connection = connections[i];

		if (nm_device_check_connection_compatible (device, NM_CONNECTION (connection))) {
			nm_settings_connection_set_autoconnect_blocked_reason (connection,
			                                                       NM_DEVICE_STATE_REASON_USER_REQUESTED);
		}
	}
}

static void
sleeping_changed (NMManager *manager, GParamSpec *pspec, gpointer user_data)
{
	NMPolicyPrivate *priv = user_data;
	NMPolicy *self = _PRIV_TO_SELF (priv);
	gboolean sleeping = FALSE, enabled = FALSE;

	g_object_get (G_OBJECT (manager), NM_MANAGER_SLEEPING, &sleeping, NULL);
	g_object_get (G_OBJECT (manager), NM_MANAGER_NETWORKING_ENABLED, &enabled, NULL);

	/* Reset retries on all connections so they'll checked on wakeup */
	if (sleeping || !enabled)
		reset_autoconnect_all (self, NULL);
}

static void
schedule_activate_check (NMPolicy *self, NMDevice *device)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	ActivateData *data;
	const GSList *active_connections, *iter;

	if (nm_manager_get_state (priv->manager) == NM_STATE_ASLEEP)
		return;

	if (!nm_device_get_enabled (device))
		return;

	if (!nm_device_autoconnect_allowed (device))
		return;

	if (find_pending_activation (priv->pending_activation_checks, device))
		return;

	active_connections = nm_manager_get_active_connections (priv->manager);
	for (iter = active_connections; iter; iter = iter->next) {
		if (nm_active_connection_get_device (NM_ACTIVE_CONNECTION (iter->data)) == device)
			return;
	}

	nm_device_add_pending_action (device, NM_PENDING_ACTION_AUTOACTIVATE, TRUE);

	data = g_slice_new0 (ActivateData);
	data->policy = self;
	data->device = g_object_ref (device);
	data->autoactivate_id = g_idle_add (auto_activate_device_cb, data);
	priv->pending_activation_checks = g_slist_append (priv->pending_activation_checks, data);
}

static void
clear_pending_activate_check (NMPolicy *self, NMDevice *device)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	ActivateData *data;

	data = find_pending_activation (priv->pending_activation_checks, device);
	if (data && data->autoactivate_id)
		activate_data_free (data);
}

static gboolean
reset_connections_retries (gpointer user_data)
{
	NMPolicy *self = (NMPolicy *) user_data;
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	gs_free NMSettingsConnection **connections = NULL;
	guint i;
	gint32 con_stamp, min_stamp, now;
	gboolean changed = FALSE;

	priv->reset_retries_id = 0;

	min_stamp = 0;
	now = nm_utils_get_monotonic_timestamp_s ();
	connections = nm_settings_get_connections_sorted (priv->settings, NULL);
	for (i = 0; connections[i]; i++) {
		NMSettingsConnection *connection = connections[i];

		con_stamp = nm_settings_connection_get_autoconnect_retry_time (connection);
		if (con_stamp == 0)
			continue;

		if (con_stamp <= now) {
			nm_settings_connection_reset_autoconnect_retries (connection);
			changed = TRUE;
		} else if (min_stamp == 0 || min_stamp > con_stamp)
			min_stamp = con_stamp;
	}

	/* Schedule the handler again if there are some stamps left */
	if (min_stamp != 0)
		priv->reset_retries_id = g_timeout_add_seconds (min_stamp - now, reset_connections_retries, self);

	/* If anything changed, try to activate the newly re-enabled connections */
	if (changed)
		schedule_activate_all (self);

	return FALSE;
}

static void
activate_slave_connections (NMPolicy *self, NMDevice *device)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	const char *master_device, *master_uuid_settings = NULL, *master_uuid_applied = NULL;
	guint i;
	NMActRequest *req;
	gboolean internal_activation = FALSE;

	master_device = nm_device_get_iface (device);
	g_assert (master_device);

	req = nm_device_get_act_request (device);
	if (req) {
		NMConnection *con;
		NMAuthSubject *subject;

		con = nm_active_connection_get_applied_connection (NM_ACTIVE_CONNECTION (req));
		if (con)
			master_uuid_applied = nm_connection_get_uuid (con);
		con = NM_CONNECTION (nm_active_connection_get_settings_connection (NM_ACTIVE_CONNECTION (req)));
		if (con) {
			master_uuid_settings = nm_connection_get_uuid (con);
			if (!g_strcmp0 (master_uuid_settings, master_uuid_applied))
				master_uuid_settings = NULL;
		}

		subject = nm_active_connection_get_subject (NM_ACTIVE_CONNECTION (req));
		internal_activation = subject && nm_auth_subject_is_internal (subject);
	}

	if (!internal_activation) {
		gs_free NMSettingsConnection **connections = NULL;

		connections = nm_settings_get_connections_sorted (priv->settings, NULL);

		for (i = 0; connections[i]; i++) {
			NMConnection *slave;
			NMSettingConnection *s_slave_con;
			const char *slave_master;

			slave = NM_CONNECTION (connections[i]);

			s_slave_con = nm_connection_get_setting_connection (slave);
			g_assert (s_slave_con);
			slave_master = nm_setting_connection_get_master (s_slave_con);
			if (!slave_master)
				continue;

			if (   !g_strcmp0 (slave_master, master_device)
			    || !g_strcmp0 (slave_master, master_uuid_applied)
			    || !g_strcmp0 (slave_master, master_uuid_settings))
				nm_settings_connection_reset_autoconnect_retries (NM_SETTINGS_CONNECTION (slave));
		}
	}

	schedule_activate_all (self);
}

static gboolean
activate_secondary_connections (NMPolicy *self,
                                NMConnection *connection,
                                NMDevice *device)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	NMSettingsConnection *settings_con;
	NMActiveConnection *ac;
	PendingSecondaryData *secondary_data;
	GSList *secondary_ac_list = NULL;
	GError *error = NULL;
	guint32 i;
	gboolean success = TRUE;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	for (i = 0; i < nm_setting_connection_get_num_secondaries (s_con); i++) {
		const char *sec_uuid = nm_setting_connection_get_secondary (s_con, i);
		NMActRequest *req;

		settings_con = nm_settings_get_connection_by_uuid (priv->settings, sec_uuid);
		if (!settings_con) {
			_LOGW (LOGD_DEVICE, "secondary connection '%s' auto-activation failed: The connection doesn't exist.",
			       sec_uuid);
			success = FALSE;
			break;
		}
		if (!nm_connection_is_type (NM_CONNECTION (settings_con), NM_SETTING_VPN_SETTING_NAME)) {
			_LOGW (LOGD_DEVICE, "secondary connection '%s (%s)' auto-activation failed: The connection is not a VPN.",
			       nm_settings_connection_get_id (settings_con), sec_uuid);
			success = FALSE;
			break;
		}

		req = nm_device_get_act_request (device);
		g_assert (req);

		_LOGD (LOGD_DEVICE, "activating secondary connection '%s (%s)' for base connection '%s (%s)'",
		       nm_settings_connection_get_id (settings_con), sec_uuid,
		       nm_connection_get_id (connection), nm_connection_get_uuid (connection));
		ac = nm_manager_activate_connection (priv->manager,
		                                     settings_con,
		                                     NULL,
		                                     nm_exported_object_get_path (NM_EXPORTED_OBJECT (req)),
		                                     device,
		                                     nm_active_connection_get_subject (NM_ACTIVE_CONNECTION (req)),
		                                     &error);
		if (ac)
			secondary_ac_list = g_slist_append (secondary_ac_list, g_object_ref (ac));
		else {
			_LOGW (LOGD_DEVICE, "secondary connection '%s (%s)' auto-activation failed: (%d) %s",
			       nm_settings_connection_get_id (settings_con), sec_uuid,
			       error->code,
			       error->message);
			g_clear_error (&error);
			success = FALSE;
			break;
		}
	}

	if (success && secondary_ac_list != NULL) {
		secondary_data = pending_secondary_data_new (device, secondary_ac_list);
		priv->pending_secondaries = g_slist_append (priv->pending_secondaries, secondary_data);
	} else
		g_slist_free_full (secondary_ac_list, g_object_unref);

	return success;
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMPolicyPrivate *priv = user_data;
	NMPolicy *self = _PRIV_TO_SELF (priv);

	NMSettingsConnection *connection = nm_device_get_settings_connection (device);

	const char *ip_iface = nm_device_get_ip_iface (device);
	NMIP4Config *ip4_config;
	NMIP6Config *ip6_config;
	NMSettingConnection *s_con = NULL;

	switch (new_state) {
	case NM_DEVICE_STATE_FAILED:
		/* Mark the connection invalid if it failed during activation so that
		 * it doesn't get automatically chosen over and over and over again.
		 */
		if (   connection
		    && old_state >= NM_DEVICE_STATE_PREPARE
		    && old_state <= NM_DEVICE_STATE_ACTIVATED) {
			int tries = nm_settings_connection_get_autoconnect_retries (connection);

			if (reason == NM_DEVICE_STATE_REASON_NO_SECRETS) {
				_LOGD (LOGD_DEVICE, "connection '%s' now blocked from autoconnect due to no secrets",
				       nm_settings_connection_get_id (connection));

				nm_settings_connection_set_autoconnect_blocked_reason (connection, NM_DEVICE_STATE_REASON_NO_SECRETS);
			} else if (tries != 0) {
				_LOGD (LOGD_DEVICE, "connection '%s' failed to autoconnect; %d tries left",
				       nm_settings_connection_get_id (connection), tries);
				if (tries > 0)
					nm_settings_connection_set_autoconnect_retries (connection, tries - 1);
			}

			if (nm_settings_connection_get_autoconnect_retries (connection) == 0) {
				_LOGI (LOGD_DEVICE, "disabling autoconnect for connection '%s'.",
				       nm_settings_connection_get_id (connection));
				/* Schedule a handler to reset retries count */
				if (!priv->reset_retries_id) {
					gint32 retry_time = nm_settings_connection_get_autoconnect_retry_time (connection);

					g_warn_if_fail (retry_time != 0);
					priv->reset_retries_id = g_timeout_add_seconds (MAX (0, retry_time - nm_utils_get_monotonic_timestamp_s ()), reset_connections_retries, self);
				}
			}
			nm_connection_clear_secrets (NM_CONNECTION (connection));
		}
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		if (connection) {
			/* Reset auto retries back to default since connection was successful */
			nm_settings_connection_reset_autoconnect_retries (connection);

			/* And clear secrets so they will always be requested from the
			 * settings service when the next connection is made.
			 */

			nm_connection_clear_secrets (NM_CONNECTION (connection));
		}

		/* Add device's new IPv4 and IPv6 configs to DNS */

		nm_dns_manager_begin_updates (priv->dns_manager, __func__);

		ip4_config = nm_device_get_ip4_config (device);
		if (ip4_config)
			nm_dns_manager_add_ip4_config (priv->dns_manager, ip_iface, ip4_config, NM_DNS_IP_CONFIG_TYPE_DEFAULT);
		ip6_config = nm_device_get_ip6_config (device);
		if (ip6_config)
			nm_dns_manager_add_ip6_config (priv->dns_manager, ip_iface, ip6_config, NM_DNS_IP_CONFIG_TYPE_DEFAULT);

		update_routing_and_dns (self, FALSE);

		nm_dns_manager_end_updates (priv->dns_manager, __func__);
		break;
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
		if (old_state > NM_DEVICE_STATE_DISCONNECTED)
			update_routing_and_dns (self, FALSE);
		break;
	case NM_DEVICE_STATE_DEACTIVATING:
		if (reason == NM_DEVICE_STATE_REASON_USER_REQUESTED) {
			if (!nm_device_get_autoconnect (device)) {
				/* The device was disconnected; block all connections on it */
				block_autoconnect_for_device (self, device);
			} else {
				if (connection) {
					/* The connection was deactivated, so block just this connection */
					_LOGD (LOGD_DEVICE, "blocking autoconnect of connection '%s' by user request",
					       nm_settings_connection_get_id (connection));
					nm_settings_connection_set_autoconnect_blocked_reason (connection,
					                                                       NM_DEVICE_STATE_REASON_USER_REQUESTED);
				}
			}
		}
		ip6_remove_device_prefix_delegations (self, device);
		break;
	case NM_DEVICE_STATE_DISCONNECTED:
		/* Reset retry counts for a device's connections when carrier on; if cable
		 * was unplugged and plugged in again, we should try to reconnect.
		 */
		if (reason == NM_DEVICE_STATE_REASON_CARRIER && old_state == NM_DEVICE_STATE_UNAVAILABLE)
			reset_autoconnect_all (self, device);

		if (old_state > NM_DEVICE_STATE_DISCONNECTED)
			update_routing_and_dns (self, FALSE);

		/* Device is now available for auto-activation */
		schedule_activate_check (self, device);
		break;

	case NM_DEVICE_STATE_PREPARE:
		/* Reset auto-connect retries of all slaves and schedule them for
		 * activation. */
		activate_slave_connections (self, device);
		break;
	case NM_DEVICE_STATE_IP_CONFIG:
		/* We must have secrets if we got here. */
		if (connection)
			nm_settings_connection_set_autoconnect_blocked_reason (connection, NM_DEVICE_STATE_REASON_NONE);
		break;
	case NM_DEVICE_STATE_SECONDARIES:
		if (connection)
			s_con = nm_connection_get_setting_connection (NM_CONNECTION (connection));
		if (s_con && nm_setting_connection_get_num_secondaries (s_con) > 0) {
			/* Make routes and DNS up-to-date before activating dependent connections */
			update_routing_and_dns (self, FALSE);

			/* Activate secondary (VPN) connections */
			if (!activate_secondary_connections (self, NM_CONNECTION (connection), device))
				nm_device_queue_state (device, NM_DEVICE_STATE_FAILED,
				                       NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED);
		} else
			nm_device_queue_state (device, NM_DEVICE_STATE_ACTIVATED,
			                       NM_DEVICE_STATE_REASON_NONE);
		break;

	default:
		break;
	}

	check_activating_devices (self);
}

static void
device_ip4_config_changed (NMDevice *device,
                           NMIP4Config *new_config,
                           NMIP4Config *old_config,
                           gpointer user_data)
{
	NMPolicyPrivate *priv = user_data;
	NMPolicy *self = _PRIV_TO_SELF (priv);
	const char *ip_iface = nm_device_get_ip_iface (device);

	nm_dns_manager_begin_updates (priv->dns_manager, __func__);

	/* Ignore IP config changes while the device is activating, because we'll
	 * catch all the changes when the device moves to ACTIVATED state.
	 * Prevents unecessary changes to DNS information.
	 */
	if (nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED) {
		if (old_config != new_config) {
			if (old_config)
				nm_dns_manager_remove_ip4_config (priv->dns_manager, old_config);
			if (new_config)
				nm_dns_manager_add_ip4_config (priv->dns_manager, ip_iface, new_config, NM_DNS_IP_CONFIG_TYPE_DEFAULT);
		}
		update_ip4_dns (self, priv->dns_manager);
		update_ip4_routing (self, TRUE);
		update_system_hostname (self, priv->default_device4, priv->default_device6);
	} else {
		/* Old configs get removed immediately */
		if (old_config)
			nm_dns_manager_remove_ip4_config (priv->dns_manager, old_config);
	}

	nm_dns_manager_end_updates (priv->dns_manager, __func__);
}

static void
device_ip6_config_changed (NMDevice *device,
                           NMIP6Config *new_config,
                           NMIP6Config *old_config,
                           gpointer user_data)
{
	NMPolicyPrivate *priv = user_data;
	NMPolicy *self = _PRIV_TO_SELF (priv);
	const char *ip_iface = nm_device_get_ip_iface (device);

	nm_dns_manager_begin_updates (priv->dns_manager, __func__);

	/* Ignore IP config changes while the device is activating, because we'll
	 * catch all the changes when the device moves to ACTIVATED state.
	 * Prevents unecessary changes to DNS information.
	 */
	if (!nm_device_is_activating (device)) {
		if (old_config != new_config) {
			if (old_config)
				nm_dns_manager_remove_ip6_config (priv->dns_manager, old_config);
			if (new_config)
				nm_dns_manager_add_ip6_config (priv->dns_manager, ip_iface, new_config, NM_DNS_IP_CONFIG_TYPE_DEFAULT);
		}
		update_ip6_dns (self, priv->dns_manager);
		update_ip6_routing (self, TRUE);
		update_system_hostname (self, priv->default_device4, priv->default_device6);
	} else {
		/* Old configs get removed immediately */
		if (old_config)
			nm_dns_manager_remove_ip6_config (priv->dns_manager, old_config);
	}

	nm_dns_manager_end_updates (priv->dns_manager, __func__);
}

/*****************************************************************************/

static void
device_autoconnect_changed (NMDevice *device,
                            GParamSpec *pspec,
                            gpointer user_data)
{
	NMPolicyPrivate *priv = user_data;
	NMPolicy *self = _PRIV_TO_SELF (priv);

	if (nm_device_autoconnect_allowed (device))
		schedule_activate_check (self, device);
}

static void
device_recheck_auto_activate (NMDevice *device, gpointer user_data)
{
	NMPolicyPrivate *priv = user_data;
	NMPolicy *self = _PRIV_TO_SELF (priv);

	schedule_activate_check (self, device);
}

static void
devices_list_unregister (NMPolicy *self, NMDevice *device)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);

	g_signal_handlers_disconnect_by_data ((GObject *) device, priv);
}

static void
devices_list_register (NMPolicy *self, NMDevice *device)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);

	/* Connect state-changed with _after, so that the handler is invoked after other handlers. */
	g_signal_connect_after (device, NM_DEVICE_STATE_CHANGED,          (GCallback) device_state_changed, priv);
	g_signal_connect       (device, NM_DEVICE_IP4_CONFIG_CHANGED,     (GCallback) device_ip4_config_changed, priv);
	g_signal_connect       (device, NM_DEVICE_IP6_CONFIG_CHANGED,     (GCallback) device_ip6_config_changed, priv);
	g_signal_connect       (device, NM_DEVICE_IP6_PREFIX_DELEGATED,   (GCallback) device_ip6_prefix_delegated, priv);
	g_signal_connect       (device, NM_DEVICE_IP6_SUBNET_NEEDED,      (GCallback) device_ip6_subnet_needed, priv);
	g_signal_connect       (device, "notify::" NM_DEVICE_AUTOCONNECT, (GCallback) device_autoconnect_changed, priv);
	g_signal_connect       (device, NM_DEVICE_RECHECK_AUTO_ACTIVATE,  (GCallback) device_recheck_auto_activate, priv);
}

static void
device_added (NMManager *manager, NMDevice *device, gpointer user_data)
{
	NMPolicyPrivate *priv = user_data;
	NMPolicy *self = _PRIV_TO_SELF (priv);

	g_return_if_fail (NM_IS_POLICY (self));

	priv = NM_POLICY_GET_PRIVATE (self);

	if (!nm_g_hash_table_add (priv->devices, device))
		g_return_if_reached ();

	devices_list_register (self, device);
}

static void
device_removed (NMManager *manager, NMDevice *device, gpointer user_data)
{
	NMPolicyPrivate *priv = user_data;
	NMPolicy *self = _PRIV_TO_SELF (priv);

	/* XXX is this needed? The delegations are cleaned up
	 * on transition to deactivated too. */
	ip6_remove_device_prefix_delegations (self, device);

	/* Clear any idle callbacks for this device */
	clear_pending_activate_check (self, device);

	if (g_hash_table_remove (priv->devices, device))
		devices_list_unregister (self, device);

	/* Don't update routing and DNS here as we've already handled that
	 * for devices that need it when the device's state changed to UNMANAGED.
	 */
}

/*****************************************************************************/

static void
vpn_connection_activated (NMPolicy *self, NMVpnConnection *vpn)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	NMIP4Config *ip4_config;
	NMIP6Config *ip6_config;
	const char *ip_iface;

	nm_dns_manager_begin_updates (priv->dns_manager, __func__);

	ip_iface = nm_vpn_connection_get_ip_iface (vpn, TRUE);

	/* Add the VPN connection's IP configs from DNS */

	ip4_config = nm_vpn_connection_get_ip4_config (vpn);
	if (ip4_config)
		nm_dns_manager_add_ip4_config (priv->dns_manager, ip_iface, ip4_config, NM_DNS_IP_CONFIG_TYPE_VPN);

	ip6_config = nm_vpn_connection_get_ip6_config (vpn);
	if (ip6_config)
		nm_dns_manager_add_ip6_config (priv->dns_manager, ip_iface, ip6_config, NM_DNS_IP_CONFIG_TYPE_VPN);

	update_routing_and_dns (self, TRUE);

	nm_dns_manager_end_updates (priv->dns_manager, __func__);
}

static void
vpn_connection_deactivated (NMPolicy *self, NMVpnConnection *vpn)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	NMIP4Config *ip4_config;
	NMIP6Config *ip6_config;

	nm_dns_manager_begin_updates (priv->dns_manager, __func__);

	ip4_config = nm_vpn_connection_get_ip4_config (vpn);
	if (ip4_config) {
		/* Remove the VPN connection's IP4 config from DNS */
		nm_dns_manager_remove_ip4_config (priv->dns_manager, ip4_config);
	}

	ip6_config = nm_vpn_connection_get_ip6_config (vpn);
	if (ip6_config) {
		/* Remove the VPN connection's IP6 config from DNS */
		nm_dns_manager_remove_ip6_config (priv->dns_manager, ip6_config);
	}

	update_routing_and_dns (self, TRUE);

	nm_dns_manager_end_updates (priv->dns_manager, __func__);
}

static void
vpn_connection_state_changed (NMVpnConnection *vpn,
                              NMVpnConnectionState new_state,
                              NMVpnConnectionState old_state,
                              NMVpnConnectionStateReason reason,
                              NMPolicy *self)
{
	if (new_state == NM_VPN_CONNECTION_STATE_ACTIVATED)
		vpn_connection_activated (self, vpn);
	else if (new_state >= NM_VPN_CONNECTION_STATE_FAILED) {
		/* Only clean up IP/DNS if the connection ever got past IP_CONFIG */
		if (old_state >= NM_VPN_CONNECTION_STATE_IP_CONFIG_GET &&
		    old_state <= NM_VPN_CONNECTION_STATE_ACTIVATED)
			vpn_connection_deactivated (self, vpn);
	}
}

static void
vpn_connection_retry_after_failure (NMVpnConnection *vpn, NMPolicy *self)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	NMActiveConnection *ac = NM_ACTIVE_CONNECTION (vpn);
	NMSettingsConnection *connection = nm_active_connection_get_settings_connection (ac);
	GError *error = NULL;

	/* Attempt to reconnect VPN connections that failed after being connected */
	if (!nm_manager_activate_connection (priv->manager,
	                                     connection,
	                                     NULL,
	                                     NULL,
	                                     NULL,
	                                     nm_active_connection_get_subject (ac),
	                                     &error)) {
		_LOGW (LOGD_DEVICE, "VPN '%s' reconnect failed: %s",
		       nm_settings_connection_get_id (connection),
		       error->message ? error->message : "unknown");
		g_clear_error (&error);
	}
}

static void
active_connection_state_changed (NMActiveConnection *active,
                                 GParamSpec *pspec,
                                 NMPolicy *self)
{
	NMActiveConnectionState state = nm_active_connection_get_state (active);

	if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED)
		process_secondaries (self, active, TRUE);
	else if (state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED)
		process_secondaries (self, active, FALSE);
}

static void
active_connection_added (NMManager *manager,
                         NMActiveConnection *active,
                         gpointer user_data)
{
	NMPolicyPrivate *priv = user_data;
	NMPolicy *self = _PRIV_TO_SELF (priv);

	if (NM_IS_VPN_CONNECTION (active)) {
		g_signal_connect (active, NM_VPN_CONNECTION_INTERNAL_STATE_CHANGED,
		                  G_CALLBACK (vpn_connection_state_changed),
		                  self);
		g_signal_connect (active, NM_VPN_CONNECTION_INTERNAL_RETRY_AFTER_FAILURE,
		                  G_CALLBACK (vpn_connection_retry_after_failure),
		                  self);
	}

	g_signal_connect (active, "notify::" NM_ACTIVE_CONNECTION_STATE,
	                  G_CALLBACK (active_connection_state_changed),
	                  self);
}

static void
active_connection_removed (NMManager *manager,
                           NMActiveConnection *active,
                           gpointer user_data)
{
	NMPolicyPrivate *priv = user_data;
	NMPolicy *self = _PRIV_TO_SELF (priv);

	g_signal_handlers_disconnect_by_func (active,
	                                      vpn_connection_state_changed,
	                                      self);
	g_signal_handlers_disconnect_by_func (active,
	                                      vpn_connection_retry_after_failure,
	                                      self);
	g_signal_handlers_disconnect_by_func (active,
	                                      active_connection_state_changed,
	                                      self);
}

/*****************************************************************************/

static gboolean
schedule_activate_all_cb (gpointer user_data)
{
	NMPolicy *self = user_data;
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	const GSList *iter;

	priv->schedule_activate_all_id = 0;

	for (iter = nm_manager_get_devices (priv->manager); iter; iter = g_slist_next (iter))
		schedule_activate_check (self, iter->data);

	return G_SOURCE_REMOVE;
}

static void
schedule_activate_all (NMPolicy *self)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);

	/* always restart the idle handler. That way, we settle
	 * all other events before restarting to activate them. */
	nm_clear_g_source (&priv->schedule_activate_all_id);
	priv->schedule_activate_all_id = g_idle_add (schedule_activate_all_cb, self);
}

static void
connection_added (NMSettings *settings,
                  NMSettingsConnection *connection,
                  gpointer user_data)
{
	NMPolicyPrivate *priv = user_data;
	NMPolicy *self = _PRIV_TO_SELF (priv);

	schedule_activate_all (self);
}

static void
firewall_started (NMFirewallManager *manager,
                  gpointer user_data)
{
	NMPolicy *self = (NMPolicy *) user_data;
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	const GSList *iter;

	/* add interface of each device to correct zone */
	for (iter = nm_manager_get_devices (priv->manager); iter; iter = g_slist_next (iter))
		nm_device_update_firewall_zone (iter->data);
}

static void
dns_config_changed (NMDnsManager *dns_manager, gpointer user_data)
{
	NMPolicy *self = (NMPolicy *) user_data;
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);

	/* Restart a thread for reverse-DNS lookup after we are signalled that
	 * DNS changed. Because the result from a previous run may not be right
	 * (race in updating DNS and doing the reverse lookup).
	 */

	/* Stop a lookup thread if any. */
	if (priv->lookup_cancellable) {
		g_cancellable_cancel (priv->lookup_cancellable);
		g_clear_object (&priv->lookup_cancellable);
	}

	/* Re-start the hostname lookup thread if we don't have hostname yet. */
	if (priv->lookup_addr) {
		char *str = NULL;

		_LOGD (LOGD_DNS, "restarting reverse-lookup thread for address %s",
		       (str = g_inet_address_to_string (priv->lookup_addr)));
		g_free (str);

		priv->lookup_cancellable = g_cancellable_new ();
		g_resolver_lookup_by_address_async (priv->resolver,
		                                    priv->lookup_addr,
		                                    priv->lookup_cancellable,
		                                    lookup_callback, self);
	}
}

static void
connection_updated (NMSettings *settings,
                    NMSettingsConnection *connection,
                    gboolean by_user,
                    gpointer user_data)
{
	NMPolicyPrivate *priv = user_data;
	NMPolicy *self = _PRIV_TO_SELF (priv);
	const GSList *iter;
	NMDevice *device = NULL;

	if (by_user) {
		/* find device with given connection */
		for (iter = nm_manager_get_devices (priv->manager); iter; iter = g_slist_next (iter)) {
			NMDevice *dev = NM_DEVICE (iter->data);

			if (nm_device_get_settings_connection (dev) == connection) {
				device = dev;
				break;
			}
		}

		if (device)
			nm_device_reapply_settings_immediately (device);

		/* Reset auto retries back to default since connection was updated */
		nm_settings_connection_reset_autoconnect_retries (connection);
	}

	schedule_activate_all (self);
}

static void
_deactivate_if_active (NMManager *manager, NMSettingsConnection *connection)
{
	const GSList *active, *iter;

	active = nm_manager_get_active_connections (manager);
	for (iter = active; iter; iter = g_slist_next (iter)) {
		NMActiveConnection *ac = iter->data;
		NMActiveConnectionState state = nm_active_connection_get_state (ac);
		GError *error = NULL;

		if (nm_active_connection_get_settings_connection (ac) == connection &&
		    (state <= NM_ACTIVE_CONNECTION_STATE_ACTIVATED)) {
			if (!nm_manager_deactivate_connection (manager,
			                                       ac,
			                                       NM_DEVICE_STATE_REASON_CONNECTION_REMOVED,
			                                       &error)) {
				_LOGW (LOGD_DEVICE, "connection '%s' disappeared, but error deactivating it: (%d) %s",
				       nm_settings_connection_get_id (connection),
				       error ? error->code : -1,
				       error ? error->message : "(unknown)");
				g_clear_error (&error);
			}
		}
	}
}

static void
connection_removed (NMSettings *settings,
                    NMSettingsConnection *connection,
                    gpointer user_data)
{
	NMPolicyPrivate *priv = user_data;

	_deactivate_if_active (priv->manager, connection);
}

static void
connection_visibility_changed (NMSettings *settings,
                               NMSettingsConnection *connection,
                               gpointer user_data)
{
	NMPolicyPrivate *priv = user_data;
	NMPolicy *self = _PRIV_TO_SELF (priv);

	if (nm_settings_connection_is_visible (connection))
		schedule_activate_all (self);
	else
		_deactivate_if_active (priv->manager, connection);
}

static void
secret_agent_registered (NMSettings *settings,
                         NMSecretAgent *agent,
                         gpointer user_data)
{
	NMPolicyPrivate *priv = user_data;
	NMPolicy *self = _PRIV_TO_SELF (priv);

	/* The registered secret agent may provide some missing secrets. Thus we
	 * reset retries count here and schedule activation, so that the
	 * connections failed due to missing secrets may re-try auto-connection.
	 */
	reset_autoconnect_for_failed_secrets (self);
	schedule_activate_all (self);
}

NMDevice *
nm_policy_get_default_ip4_device (NMPolicy *self)
{
	return NM_POLICY_GET_PRIVATE (self)->default_device4;
}

NMDevice *
nm_policy_get_default_ip6_device (NMPolicy *self)
{
	return NM_POLICY_GET_PRIVATE (self)->default_device6;
}

NMDevice *
nm_policy_get_activating_ip4_device (NMPolicy *self)
{
	return NM_POLICY_GET_PRIVATE (self)->activating_device4;
}

NMDevice *
nm_policy_get_activating_ip6_device (NMPolicy *self)
{
	return NM_POLICY_GET_PRIVATE (self)->activating_device6;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMPolicy *self = NM_POLICY (object);
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_DEFAULT_IP4_DEVICE:
		g_value_set_object (value, priv->default_device4);
		break;
	case PROP_DEFAULT_IP6_DEVICE:
		g_value_set_object (value, priv->default_device6);
		break;
	case PROP_ACTIVATING_IP4_DEVICE:
		g_value_set_object (value, priv->activating_device4);
		break;
	case PROP_ACTIVATING_IP6_DEVICE:
		g_value_set_object (value, priv->activating_device6);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMPolicy *self = NM_POLICY (object);
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_MANAGER:
		/* construct-only */
		priv->manager = g_value_get_object (value);
		g_return_if_fail (NM_IS_MANAGER (priv->manager));
		break;
	case PROP_SETTINGS:
		/* construct-only */
		priv->settings = g_value_dup_object (value);
		g_return_if_fail (NM_IS_SETTINGS (priv->settings));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_policy_init (NMPolicy *self)
{
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);

	priv->devices = g_hash_table_new (NULL, NULL);
	priv->ip6_prefix_delegations = g_array_new (FALSE, FALSE, sizeof (IP6PrefixDelegation));
	g_array_set_clear_func (priv->ip6_prefix_delegations, clear_ip6_prefix_delegation);
}

static void
constructed (GObject *object)
{
	NMPolicy *self = NM_POLICY (object);
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	char *hostname = NULL;

	/* Grab hostname on startup and use that if nothing provides one */
	if (_get_hostname (self, &hostname)) {
		/* only cache it if it's a valid hostname */
		if (nm_utils_is_specific_hostname (hostname))
			priv->orig_hostname = hostname;
		else
			g_free (hostname);
	}

	priv->firewall_manager = g_object_ref (nm_firewall_manager_get ());

	priv->fw_started_id = g_signal_connect (priv->firewall_manager, NM_FIREWALL_MANAGER_STARTED,
	                                        G_CALLBACK (firewall_started), self);

	priv->dns_manager = g_object_ref (nm_dns_manager_get ());
	nm_dns_manager_set_initial_hostname (priv->dns_manager, priv->orig_hostname);
	priv->config_changed_id = g_signal_connect (priv->dns_manager, NM_DNS_MANAGER_CONFIG_CHANGED,
	                                            G_CALLBACK (dns_config_changed), self);

	priv->resolver = g_resolver_get_default ();

	g_signal_connect (priv->manager, "notify::" NM_MANAGER_HOSTNAME,           (GCallback) hostname_changed, priv);
	g_signal_connect (priv->manager, "notify::" NM_MANAGER_SLEEPING,           (GCallback) sleeping_changed, priv);
	g_signal_connect (priv->manager, "notify::" NM_MANAGER_NETWORKING_ENABLED, (GCallback) sleeping_changed, priv);
	g_signal_connect (priv->manager, NM_MANAGER_INTERNAL_DEVICE_ADDED,         (GCallback) device_added, priv);
	g_signal_connect (priv->manager, NM_MANAGER_INTERNAL_DEVICE_REMOVED,       (GCallback) device_removed, priv);
	g_signal_connect (priv->manager, NM_MANAGER_ACTIVE_CONNECTION_ADDED,       (GCallback) active_connection_added, priv);
	g_signal_connect (priv->manager, NM_MANAGER_ACTIVE_CONNECTION_REMOVED,     (GCallback) active_connection_removed, priv);

	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_ADDED,              (GCallback) connection_added, priv);
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_UPDATED,            (GCallback) connection_updated, priv);
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_REMOVED,            (GCallback) connection_removed, priv);
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_VISIBILITY_CHANGED, (GCallback) connection_visibility_changed, priv);
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_AGENT_REGISTERED,              (GCallback) secret_agent_registered, priv);

	G_OBJECT_CLASS (nm_policy_parent_class)->constructed (object);
}

NMPolicy *
nm_policy_new (NMManager *manager, NMSettings *settings)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (NM_IS_SETTINGS (settings), NULL);

	return g_object_new (NM_TYPE_POLICY,
	                     NM_POLICY_MANAGER, manager,
	                     NM_POLICY_SETTINGS, settings,
	                     NULL);
}

static void
dispose (GObject *object)
{
	NMPolicy *self = NM_POLICY (object);
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);
	const GSList *connections;
	GHashTableIter h_iter;
	NMDevice *device;

	nm_clear_g_cancellable (&priv->lookup_cancellable);

	g_clear_object (&priv->lookup_addr);
	g_clear_object (&priv->resolver);

	while (priv->pending_activation_checks)
		activate_data_free (priv->pending_activation_checks->data);

	g_slist_free_full (priv->pending_secondaries, (GDestroyNotify) pending_secondary_data_free);
	priv->pending_secondaries = NULL;

	if (priv->firewall_manager) {
		g_assert (priv->fw_started_id);
		nm_clear_g_signal_handler (priv->firewall_manager, &priv->fw_started_id);
		g_clear_object (&priv->firewall_manager);
	}

	if (priv->dns_manager) {
		nm_clear_g_signal_handler (priv->dns_manager, &priv->config_changed_id);
		g_clear_object (&priv->dns_manager);
	}

	g_hash_table_iter_init (&h_iter, priv->devices);
	if (g_hash_table_iter_next (&h_iter, (gpointer *) &device, NULL)) {
		g_hash_table_iter_remove (&h_iter);
		devices_list_unregister (self, device);
	}

	/* The manager should have disposed of ActiveConnections already, which
	 * will have called active_connection_removed() and thus we don't need
	 * to clean anything up.  Assert that this is TRUE.
	 */
	connections = nm_manager_get_active_connections (priv->manager);
	g_assert (connections == NULL);

	nm_clear_g_source (&priv->reset_retries_id);
	nm_clear_g_source (&priv->schedule_activate_all_id);

	g_clear_pointer (&priv->orig_hostname, g_free);
	g_clear_pointer (&priv->cur_hostname, g_free);

	if (priv->settings) {
		g_signal_handlers_disconnect_by_data (priv->settings, priv);
		g_clear_object (&priv->settings);

		/* we don't clear priv->manager as we don't own a reference to it,
		 * that is, NMManager must outlive NMPolicy anyway.
		 *
		 * Hence, we unsubscribe the signals here together with the signals
		 * for settings. */
		g_signal_handlers_disconnect_by_data (priv->manager, priv);
	}

	if (priv->ip6_prefix_delegations) {
		g_array_free (priv->ip6_prefix_delegations, TRUE);
		priv->ip6_prefix_delegations = NULL;
	}

	nm_assert (NM_IS_MANAGER (priv->manager));

	G_OBJECT_CLASS (nm_policy_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMPolicy *self = NM_POLICY (object);
	NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE (self);

	g_hash_table_unref (priv->devices);

	G_OBJECT_CLASS (nm_policy_parent_class)->finalize (object);
}

static void
nm_policy_class_init (NMPolicyClass *policy_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (policy_class);

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->constructed = constructed;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	obj_properties[PROP_MANAGER] =
	    g_param_spec_object (NM_POLICY_MANAGER, "", "",
	                         NM_TYPE_MANAGER,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_SETTINGS] =
	    g_param_spec_object (NM_POLICY_SETTINGS, "", "",
	                         NM_TYPE_SETTINGS,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DEFAULT_IP4_DEVICE] =
	    g_param_spec_object (NM_POLICY_DEFAULT_IP4_DEVICE, "", "",
	                         NM_TYPE_DEVICE,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DEFAULT_IP6_DEVICE] =
	    g_param_spec_object (NM_POLICY_DEFAULT_IP6_DEVICE, "", "",
	                         NM_TYPE_DEVICE,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ACTIVATING_IP4_DEVICE] =
	    g_param_spec_object (NM_POLICY_ACTIVATING_IP4_DEVICE, "", "",
	                         NM_TYPE_DEVICE,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ACTIVATING_IP6_DEVICE] =
	    g_param_spec_object (NM_POLICY_ACTIVATING_IP6_DEVICE, "", "",
	                         NM_TYPE_DEVICE,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
