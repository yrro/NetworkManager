/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager
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
 * Copyright (C) 2016 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-checkpoint-manager.h"

#include "nm-auth-subject.h"
#include "nm-connection.h"
#include "nm-core-utils.h"
#include "nm-device.h"
#include "nm-manager.h"
#include "nm-exported-object.h"
#include "nm-settings.h"
#include "nm-simple-connection.h"
#include "nm-utils.h"

/*****************************************************************************/

struct _NMCheckpointManager {
	NMManager *_manager;
	GHashTable *checkpoints;
	guint rollback_timeout_id;
};

#define GET_MANAGER(self) \
	({ \
		typeof (self) _self = (self); \
		\
		_nm_unused NMCheckpointManager *_self2 = _self; \
		\
		nm_assert (_self); \
		nm_assert (NM_IS_MANAGER (_self->_manager)); \
		_self->_manager; \
	})

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME                "checkpoint"
#define _NMLOG_DOMAIN                     LOGD_CORE

#define _NMLOG(level, ...) \
	nm_log (level, _NMLOG_DOMAIN, \
	        "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
	        _NMLOG_PREFIX_NAME \
	        _NM_UTILS_MACRO_REST(__VA_ARGS__))

/*****************************************************************************/

typedef struct {
	char *dev_path;
	NMConnection *connection;
} DeviceCheckpoint;

typedef struct {
	char *id;
	gint64 rollback_ts;
	GHashTable *devices;
} Checkpoint;

static void update_rollback_timeout (NMCheckpointManager *self);

static void
device_checkpoint_destroy (gpointer data)
{
	DeviceCheckpoint *dev_cp = data;

	g_free (dev_cp->dev_path);
	g_clear_object (&dev_cp->connection);
	g_slice_free (DeviceCheckpoint, dev_cp);
}

static void
checkpoint_destroy (gpointer data)
{
	Checkpoint *cp = data;

	g_free (cp->id);
	g_hash_table_destroy (cp->devices);
	g_slice_free (Checkpoint, cp);
}

static gboolean
do_rollback (NMCheckpointManager *self, Checkpoint *cp, GError **error)
{
	DeviceCheckpoint *dev_cp;
	GHashTableIter iter;
	const char *path;
	NMSettingsConnection *connection;
	NMDevice *device;
	GError *local_error = NULL;
	gboolean success = TRUE;

	_LOGI ("rollback of checkpoint %s", cp->id);

	/* Start rolling-back each device */
	g_hash_table_iter_init (&iter, cp->devices);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &dev_cp)) {
		gs_unref_object NMAuthSubject *subject = NULL;

		device = nm_manager_get_device_by_path (self->_manager, dev_cp->dev_path);
		if (!device) {
			_LOGD ("device %s no longer exists", dev_cp->dev_path);
			success = FALSE;
		}

		_LOGD ("restoring state of device %s", nm_device_get_iface (device));

		if (dev_cp->connection) {
			/* The device had an active connection, check if the
			 * connection still exists
			 * */
			path = nm_connection_get_path (dev_cp->connection);
			connection = nm_settings_get_connection_by_path (nm_settings_get(), path);

			if (connection) {
				/* If the connection is still there, restore its content
				 * and save it
				 * */
				_LOGD ("connection %s still exists", path);

				nm_connection_replace_settings_from_connection (NM_CONNECTION (connection),
				                                                dev_cp->connection);
				nm_settings_connection_commit_changes (connection,
				                                       NM_SETTINGS_CONNECTION_COMMIT_REASON_NONE,
				                                       NULL,
				                                       NULL);
			} else {
				/* The connection was deleted, recreate it */

				_LOGD ("adding connection %s again", path);

				connection = nm_settings_add_connection (nm_settings_get (),
				                                         dev_cp->connection,
				                                         TRUE,
				                                         &local_error);
				if (!connection) {
					_LOGW ("connection add failure: %s", local_error->message);
					g_clear_error (&local_error);
					success = FALSE;
					continue;
				}
			}

			/* Now re-activate the connection */
			subject = nm_auth_subject_new_internal ();
			if (!nm_manager_activate_connection (self->_manager,
			                                     connection,
			                                     NULL,
			                                     device,
			                                     subject,
			                                     &local_error)) {
				_LOGW ("reactivation of connection %s/%s failed: %s",
				       nm_connection_get_id ((NMConnection *) connection),
				       nm_connection_get_uuid ((NMConnection *	) connection),
				       local_error->message);
				g_clear_error (&local_error);
				success = FALSE;
				continue;
			}
		} else {

			/* The device was disconnected, deactivate any existing connection */

			_LOGD ("disconnecting device %s", nm_device_get_iface (device));

			if (   nm_device_get_state (device) > NM_DEVICE_STATE_DISCONNECTED
			    && nm_device_get_state (device) < NM_DEVICE_STATE_DEACTIVATING) {
				nm_device_state_changed (device,
				                         NM_DEVICE_STATE_DEACTIVATING,
				                         NM_DEVICE_STATE_REASON_USER_REQUESTED);
			}
		}
	}

	return success;
}


static gboolean
rollback_timeout_cb (NMCheckpointManager *self)
{
	GHashTableIter iter;
	Checkpoint *cp;
	gint64 now;

	now = nm_utils_get_monotonic_timestamp_ms ();

	g_hash_table_iter_init (&iter, self->checkpoints);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &cp)) {
		if (cp->rollback_ts <= now) {
			do_rollback (self, cp, NULL);
			g_hash_table_iter_remove (&iter);
		}
	}

	self->rollback_timeout_id = 0;
	update_rollback_timeout (self);

	return FALSE;
}

static void
update_rollback_timeout (NMCheckpointManager *self)
{
	GHashTableIter iter;
	Checkpoint *cp;
	gint64 delta, next = G_MAXINT64;

	g_hash_table_iter_init (&iter, self->checkpoints);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &cp)) {
		if (cp->rollback_ts && cp->rollback_ts < next)
			next = cp->rollback_ts;
	}

	nm_clear_g_source (&self->rollback_timeout_id);

	if (next != G_MAXINT64) {
		delta = MAX (next - nm_utils_get_monotonic_timestamp_ms (), 0);
		self->rollback_timeout_id = g_timeout_add (delta,
		                                           (GSourceFunc) rollback_timeout_cb,
		                                           self);
		_LOGT ("update timeout: next check in %" G_GINT64_FORMAT " ms", delta);
	}
}

static Checkpoint *
find_checkpoint_for_device (NMCheckpointManager *self, const char *dev_path)
{
	GHashTableIter iter;
	Checkpoint *cp;
	DeviceCheckpoint *dev_cp;

	g_hash_table_iter_init (&iter, self->checkpoints);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &cp)) {
		dev_cp = g_hash_table_lookup (cp->devices, dev_path);
		if (dev_cp)
			return cp;
	}

	return NULL;
}

static DeviceCheckpoint *
device_checkpoint_create (NMCheckpointManager *self,
                          const char *dev_path,
                          GError **error)
{
	NMDevice *device;
	NMConnection *connection;
	DeviceCheckpoint *cp;

	device = nm_manager_get_device_by_path (self->_manager, dev_path);
	if (!device) {
		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_UNKNOWN_DEVICE,
		             "unknown device '%s'", dev_path);
		return NULL;
	}

	cp = g_slice_new0 (DeviceCheckpoint);
	cp->dev_path = g_strdup (dev_path);

	connection = nm_device_get_applied_connection (device);
	if (connection)
		cp->connection = nm_simple_connection_new_clone (connection);

	return cp;
}

static const char **
get_all_device_paths (NMCheckpointManager *self)
{
	const GSList *devices, *iter;
	NMDevice *dev;
	GPtrArray *paths;
	const char *path;

	devices = nm_manager_get_devices (self->_manager);
	paths = g_ptr_array_new ();

	for (iter = devices; iter; iter = g_slist_next (iter)) {
		dev = iter->data;

		if (!nm_device_is_real (dev))
			continue;
		if (nm_device_get_state (dev) == NM_DEVICE_STATE_UNMANAGED)
			continue;
		/* We never touch assumed connections, unless told explicitly */
		if (nm_device_uses_assumed_connection (dev))
			continue;

		path = nm_exported_object_get_path (NM_EXPORTED_OBJECT (dev));
		g_ptr_array_add (paths, (gpointer) path);
	}

	g_ptr_array_add (paths, NULL);

	return (const char **) g_ptr_array_free (paths, FALSE);
}

char *
nm_checkpoint_manager_create (NMCheckpointManager *self,
                              const char *const *device_paths,
                              guint32 rollback_timeout,
                              NMCheckpointCreateFlags flags,
                              GError **error)
{
	Checkpoint *cp;
	DeviceCheckpoint *dev_cp;
	const char * const *path;
	gs_free const char **device_paths_free = NULL;

	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	if (!device_paths || !device_paths[0]) {
		device_paths_free = get_all_device_paths (self);
		device_paths = (const char *const *) device_paths_free;
	}

	if (!NM_FLAGS_HAS (flags, NM_CHECKPOINT_CREATE_FLAG_DESTROY_ALL)) {
		for (path = device_paths; *path; path++) {
			if (find_checkpoint_for_device (self, *path)) {
				g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_INVALID_ARGUMENTS,
				             "a checkpoint for device '%s' already exists",
				             *path);
				return NULL;
			}
		}
	}

	cp = g_slice_new0 (Checkpoint);
	cp->rollback_ts = rollback_timeout ?
		(nm_utils_get_monotonic_timestamp_ms () + (gint64) 1000 * rollback_timeout) :
		0;
	cp->devices = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                     NULL, device_checkpoint_destroy);

	for (path = device_paths; *path; path++) {
		dev_cp = device_checkpoint_create (self, *path, error);
		if (!dev_cp) {
			checkpoint_destroy (cp);
			return NULL;
		}
		g_hash_table_insert (cp->devices, dev_cp->dev_path, dev_cp);
	}

	if (NM_FLAGS_HAS (flags, NM_CHECKPOINT_CREATE_FLAG_DESTROY_ALL))
		g_hash_table_remove_all (self->checkpoints);

	cp->id = nm_utils_uuid_generate ();
	if (!nm_g_hash_table_insert (self->checkpoints, cp->id, cp))
		g_return_val_if_reached (NULL);

	_LOGI ("created checkpoint %s", cp->id);

	update_rollback_timeout (self);

	return cp->id;
}

gboolean
nm_checkpoint_manager_destroy_all (NMCheckpointManager *self,
                                   GError **error)
{
	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	g_hash_table_remove_all (self->checkpoints);

	return TRUE;
}

gboolean
nm_checkpoint_manager_destroy (NMCheckpointManager *self,
                               const char *checkpoint_id,
                               GError **error)
{
	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	if (checkpoint_id && checkpoint_id[0]) {
		_LOGI ("destroy checkpoint %s", checkpoint_id);
		return g_hash_table_remove (self->checkpoints, checkpoint_id);
	} else {
		_LOGI ("destroy all checkpoints");
		g_hash_table_remove_all (self->checkpoints);
		return TRUE;
	}
}

gboolean
nm_checkpoint_manager_rollback (NMCheckpointManager *self,
                                const char *checkpoint_id,
                                GError **error)
{
	Checkpoint *cp;
	gboolean ret;

	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (checkpoint_id && *checkpoint_id, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	cp = g_hash_table_lookup (self->checkpoints, checkpoint_id);
	if (!cp) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
		             "checkpoint '%s' does not exist", checkpoint_id);
		return FALSE;
	}

	ret = do_rollback (self, cp, error);

	g_hash_table_remove (self->checkpoints, cp->id);

	return ret;
}

/*****************************************************************************/

NMCheckpointManager *
nm_checkpoint_manager_new (NMManager *manager)
{
	NMCheckpointManager *self;

	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);

	self = g_slice_new0 (NMCheckpointManager);

	/* the NMCheckpointManager instance is actually owned by NMManager.
	 * Thus, we cannot take a reference to it, and we also don't bother
	 * taking a weak-reference. Instead let GET_MANAGER() assert that
	 * self->_manager is alive -- which we always expect as the lifetime
	 * of NMManager shall surpass the lifetime of the NMCheckpointManager
	 * instance. */
	self->_manager = manager;
	self->checkpoints = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                           NULL, checkpoint_destroy);

	return self;
}

void
nm_checkpoint_manager_unref (NMCheckpointManager *self)
{
	/* proper ref-counting is not yet implemented, and maybe not needed. */

	if (!self)
		return;

	GET_MANAGER (self);

	nm_clear_g_source (&self->rollback_timeout_id);
	g_hash_table_destroy (self->checkpoints);

	g_slice_free (NMCheckpointManager, self);
}

