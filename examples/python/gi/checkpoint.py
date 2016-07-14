#!/usr/bin/env python
# vim: ft=python ts=4 sts=4 sw=4 et ai
# -*- Mode: python; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2016 Red Hat, Inc.
#

import sys
import time
import gi
gi.require_version('NM', '1.0')
from gi.repository import GLib, NM

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit('Usage: %s <interface>' % sys.argv[0])

    client = NM.Client.new(None)

    dev = client.get_device_by_iface(sys.argv[1])
    if dev is None:
        sys.exit('Device \'%s\' not found' % sys.argv[1])

    id = client.checkpoint_create([ dev ], 0,
                                  NM.CheckpointCreateFlags.DESTROY_ALL)

    print "Checkpoint id: %s" % (id)

    choice = raw_input('Do you want to rollback [y/n]? ').lower()

    if choice == 'y':
        print "Rollback of checkpoint %s" % (id)
        client.checkpoint_rollback(id)
    else:
        print "Destroy checkpoint %s" % (id)
        client.checkpoint_destroy(id)
