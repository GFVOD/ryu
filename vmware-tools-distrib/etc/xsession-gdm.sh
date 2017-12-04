#!/bin/sh
#
# Copyright (c) 2007-2015 VMware, Inc.  All rights reserved.
#

# This script is -sourced- by one of GDM's "legacy" session scripts.  (Said
# legacy method is very convenient for us, however!)  As such, it should be
# kept as simple as possible.  To do so, we make use of the XDM helper and
# instruct it to stop short of executing an Xsession script.
vmware_xsession_xdm="/etc/vmware-tools/xsession-xdm.sh"
if [ -x "$vmware_xsession_xdm" ]; then
   { sleep 15 && $vmware_xsession_xdm -gdm; } &
fi
