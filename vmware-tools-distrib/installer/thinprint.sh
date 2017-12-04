#!/bin/sh
#
# Copyright (c) 1998-2015 VMware, Inc.  All rights reserved.
#
# This script manages the services needed to run VMware software

##VMWARE_INIT_INFO##

SCRIPTNAME="$(basename $(readlink -f "$0"))"
MODNAME="thinprint"
subsys="vmware-tools-vmtoolsd"
vmware_etc_dir=/etc/vmware-tools

# This should come before the inclusion of UTIL_DOT_SH.
vmdbScript="/usr/lib/vmware-tools/moduleScripts/${MODNAME}/vmware-db.pl @@OSTAG@@"

vmdb_answer_SBINDIR=`$vmdbScript --dbGetAnswer SBINDIR`
vmdb_answer_OPEN_VM_COMPAT=`$vmdbScript --dbGetAnswer OPEN_VM_COMPAT`
SYSTEM_DAEMON=vmtoolsd

if [ "$vmdb_answer_OPEN_VM_COMPAT" = 'yes' ] ; then
   SYSTEM_DAEMON_PATH=/usr/bin/${SYSTEM_DAEMON}
else
   SYSTEM_DAEMON_PATH=${vmdb_answer_SBINDIR}/${SYSTEM_DAEMON}
fi

# Make sure the ESC byte is literal: Ash does not support echo -e
rc_done='[71G done'
rc_failed='[71Gfailed'

# BEGINNING_OF_UTIL_DOT_SH
#!/bin/sh
#
# Copyright (c) 2005-2015 VMware, Inc.  All rights reserved.
#
# A few utility functions used by our shell scripts.  Some expect the settings
# database to already be loaded and evaluated.

vmblockmntpt="/proc/fs/vmblock/mountPoint"
vmblockfusemntpt="/var/run/vmblock-fuse"

# Unless vmdbScript already has a value, assign default value to it.
# The assumption here is that the script that includes util.sh will assign it first.
# This is just a safety, in case a sourcing script forgets to assign it.
: ${vmdbScript:="/usr/lib/vmware-tools/moduleScripts/${MODNAME}/vmware-db.pl @@OSTAG@@"}

vmdb_answer_SBINDIR=`$vmdbScript --dbGetAnswer SBINDIR`
vmdb_answer_LIBDIR=`$vmdbScript --dbGetAnswer LIBDIR`
CHECKVMBIN=$vmdb_answer_LIBDIR"/sbin/vmware-checkvm"

#
# We exit on failure because these functions are called within the
# context of vmware_exec, which sets up a trap that causes exit to jump
# back to vmware_exec, like an exception handler. On success, we return
# because our caller may want to perform additional instructions.

# XXX: This module does not handle the upstream module case at the moment
#      b/c this function is only needed for PMWV modules.
# XXX: FIXME.  Should use info in modules.dep, not look for file names.
vmware_isModuleInstalled() {
   kernel=`uname -r`

   # Look in extra/vmware/ for our modules.
   if [ -e /lib/modules/$kernel/extra/vmware/$MODNAME.ko ]; then
      /bin/true
   else
      /bin/false
   fi
}

# PMWV_MODULE

vmware_modprobe() {
   local module_name="`vmware_getModName $1`"

   # The module is already registered through depmod.  Just load it.
   /sbin/modprobe "$module_name" || exit 1

   return 0
}

vmware_load_module() {
   # Since we are moving to modprobe, we only need to modprobe the module.
   # We no longer unload and re-load because that may cause severe
   # problems (ie pvscsi or vmxnet3).
   vmware_modprobe $1
}

vmware_unload_module() {
   local module="$1"
   local module_name="`vmware_getModName $1`"
   if [ "`isLoaded "$1"`" = 'yes' ]; then
      # First try our module name.  If we are unloading an upstreamed module
      # then this won't work and we need to unload the name of the upstream
      # module.  Use --first-time with our modprobe commands here so we
      # actually know if we unloaded something.
      # Then there is this awesome bug in modprobe where if your module file
      # name is different than the name the module gets loaded as, modprobe
      # will be unable to unload the module because it tries to rmmod the
      # module based on its file name (assuming its the same as its loaded
      # name).  So fall back to a direct rmmod.  Its not the best, but its
      # better than nothing.
      /sbin/modprobe --first-time -r "$module" || \
         /sbin/modprobe --first-time -r "$module_name" || \
         /sbin/rmmod "$module" || \
         return 1
   fi

   return 0
}

vmware_failed() {
  if [ "`type -t 'echo_failure' 2>/dev/null`" = 'function' ]; then
    echo_failure
  else
    echo -n "$rc_failed"
  fi
}

vmware_success() {
  if [ "`type -t 'echo_success' 2>/dev/null`" = 'function' ]; then
    echo_success
  else
    echo -n "$rc_done"
  fi
}

# Execute a macro
vmware_exec() {
  local msg="$1"  # IN
  local func="$2" # IN
  shift 2

  echo -n '   '"$msg"

  # On Caldera 2.2, SIGHUP is sent to all our children when this script exits
  # I wanted to use shopt -u huponexit instead but their bash version
  # 1.14.7(1) is too old
  #
  # Ksh does not recognize the SIG prefix in front of a signal name
  if [ "$VMWARE_DEBUG" = 'yes' ]; then
    (trap '' HUP; "$func" "$@")
  else
    (trap '' HUP; "$func" "$@") >/dev/null 2>&1
  fi
  if [ "$?" -gt 0 ]; then
    vmware_failed
    echo
    return 1
  fi

  vmware_success
  echo
  return 0
}

# Execute a macro in the background
vmware_bg_exec() {
  local msg="$1"  # IN
  local func="$2" # IN
  shift 2

  if [ "$VMWARE_DEBUG" = 'yes' ]; then
    # Force synchronism when debugging
    vmware_exec "$msg" "$func" "$@"
  else
    echo -n '   '"$msg"' (background)'

    # On Caldera 2.2, SIGHUP is sent to all our children when this script exits
    # I wanted to use shopt -u huponexit instead but their bash version
    # 1.14.7(1) is too old
    #
    # Ksh does not recognize the SIG prefix in front of a signal name
    (trap '' HUP; "$func" "$@") 2>&1 | logger -t 'VMware[init]' -p daemon.err &

    vmware_success
    echo
    return 0
  fi
}

# This is a function in case a future product name contains language-specific
# escape characters.
vmware_product_name() {
  echo "VMware Tools $MODNAME Module"
  exit 0
}

# This is a function in case a future product contains language-specific
# escape characters.
vmware_product() {
  echo "tools-for-linux-$MODNAME"
  exit 0
}

# They are a lot of small utility programs to create temporary files in a
# secure way, but none of them is standard. So I wrote this
make_tmp_dir() {
  local dirname="$1" # OUT
  local prefix="$2"  # IN
  local tmp
  local serial
  local loop

  tmp="${TMPDIR:-/tmp}"

  # Don't overwrite existing user data
  # -> Create a directory with a name that didn't exist before
  #
  # This may never succeed (if we are racing with a malicious process), but at
  # least it is secure
  serial=0
  loop='yes'
  while [ "$loop" = 'yes' ]; do
    # Check the validity of the temporary directory. We do this in the loop
    # because it can change over time
    if [ ! -d "$tmp" ]; then
      echo 'Error: "'"$tmp"'" is not a directory.'
      echo
      exit 1
    fi
    if [ ! -w "$tmp" -o ! -x "$tmp" ]; then
      echo 'Error: "'"$tmp"'" should be writable and executable.'
      echo
      exit 1
    fi

    # Be secure
    # -> Don't give write access to other users (so that they can not use this
    # directory to launch a symlink attack)
    if mkdir -m 0755 "$tmp"'/'"$prefix$serial" >/dev/null 2>&1; then
      loop='no'
    else
      serial=`expr $serial + 1`
      serial_mod=`expr $serial % 200`
      if [ "$serial_mod" = '0' ]; then
        echo 'Warning: The "'"$tmp"'" directory may be under attack.'
        echo
      fi
    fi
  done

  eval "$dirname"'="$tmp"'"'"'/'"'"'"$prefix$serial"'
}

# Removes "stale" device node
# On udev-based systems, this is never needed.
# On older systems, after an unclean shutdown, we might end up with
# a stale device node while the kernel driver has a new major/minor.
vmware_rm_stale_node() {
   local node="$1"  # IN
   if [ -e "/dev/$node" -a "$node" != "" ]; then
      local node_major=`ls -l "/dev/$node" | awk '{print \$5}' | sed -e s/,//`
      local node_minor=`ls -l "/dev/$node" | awk '{print \$6}'`
      if [ "$node_major" = "10" ]; then
         local real_minor=`cat /proc/misc | grep "$node" | awk '{print \$1}'`
         if [ "$node_minor" != "$real_minor" ]; then
            rm -f "/dev/$node"
         fi
      else
         local node_name=`echo $node | sed -e s/[0-9]*$//`
         local real_major=`cat /proc/devices | grep "$node_name" | awk '{print \$1}'`
         if [ "$node_major" != "$real_major" ]; then
            rm -f "/dev/$node"
         fi
      fi
   fi
}

# Checks if the given pid represents a live process.
# Returns 0 if the pid is a live process, 1 otherwise
vmware_is_process_alive() {
  local pid="$1" # IN

  ps -p $pid | grep $pid > /dev/null 2>&1
}

# Check if the process associated to a pidfile is running.
# Return 0 if the pidfile exists and the process is running, 1 otherwise
vmware_check_pidfile() {
  local pidfile="$1" # IN
  local pid

  pid=`cat "$pidfile" 2>/dev/null`
  if [ "$pid" = '' ]; then
    # The file probably does not exist or is empty. Failure
    return 1
  fi
  # Keep only the first number we find, because some Samba pid files are really
  # trashy: they end with NUL characters
  # There is no double quote around $pid on purpose
  set -- $pid
  pid="$1"

  vmware_is_process_alive $pid
}

# Note:
#  . Each daemon must be started from its own directory to avoid busy devices
#  . Each PID file doesn't need to be added to the installer database, because
#    it is going to be automatically removed when it becomes stale (after a
#    reboot). It must go directly under /var/run, or some distributions
#    (RedHat 6.0) won't clean it
#

# Terminate a process synchronously
vmware_synchrone_kill() {
   local pid="$1"    # IN
   local signal="$2" # IN
   local second

   kill -"$signal" "$pid"

   # Wait a bit to see if the dirty job has really been done
   for second in 0 1 2 3 4 5 6 7 8 9 10; do
      vmware_is_process_alive "$pid"
      if [ "$?" -ne 0 ]; then
         # Success
         return 0
      fi

      sleep 1
   done

   # Timeout
   return 1
}

# Kill the process associated to a pidfile
vmware_stop_pidfile() {
   local pidfile="$1" # IN
   local pid

   pid=`cat "$pidfile" 2>/dev/null`
   if [ "$pid" = '' ]; then
      # The file probably does not exist or is empty. Success
      return 0
   fi
   # Keep only the first number we find, because some Samba pid files are really
   # trashy: they end with NUL characters
   # There is no double quote around $pid on purpose
   set -- $pid
   pid="$1"

   # First try a nice SIGTERM
   if vmware_synchrone_kill "$pid" 15; then
      return 0
   fi

   # Then send a strong SIGKILL
   if vmware_synchrone_kill "$pid" 9; then
      return 0
   fi

   return 1
}

# Determine if SELinux is enabled
isSELinuxEnabled() {
   if [ "`cat /selinux/enforce 2> /dev/null`" = "1" ]; then
      echo "yes"
   else
      echo "no"
   fi
}

# Runs a command and retries under the provided SELinux context if it fails
vmware_exec_selinux() {
   local command="$1"
   # XXX We should probably ask the user at install time what context to use
   # when we retry commands.  unconfined_t is the correct choice for Red Hat.
   local context="unconfined_t"
   local retval

   $command
   retval=$?
   if [ $retval -ne 0 -a "`isSELinuxEnabled`" = 'yes' ]; then
      runcon -t $context -- $command
      retval=$?
   fi

   return $retval
}

# This is necessary to allow udev time to create a device node.  If we don't
# wait then udev will override the permissions we choose when it creates the
# device node after us.
vmware_delay_for_node() {
   local node="$1"
   local delay="$2"

   while [ ! -e $node -a ${delay} -gt 0 ]; do
      delay=`expr $delay - 1`
      sleep 1
   done
}

# Are we running in a VM?
vmware_inVM() {
   "$CHECKVMBIN" >/dev/null 2>&1
}

is_ESX_running() {
  if [ ! -f "${CHECKVMBIN}" ] ; then
    echo no
    return
  fi
  if "${CHECKVMBIN}" -p | grep -q ESX; then
    echo yes
  else
    echo no
  fi
}

wrap () {
  AMSG="$1"
  while [ `echo $AMSG | wc -c` -gt 75 ] ; do
    AMSG1=`echo $AMSG | sed -e 's/\(.\{1,75\} \).*/\1/' -e 's/  [ 	]*/  /'`
    AMSG=`echo $AMSG | sed -e 's/.\{1,75\} //' -e 's/  [ 	]*/  /'`
    echo "  $AMSG1"
  done
  echo "  $AMSG"
  echo " "
}

#---------------------------------------------------------------------------
#
# load_settings
#
# Load VMware Installer Service settings
#
# Returns:
#    0 on success, otherwise 1.
#
# Side Effects:
#    vmdb_* variables are set.
#---------------------------------------------------------------------------

load_settings() {
  local settings=`$DATABASE/vmis-settings`
  if [ $? -eq 0 ]; then
    eval "$settings"
    return 0
  else
    return 1
  fi
}

#---------------------------------------------------------------------------
#
# launch_binary
#
# Launch a binary with resolved dependencies.
#
# Returns:
#    None.
#
# Side Effects:
#    Process is replaced with the binary if successful,
#    otherwise returns 1.
#---------------------------------------------------------------------------

launch_binary() {
  local component="$1"		# IN: component name
  shift
  local binary="$2"		# IN: binary name
  shift
  local args="$@"		# IN: arguments
  shift

  # Convert -'s in component name to _ and lookup its libdir
  local component=`echo $component | tr '-' '_'`
  local libdir="vmdb_$component_libdir"

  exec "$libdir"'/bin/launcher.sh'		\
       "$libdir"'/lib'				\
       "$libdir"'/bin/'"$binary"		\
       "$libdir"'/libconf' "$args"
  return 1
}
# END_OF_UTIL_DOT_SH

#
# Utilities
#

# function to tell if this is an OSP installation or not
vmware_is_osp() {
   echo no
}

# thinprint is always 'confed' if this is an OSP. For tar installs this is
# optional
vmware_thinprint_confed() {
   if [ "$(vmware_is_osp)" = "yes" ] ; then
      echo 'yes'
   else
      $vmdbScript --dbGetAnswer THINPRINT_CONFED
   fi
}

# Setup thinprint serial port and start daemon
vmware_start_thinprint() {
   if [ "$(vmware_thinprint_confed)" = 'yes' ]; then
      # set serial port in tpvmlp.conf
      local serialPort=`vmware_thinprint_get_tty`
      mv -f /etc/tpvmlp.conf /etc/tpvmlp.conf.bak
      sed -e "/^\s*vmwcomgw\s*=/s/=.*/= \/dev\/$serialPort/" /etc/tpvmlp.conf.bak \
         > /etc/tpvmlp.conf
      rm -f /etc/tpvmlp.conf.bak

      export TPVMLP_SVC=global:daemon
      /usr/bin/tpvmlpd

   fi
}


# Stop thinprint daemon
vmware_stop_thinprint() {
   vmware_stop_pidfile "/var/run/tpvmlpd.pid"
}

vmware_thinprint_get_tty() {
   ${SYSTEM_DAEMON_PATH} --cmd 'info-get guestinfo.vprint.thinprintBackend' | \
	   sed -e s/serial/ttyS/
}


main()
{
   # See how we were called.
   case "$1" in
      start)
         if vmware_inVM; then
            vmware_exec 'Starting Virtual Printing daemon:' vmware_start_thinprint
            # Ignore the exitcode. The 64bit version of tpvlpd segfaults.
            # There is not much we can do about it.
         fi
         ;;

      stop)
         if vmware_inVM; then
            echo 'Stopping Thinprint services in the virtual machine:'
            vmware_exec 'Stopping Virtual Printing daemon:' vmware_stop_thinprint
            exit $?
         fi
         ;;

      status)
         tpstatus='is NOT running'
         vmware_check_pidfile "/var/run/tpvmlpd.pid"
         exitcode=$?
         if [ "$exitcode" = "0" ]; then
            tpstatus='is running'
         fi
         echo "Thinprint daemon ${tpstatus}."
         exit $exitcode
         ;;

      restart | force-reload)
         "$0" stop && "$0" start
         ;;

      source)
         # Used to source the script so that functions can be
         # selectively overridden.
         return 0
         ;;

      *)
         echo "Usage: `basename "$0"` {start|stop|status|restart|force-reload}"
         exit 1
   esac

   exit 0
}

main "$@"
