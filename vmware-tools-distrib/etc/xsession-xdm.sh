#!/bin/sh
#
# Copyright (c) 2007-2015 VMware, Inc.  All rights reserved.
#
# This script is run in two instances:
#   1.  It was hooked into XDM via twiddling xdm-config.
#   2.  It was hooked into legacy GDM via inserting a script in
#       /etc/X11/xinitrc.d.
#
# This script's responsibility is primarily to launch vmware-user during
# X session startup.  In the XDM case, after launching vmware-user, we
# resume executing the original, system Xsession script.  In the GDM
# case, we do nothing else.
#
# usage: xsession-xdm.sh [-gdm]
#    -gdm: Indicates caller is the GDM helper (xsession-gdm); run
#          vmware-user -only-, then exit.

# BEGINNING_OF_DB_DOT_SH
#!/bin/sh

#
# Manage an installer database
#

# Add an answer to a database in memory
db_answer_add() {
  local dbvar="$1" # IN/OUT
  local id="$2"    # IN
  local value="$3" # IN
  local answers
  local i

  eval "$dbvar"'_answer_'"$id"'="$value"'

  eval 'answers="$'"$dbvar"'_answers"'
  # There is no double quote around $answers on purpose
  for i in $answers; do
    if [ "$i" = "$id" ]; then
      return
    fi
  done
  answers="$answers"' '"$id"
  eval "$dbvar"'_answers="$answers"'
}

# Remove an answer from a database in memory
db_answer_remove() {
  local dbvar="$1" # IN/OUT
  local id="$2"    # IN
  local new_answers
  local answers
  local i

  eval 'unset '"$dbvar"'_answer_'"$id"

  new_answers=''
  eval 'answers="$'"$dbvar"'_answers"'
  # There is no double quote around $answers on purpose
  for i in $answers; do
    if [ "$i" != "$id" ]; then
      new_answers="$new_answers"' '"$i"
    fi
  done
  eval "$dbvar"'_answers="$new_answers"'
}

# Load all answers from a database on stdin to memory (<dbvar>_answer_*
# variables)
db_load_from_stdin() {
  local dbvar="$1" # OUT

  eval "$dbvar"'_answers=""'

  # read doesn't support -r on FreeBSD 3.x. For this reason, the following line
  # is patched to remove the -r in case of FreeBSD tools build. So don't make
  # changes to it.
  while read -r action p1 p2; do
    if [ "$action" = 'answer' ]; then
      db_answer_add "$dbvar" "$p1" "$p2"
    elif [ "$action" = 'remove_answer' ]; then
      db_answer_remove "$dbvar" "$p1"
    fi
  done
}

# Load all answers from a database on disk to memory (<dbvar>_answer_*
# variables)
db_load() {
  local dbvar="$1"  # OUT
  local dbfile="$2" # IN

  db_load_from_stdin "$dbvar" < "$dbfile"
}

# Iterate through all answers in a database in memory, calling <func> with
# id/value pairs and the remaining arguments to this function
db_iterate() {
  local dbvar="$1" # IN
  local func="$2"  # IN
  shift 2
  local answers
  local i
  local value

  eval 'answers="$'"$dbvar"'_answers"'
  # There is no double quote around $answers on purpose
  for i in $answers; do
    eval 'value="$'"$dbvar"'_answer_'"$i"'"'
    "$func" "$i" "$value" "$@"
  done
}

# If it exists in memory, remove an answer from a database (disk and memory)
db_remove_answer() {
  local dbvar="$1"  # IN/OUT
  local dbfile="$2" # IN
  local id="$3"     # IN
  local answers
  local i

  eval 'answers="$'"$dbvar"'_answers"'
  # There is no double quote around $answers on purpose
  for i in $answers; do
    if [ "$i" = "$id" ]; then
      echo 'remove_answer '"$id" >> "$dbfile"
      db_answer_remove "$dbvar" "$id"
      return
    fi
  done
}

# Add an answer to a database (disk and memory)
db_add_answer() {
  local dbvar="$1"  # IN/OUT
  local dbfile="$2" # IN
  local id="$3"     # IN
  local value="$4"  # IN

  db_remove_answer "$dbvar" "$dbfile" "$id"
  echo 'answer '"$id"' '"$value" >> "$dbfile"
  db_answer_add "$dbvar" "$id" "$value"
}

# Add a file to a database on disk
# 'file' is the file to put in the database (it may not exist on the disk)
# 'tsfile' is the file to get the timestamp from, '' if no timestamp
db_add_file() {
  local dbfile="$1" # IN
  local file="$2"   # IN
  local tsfile="$3" # IN
  local date

  if [ "$tsfile" = '' ]; then
    echo 'file '"$file" >> "$dbfile"
  else
    # We cannot guarantee existence of GNU coreutils date on all platforms
    # (e.g. Solaris).  Ignore timestamps in that case.
    date=`date -r "$tsfile" '+%s' 2> /dev/null` || true
    if [ "$date" != '' ]; then
      date=' '"$date"
    fi
    echo 'file '"$file$date" >> "$dbfile"
  fi
}

# Remove file from database
db_remove_file() {
  local dbfile="$1" # IN
  local file="$2"   # IN

  echo "remove_file $file" >> "$dbfile"
}

# Add a directory to a database on disk
db_add_dir() {
  local dbfile="$1" # IN
  local dir="$2"    # IN

  echo 'directory '"$dir" >> "$dbfile"
}
# END_OF_DB_DOT_SH

export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH=${PATH}:/usr/X11R6/bin

Xsession=""
vmware_user=""
vmware_etc_dir="/etc/vmware-tools"
vmware_db=""

failsafe()
{
   # Old school -- X11 ports/packages used to be installed under $X11BASE.
   exec /usr/X11R6/lib/X11/xdm/Xsession
   # New school -- recent X11 ports/packages installed under $LOCALBASE.
   exec /usr/local/lib/X11/xdm/Xsession
   # Linux school
   exec /etc/X11/xdm/Xsession
}

open_db()
{
   vmware_etc_dir="/etc/vmware-tools"
   vmware_db="${vmware_etc_dir}/locations"
   # Load up the install-time database
   if [ ! -r "$vmware_db" ]; then
      # XXX
      return
   fi
   db_load 'vmdb' "$vmware_db"
}

run_vmware_user()
{
   vmware_user="${vmdb_answer_BINDIR}/vmware-user"

   # BINDIR/vmware-user is really a symlink to the setuid wrapper,
   # and said wrapper will fork on its own, so there's no need to
   # background the process here.
   if [ -n "$vmware_user" -a -x "$vmware_user" ]; then
      "$vmware_user"
   fi
}

exec_xsession()
{
   local x11_base="$vmdb_answer_X11DIR"
   local xrdb="$x11_base/bin/xrdb"
   local xdmConfig="$x11_base/lib/X11/xdm/xdm-config"

   [ -r "$xdmConfig" ] || xdmConfig="/etc/X11/xdm/xdm-config"
   [ -r "$xdmConfig" ] || return

   # Determine an Xsession script to run.
   #
   # XXX Even though we require Perl to install and configure the Tools, we
   # can't be sure that it's present in the PATH defined above.  If this turns
   # out to be a problem, this script can be massaged at config time.
   Xsession=$("$xrdb" -n -DVMWARE_USER_AUTOSTART "$xdmConfig" |
              perl "${vmware_etc_dir}/xsession-xdm.pl")
   exec "$Xsession"
}


main()
{
   if open_db; then
      run_vmware_user

      if [ $# -ge 1 -a "$1" = "-gdm" ]; then
         exit;
      fi

      exec_xsession
   fi
   failsafe
}

main "$@"
