#!/bin/sh
# Copyright (c) 1998-2015 VMware, Inc.  All rights reserved.
#
# Configures file paths in GTK+ library.
#

set -e

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

# function that does what readlink -f does, but portable:
readlinkf() {
  file=$1

  cd $(dirname $file)
  file=$(basename $file)

  # Iterate down a (possible) chain of symlinks
  while [ -L "$file" ] ; do
    file=$(readlink $file)
    cd $(dirname $file)
    file=$(basename $file)
  done

  realdir=$(pwd -P)
  echo $realdir/$file
}

vmware_db='/etc/vmware-tools/locations'
db_load 'vm_db' "$vmware_db"

confs="$vm_db_answer_LIBDIR/libconf"
pangorc="$confs/etc/pango/pangorc"
pangoModules="$confs/etc/pango/pango.modules"
pangoxAliases="$confs/etc/pango/pangox.aliases"
gdkPixbufLoaders="$confs/etc/gtk-2.0/gdk-pixbuf.loaders"
gtkIMModules="$confs/etc/gtk-2.0/gtk.immodules"
template="@@LIBCONF_DIR@@"

TDIR=/tmp
if [ -n "$TMPDIR" -a -d "$TMPDIR" ]; then
   TDIR=$TMPDIR
fi
tmp_dir=$(mktemp -d $TDIR/tmp_sed.XXXXXX)

for i in pangorc pangoModules pangoxAliases gdkPixbufLoaders gtkIMModules; do
  eval "path=\$$i"
  tmp_file="$tmp_dir/$(basename $path)"
  sed -e "s,$template,$confs,g" < "$path" > "$tmp_file"
  cp "$tmp_file" "$path"; rm "$tmp_file"
  realpath=$(readlinkf $path)
  db_remove_file "$vmware_db" "$realpath"
  db_add_file "$vmware_db" "$realpath" "$realpath"
done

rm -rf $tmp_dir
exit 0
