#!/usr/bin/perl

### BEGIN /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/coreModules/fileUtils.pm ###
#
######################################################
# Copyright (c) 2010-2015 VMware, Inc.  All rights reserved.
######################################################
#
# fileUtils.pm
#
# Handles all of the basic file utilities.
#

use strict;
no warnings 'redefine';

# Dependencies.
# Yes there is a circular dependency with logging, but
# that is ok.
loadCoreModule("logging");
loadCoreModule("osinfo");

# Globals
#
my $gTmpDir;


sub getTmpDir {
   my $tmpDir = defined($ENV{'TMPDIR'}) ? $ENV{'TMPDIR'} : '/tmp';
   if (not -d $tmpDir) {
      warning("Temp directory $tmpDir does not exist\n");
   }
   return $tmpDir;
}


sub makeTmpDir {
	use File::Temp 'tempdir';
	my $tmpDir = getTmpDir();
	my $dir = File::Temp::tempdir("$tmpDir/vmware-XXXXXX");
	debug("Created temporary directory $dir\n");
	return $dir;
}


sub internalMkdir {
   my $path = shift;
	my $mode = shift;
	my %opts = ('mode' => (defined $mode) ? $mode : 0755);
   use File::Path 'mkpath';
	debug("Created directory $path\n");
   return mkpath($path);
}


sub dirRemoveTrailingSlashes {
  my $path = shift;

  for (;;) {
    my $len;
    my $pos;

    $len = length($path);
    if ($len < 2) {
      # Could be '/' or any other character.  Ok.
      return $path;
    }

    $pos = rindex($path, '/');
    if ($pos != $len - 1) {
      # No trailing slash
      return $path;
    }

    # Remove the trailing slash
    $path = substr($path, 0, $len - 1)
  }
}


sub internalDirname {
  my $path = shift;
  my $pos;

  $path = dirRemoveTrailingSlashes($path);

  $pos = rindex($path, '/');
  if ($pos == -1) {
    # No slash
    return '.';
  }

  if ($pos == 0) {
    # The only slash is at the beginning
    return '/';
  }

  return substr($path, 0, $pos);
}


sub getPathOfRunningPerl {
   use Cwd 'abs_path';
   return abs_path($0);
}


sub getTmpFile {
   my $prefix = shift;
   my $serial = 0;
   my $fileName;

   devel ("Getting tmp file\n");

   $prefix = 'vmware-config' if not defined $prefix;

   if (not defined $gTmpDir) {
      $gTmpDir = makeTmpDir('vmware-configure');
   }

   for (;;) {
      $fileName = join('/', $gTmpDir, $prefix . $serial);
      if (not -e $fileName) {
	 utime ($fileName);
	 last;
      }
      $serial++;
   }

   debug("Got tmp file name $fileName\n");
   return $fileName;
}


sub internalMv {
   my $src = shift;
   my $dst = shift;

   devel("Moving $src to $dst\n");
   if (-e $dst) {
      devel("Destination file $dst exists. Clobbering.\n");
   }

   use File::Copy;
   move($src, $dst);
}


sub internalRm {
  my $path = shift;

  devel("Recursively removing $path.\n");
  use File::Path "rmtree";
  rmtree($path);
}


sub internalCp {
   my $src = shift;
   my $dst = shift;

   devel("Copying $src to $dst\n");
   if (-e $dst) {
      devel("Destination file $dst exists. Clobbering.\n");
   }

   use File::Copy;
   return copy($src, $dst);
}


sub internalBasename {
  return substr($_[0], rindex($_[0], '/') + 1);
}


sub safeChown {
  my $uid = shift;
  my $gid = shift;
  my $file = shift;

  if (chown($uid, $gid, $file) != 1) {
    error('Unable to change the owner of the file ' . $file . '.'
          . "\n\n");
  }
}


sub fileNameExist {
   my $fname = shift;
   return ((-e $fname) or (-l $fname));
}


sub safeChmod {
  my $mode = shift;
  my $file = shift;

  if (chmod($mode, $file) != 1) {
    error('Unable to change the access rights of the file ' . $file . '.'
          . "\n\n");
  }
}


sub restorecon {
   my $file = shift;

   if (isSElinuxEnabled()) {
     system("/sbin/restorecon " . $file);
     # Return a 1, restorecon was called.
     return 1;
   }

   # If it is not enabled, return a -1, restorecon was NOT called.
   return -1;
}


### END /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/coreModules/fileUtils.pm ###

### BEGIN /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/coreModules/logging.pm ###
#
######################################################
# Copyright (c) 2010-2015 VMware, Inc.  All rights reserved.
######################################################
#
# logging.pm
#
# Does all of our logging.  Whoo!
#
# Depends: fileUtils
#

use strict;
no warnings 'redefine';

# Dependencies.
# Yes there is a circular dependency with fileUtils, but
# that is ok.
loadCoreModule("fileUtils");

#
# Global
#
# Set default log level to Warning to reduce log spew
my $gLogLevel = 2;


sub logging_getFilePath {
   my $tmp = getTmpDir();
   my $userName = getpwuid($<);
   my $progName = internalBasename($0);

   return join('/', $tmp, "vmware-$userName", "$progName.$$");
}


#
# logging_init
#
# duh!
#
sub logging_init() {
   # Defer openning log file until we really need to write to a log file, this is to reduce the number of tmp log files created
   #logging_openLogFile();
   debug("Logging initialized successfully\n");
}


sub logging_openLogFile {
   my $logFilePath = logging_getFilePath();
   my $logDir = internalDirname($logFilePath);

   if (-d $logDir) {
      safeChown($>, $), $logDir);
      safeChmod(0755, $logDir);
   } else {
      unlink $logDir if (-e $logDir);
		internalMkdir($logDir, 0755)
# XXX: FIX ME OH GOD FIX ME!!!
#      if (internalMkdir($logDir, 0755)) {
#			error("Unable to safely create the directory $logDir\n");
#      }
   }

   # At this point we should be in a safe area.  Now unlink the file
   # if it exists and open it for logging.
   unlink $logFilePath;
   if (not open(LOGGING_FH, ">$logFilePath")) {
      warning("Failed to open log file $logFilePath\n");
   }
}


sub closeLogFile {
   debug("Closing log file.\n");
   if (defined fileno LOGGING_FH) {
      close(LOGGING_FH);
   }
}


sub parseLogLevelOptions {
   my $level = getOptionValue("loglevel");
   if ($level >= 0 and $level <= 5) {
      $gLogLevel = $level;
   } else {
      debug("Bad logging value of $level given.  Ignoring\n");
   }
}


sub addLoggingOptions {
   addOption("-l --logging", "loglevel", $gLogLevel, "str",
	     "Sets the logging verbosity. (1-5).");
}


sub logging_logMessage {
   my $level = shift;
   my $prefix = shift;
   my $message = shift;
   my $printToScreen = shift;

   if ($level gt $gLogLevel) {
      return;
   }

   # Log all messages to the screen if the Logging
   # file handle is invalid.
   # FIXME: maybe don't always want to go to STDERR.
   if ($printToScreen) {
      print STDERR "$prefix: $message";
   }

   if (not defined fileno LOGGING_FH) {
      logging_openLogFile();
   }

   if (defined fileno LOGGING_FH) {
      print LOGGING_FH "$prefix: $message";
   }
}


sub error {
   my $msg = shift;
   logging_logMessage(1, "Error", $msg, 1);
   cleanupAndExit(1);
}


sub warning {
   my $msg = shift;
   logging_logMessage(2,"Warning", $msg, 1);
}


sub info {
   my $msg = shift;
   logging_logMessage(3, "Info", $msg, 0);
}


sub debug {
   my $msg = shift;
   logging_logMessage(4, "Debug", $msg, 0);
}


sub devel {
   my $msg = shift;
   logging_logMessage(5, "Devel", $msg, 0);
}




#
# Dependencies.
#
loadCoreModule("fileUtils");

### END /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/coreModules/logging.pm ###

### BEGIN /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/coreModules/osinfo.pm ###
#
######################################################
# Copyright (c) 2010-2015 VMware, Inc.  All rights reserved.
######################################################
#
# osinfo.pm
#
# Keeps all of the OS information.
#

use strict;
no warnings 'redefine';


# Constants
#
my @cOSKeys = ("os", "dist", "verMajor", "verMinor");


# Globals
#
my %gOSInfo = ();


sub getOSInfo {
   return %gOSInfo;
}


sub getOSKeys {
   return @cOSKeys;
}


sub setOSInfo {
   my $key = shift;
   my $val = shift;

   # XXX: Check keys
   $gOSInfo{"$key"} = $val;
}


sub isRoot {
   return ($< eq 0);
}


sub rootUserCheck {
   if (!isRoot()) {
      error("You must be root in order to execute this program\n");
   }
}

sub parseOSInfoOptions {
   my $osInfo = getOptionValue("osinfo");
   if (defined $osInfo) {
      foreach my $num (0 .. ($#cOSKeys)) {
         if ( defined $osInfo->[$num] ) {  # Not all values have to be specified.
            # Set the corresponding OS Key to its value
            # XXX: Make this more strict
            debug("Setting osinfo $cOSKeys[$num] = $osInfo->[$num]\n");
            setOSInfo($cOSKeys[$num], $osInfo->[$num]);
         }
      }
   } else {
      # XXX: Load the OS detection module and run it
      error("OS Detection Module not in place.\n");
   }
}


# getRelease
#
# Returns the release information of the running kernel
# @returns - String of release information.
#
sub getRelease() {
   my $release = getOptionValue("release");
   if (defined $release and $release ne '') {
      return $release;
   } else {
      error ("Release is not defined or is empty.\n");
   }
}

# getArch
#
# Returns the architecture of the running kernel
# @returns - String of architecture type.
#
sub getArch() {
   my $arch = getOptionValue("arch");
   if (defined $arch and $arch ne '') {
      return $arch;
   } else {
      error ("Arch is not defined or is empty.\n");
   }
}

sub addOSInfoOptions {
   addOption("--root -r", "root", "/", "str", undef);
   addOption("--os", "osinfo", undef, "list", undef);

   my $arch = `uname -m`;
   chomp $arch;
   addOption("--arch", "arch", $arch, "str", "The architecture to configure");

   # We can't use runShellCmd here because it hasn't been
   # loaded yet.  Its ok though cause uname -r will work on
   # all systems that we need to configure.
   my $release = `uname -r`;
   chomp $release;
   addOption("--release --kernel -k", "release", $release,
             "str", "The kernel release to configure");
}


sub isSElinuxEnabled {
   if (-x "/usr/sbin/selinuxenabled") {
      my $rv = system("/usr/sbin/selinuxenabled");
      return ($rv eq 0);
   } else {
      return 0;
   }
}


### END /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/coreModules/osinfo.pm ###

### BEGIN /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/coreModules/options.pm ###
#
######################################################
# Copyright (c) 2010-2015 VMware, Inc.  All rights reserved.
######################################################
#
# options.pm
#
# Parses, maintains and stores command line options
# and their values
#
# Depends: logging.pm
#

use strict;

#
# Constants
#
my %cTypes = ("bool"   => 1,
	      "str" => 1,
	      "list"   => 1);

#
# Globals
#
my %gOptionVals = ();
my %gOptionFlags = ();
my %gOptionTypes = ();
my %gOptionDesc = ();

sub addOption {
   my $optFlags = shift;
   my $optKey = shift;
   my $optValue = shift;
   my $optType = shift;
   my $optDesc = shift;

   my $logMsg = "Adding option(s) \"$optFlags\" to optKey $optKey";
   if (defined $optValue) {
      $logMsg .= " with default value \"$optValue\"\n";
   } else {
      $logMsg .= " with undefined default value\n";
   }
   debug($logMsg);

   chomp($optFlags);
   foreach my $optFlag (split(/[ ]+/, $optFlags)) {
      devel("Associating optFlag $optFlag with optKey $optKey.\n");
      $gOptionFlags{"$optFlag"} = $optKey;
   }

   # Check the arguments we add to ensure they are valid.
   if (not defined $cTypes{"$optType"}) {
      error("$optKey is of unknown argument type $optType\n");
   }
   $gOptionTypes{"$optKey"} = $optType;
   $gOptionVals{"$optKey"} = $optValue;

   # Descriptions are optional.  If we have one, we will use it in the
   # printUsage function
   if (defined $optDesc) {
      $gOptionDesc{"$optKey"} = $optDesc;
   }
}

sub getOptionValue {
   my $key = shift;
   return $gOptionVals{"$key"};
}

sub printOptionUsage {
   my $flag;
   my $flagKey;

   foreach my $key (keys %gOptionVals) {
      # First find all flags for this key
      my @flags = ();
      while (($flag, $flagKey) = each %gOptionFlags) {
	 push (@flags,$flag) if ($flagKey eq $key);
      }

      # Now print the flags and then print the description
      # FIXME: finish usage.
   }
   error("NOT IMPLEMENTED!\n\n");
}

sub parseOptionArgs {
   my @args = @ARGV;
   my $arg;
   my $argVal;

   debug("Parsing arguments.\n");

   while ($#args != -1) {
      $arg = shift(@args);

      # FIXME or REMOVE ME!
      if ( $arg =~ /[^A-Za-z_0-9-=\/,]/ ) {
        debug("Bad argument text detected!\n");
      }

      # Handle cases where args have = signs
      if ($arg =~ m/(--?\w+)=(\S+)/) {
	 $arg = $1;
	 $argVal = $2;
      } else {
	 undef $argVal;
      }

      if (defined $gOptionFlags{"$arg"}) {
	 my $key = $gOptionFlags{"$arg"};
	 my $type = $gOptionTypes{"$key"};

	 # Detect type and then handle accordingly.
	 if ($type eq "bool") {
	    $gOptionVals{"$key"} = 1;
	    debug("Found arg \"$arg\" and set the flag\n");
	 } elsif ($type eq "str") {
	    if (defined $argVal) {
	       $gOptionVals{"$key"} = $argVal;
	    } else {
	       $gOptionVals{"$key"} = shift(@args);
	    }
	    debug("Found arg \"$arg\" and set string value to " .
		  "$gOptionVals{$key}\n");
	 } elsif ($type eq "list") {
	    # FIXME: Assuming a comma separated list
	    my $delim = ',';
	    my @list;
	    if (defined $argVal) {
	       @list = split($delim, $argVal);
	    } else {
	       @list = split($delim, shift(@args));
	    }
	    $gOptionVals{"$key"} = [ @list ];
	    debug("Found arg \"$arg\" and set list value to " .
		  join(',', @{$gOptionVals{"$key"}}) . "\n");
	 } else {
	    debug("Unknown type for argument $arg.  Skipping.\n");
	 }
      } else {
	 debug("Unknown option $arg.  Skipping.\n");
      }
   }
}

### END /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/coreModules/options.pm ###

### BEGIN /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/coreModules/db.pm ###
#
######################################################
# Copyright (c) 2010-2015 VMware, Inc.  All rights reserved.
######################################################
#
# db.pm
#
# Handles all of the database stuff.
#

use strict;
no warnings 'redefine';

# Depends
#
loadCoreModule("fileUtils");


# Constants
#
my $cFlagTimestamp = 0x1;
my $cFlagConfig = 0x2;


# Globals
#
my $gDBFile;
my %gDBAnswer = ();
my %gDBFile = ();
my %gDBFileTags = ();
my %gDBDir = ();
my %gDBDirTags = ();
my $gDBIsLoaded = 0;


sub addDBOptions {
   addOption("--dbPath", "dbPath", "/etc/vmware-tools/locations",
	     "str", undef);
}


sub parseDBOptions {
   # XXX: File sanity checking?
   dbSetFilePath(getOptionValue("dbPath"));
}


sub dbGetFilePath {
   return $gDBFile;
}


sub dbSetFilePath {
   if ($gDBIsLoaded == 1) {
      error("You are attempting to change the path of the " .
            "database when it is already open for write.\n");
   }
   $gDBFile = shift;
}


sub dbLoad {
   debug("Attempting to open database file $gDBFile.\n");
   if ($gDBIsLoaded) {
      debug("Database is already loaded.  Skipping.");
      return 1;
   }

   if (not -e $gDBFile) {
      # Database file does not exist.  Set loaded global to
      # keep the path from changing.
      info("DB does not yet exist.  Nothing to load\n");
      $gDBIsLoaded = 1;
      return 1;
   }

   %gDBAnswer = ();
   %gDBFile = ();
   %gDBDir = ();
   %gDBFileTags = ();
   %gDBDirTags = ();

   if (not open(INSTALLDB, '<' . $gDBFile)) {
      error("Unable to open database file $gDBFile.\n");
   }

   while (<INSTALLDB>) {
      chomp;
      if (/^answer (\S+) (.+)$/) {
         $gDBAnswer{$1} = $2;
      } elsif (/^answer (\S+)/) {
         $gDBAnswer{$1} = '';
      } elsif (/^remove_answer (\S+)/) {
         delete $gDBAnswer{$1};
      } elsif (/^file (.+) (\d+) (.+)$/) {
         my @tags = split(/,/, $3);
         db_AddEntriesToTagsHash(\%gDBFileTags, \@tags, $1);
         $gDBFile{$1} = $2;
      } elsif (/^remove_file (.+)$/) {
         db_RmEntryFromTagsHash(\%gDBFileTags, $1);
         delete $gDBFile{$1};
      } elsif (/^directory (.+) (.+)$/) {
         my @tags = split(/,/, $2);
         db_AddEntriesToTagsHash(\%gDBDirTags, \@tags, $1);
         $gDBDir{$1} = '';
      } elsif (/^remove_directory (.+)$/) {
         db_RmEntryFromTagsHash(\%gDBDirTags, $1);
         delete $gDBDir{$1};
      }
   }

   debug("Database loaded.\n");
   close(INSTALLDB);
   $gDBIsLoaded = 1;
   return 1;
}


sub dbAppend {
   my $dbDirName = internalDirname($gDBFile);
   if (not -d $dbDirName) {
      info("Creating $dbDirName\n");
      internalMkdir($dbDirName);
   }

   if (not open(INSTALLDB, '>>' . $gDBFile)) {
      error("Unable to open the installer database $gDBFile"
	    . ' in append-mode.' . "\n\n");
   }
   # Force a flush after every write operation.
   # See 'Programming Perl' 3rd edition, p. 781 (p. 110 in an older edition)
   select((select(INSTALLDB), $| = 1)[0]);
}


sub db_RmEntryFromTagsHash {
   my $hashRef = shift;
   my $entry = shift;

   foreach my $tag (keys %$hashRef) {
      @{$$hashRef{$tag}} = grep { $_ ne $entry } @{$$hashRef{$tag}};
   }
}


sub db_AddEntriesToTagsHash {
   my $hashRef = shift;
   my $listRef = shift;
   my $entry = shift;

   foreach my $tag (@$listRef) {
      push @{$$hashRef{$tag}}, $entry;
   }
}


sub dbRemoveFile {
   my $file = shift;

   # XXX: DB opened check.

   # Find the tags associated with the file and remove them.
   db_RmEntryFromTagsHash(\%gDBFileTags, $file);

   print INSTALLDB 'remove_file ' . $file . "\n";
   delete $gDBFile{$file};
}


sub dbAddFile {
   my $file = shift;
   my @tags = @_;
   # XXX: Check if DB is opened and has been read in.

   if (not @tags) {
      push @tags, "default";
   }

   my @statbuf = stat($file);
   if (not (defined($statbuf[9]))) {
      error('Unable to get the last modification timestamp of the ' .
            "destination file $file.\n\n");
   }

   db_AddEntriesToTagsHash(\%gDBFileTags, \@tags, $file);

   $gDBFile{$file} = $statbuf[9];
   my $entry = join(' ', 'file', $file, $statbuf[9], join(',', @tags));
   print INSTALLDB "$entry\n";
}


sub dbRemoveDir {
   my $dir = shift;

   # Find the tags associated with the directory and remove them.
   db_RmEntryFromTagsHash(\%gDBDirTags, $dir);

   print INSTALLDB 'remove_directory ' . $dir . "\n";
   delete $gDBDir{$dir};
}


sub dbAddDir {
   my $dir = shift;
   my @tags = @_;

   if (not @tags) {
      push @tags, "default";
   }

   db_AddEntriesToTagsHash(\%gDBDirTags, \@tags, $dir);

   $gDBDir{$dir} = '';
   print INSTALLDB 'directory ' . $dir . ' ' . "\n";
}


sub dbRemoveAnswer {
   my $id = shift;

   if (defined($gDBAnswer{$id})) {
      print INSTALLDB 'remove_answer ' . $id . "\n";
      delete $gDBAnswer{$id};
   }
}


sub dbAddAnswer {
   my $id = shift;
   my $value = shift;

   if ($id =~ m/\s/) {
      error ("Whitespace not allowed to be used in DB keys!\n");
   }

   $gDBAnswer{$id} = $value;
   print INSTALLDB 'answer ' . $id . ' ' . $value . "\n";
}


sub dbGetAnswerIfExists {
   my $id = shift;
   if (not defined($gDBAnswer{$id})) {
      return;
   }
   return $gDBAnswer{$id};
}


sub dbGetAnswer {
   my $id = shift;
   my $answer = dbGetAnswerIfExists($id);

   if ($id =~ m/\s/) {
      error ("Whitespace is not allowed to be used in DB keys!\n");
   }

   if (not defined $answer) {
      error("Unable to find the answer $id in the installer database.  " .
            "You may want to re-install VMWare Tools.\n\n");
   }

   return $answer;
}


sub dbGetFilesWithTag {
   my $tag = shift;
   if (defined $gDBFileTags{$tag}) {
      return @{$gDBFileTags{$tag}};
   }
   return;
}


sub dbGetDirsWithTag {
   my $tag = shift;
   if (defined $gDBDirTags{$tag}) {
      return @{$gDBDirTags{$tag}};
   }
   return;
}


sub db_getTagsHash {
   my $hashRefIn = shift;
   my $hashRefOut = shift;

   while( my ($key, $vals) = each (%$hashRefIn)) {
      foreach my $val (@{$vals}) {
         push @{$$hashRefOut{$val}}, $key;
      }
   }
}


sub dbSave {
   debug("Closing database.\n");
   close(INSTALLDB);

   if (not $gDBIsLoaded) {
      warning("Tried to Save DB without opening it first\n");
      return;
   }

   my %fileTagsHash = ();
   my %dirTagsHash = ();
   db_getTagsHash(\%gDBFileTags, \%fileTagsHash);
   db_getTagsHash(\%gDBDirTags, \%dirTagsHash);

   my $newDBFile = getTmpFile('locations');
   open(DB, ">$newDBFile") or error("Failed to open $newDBFile\n");
   while( my ($key, $val) = each (%gDBFile)) {
      $val = '' if not defined $val;
      my $tagList = join(',', @{$fileTagsHash{$key}});
      print DB "file $key $val $tagList\n";
   }
   while( my ($key, $val) = each (%gDBDir)) {
      $val = '' if not defined $val;
      my $tagList = join(',', @{$dirTagsHash{$key}});
      print DB "directory $key $val $tagList\n";
   }
   while( my ($key, $val) = each (%gDBAnswer)) {
      $val = '' if not defined $val;
      print DB "answer $key $val\n";
   }
   close(DB);
   internalMv($newDBFile, $gDBFile);
   $gDBIsLoaded = 0;
}


### END /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/coreModules/db.pm ###

### BEGIN /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/coreFunctions//functions.pm ###
#
######################################################
# Copyright (c) 2010-2015 VMware, Inc.  All rights reserved.
######################################################
#
# functions.pm
#
# A module housing various functions commonly used in
# other modules.
#

use strict;
no warnings 'redefine';

sub cleanupAndExit {
   my $status = shift;

   # Ensure you send the terminating RPC message before you
   # unmount the CD.
   #my $rpcresult = sendRpc('toolinstall.is_image_inserted');
   #chomp($rpcresult);

   #sendTermRpcMsgs($status);

   # XXX: Uncomment me later.
   # Now unmount the CD.
   #if ("$rpcresult" =~ /1/) {
   #   ejectToolsInstallCD();
   #}

   dbSave();
   closeLogFile();
   exit $status;
}


sub sendTermRpcMsgs {
   my $status = shift;
   my $signal = ($status eq 0) ? '1' : '0';

   sendRpc("toolinstall.installerActive 0");
   sendRpc('toolinstall.end $signal');
}


sub sendRpc {
   my $command = shift;
   my $rpcToolName = 'vmware-rpctool';
   my $rpcToolPath;
   my @rpcResultLines;

   # We don't yet know if vmware-rpctool was copied into place.
   # Let's first try getting the location from the DB.
   $rpcToolPath = join('/', getVmwareSbinPath(), $rpcToolName);
   debug("$rpcToolName is supposedly at $rpcToolPath\n");

   if (not (-x "$rpcToolPath")) {
      # The DB didn't help.  But no matter, we can
      # extract a path to the untarred tarball installer from our
      # current location.  With that info, we can invoke the
      # rpc tool directly out of the staging area.  Woot!
      $rpcToolPath = join('/', "./lib", $rpcToolName);
      debug("The first path was no good.  Trying $rpcToolPath.\n");
   }

   # If we found the binary, send the RPC.
   if (-x "$rpcToolPath") {
      open (RPCRESULT, shell_string($rpcToolPath) . " " .
	    shell_string($command) . ' 2> /dev/null |');

      @rpcResultLines = <RPCRESULT>;
      close RPCRESULT;
      info("Sent RPC message $command.\n");
      return (join("\n", @rpcResultLines));
   } else {
      # Return something so we don't get any undef errors.
      debug("Could not find the $rpcToolName binary.\n");
      return '';
   }
}


sub runShellCmd {
   my $cmd = shift;
   my %results = ('exitStatus' => -1,
		  'exitMsg'    => '',
		  'output'     => '',);

   # XXX: make this more robust.
   debug("Attempting to run $cmd.\n");
   my @cmdOutput = `$cmd`;
   chomp @cmdOutput;

   $results{'output'} = [ @cmdOutput ];
   $results{'exitStatus'} = $?;
   $results{'exitMsg'} = $!;

   return %results;
}


sub internalWhich {
   my $bin = shift;

   debug("Attempting to locat $bin.\n");
   if (substr($bin, 0, 1) eq '/') {
      # Absolute name
      if ((-f $bin) && (-x $bin)) {
	 return $bin;
      }
   } else {
      # Relative name
      my @paths;
      my $path;

      if (index($bin, '/') == -1) {
	 # There is no other '/' in the name
	 @paths = split(':', $ENV{'PATH'});
	 foreach $path (@paths) {
	    my $fullbin = $path . '/' . $bin;
	    if ((-f $fullbin) && (-x $fullbin)) {
               return $fullbin;
	    }
	 }
      }
   }
   return '';
}


sub ejectToolsInstallCD {
   my @candidate_mounts = getCdMounts();
   my $device;
   my $mountpoint;
   my $fstype;
   my $rest;
   my $eject_cmd = internalWhich('eject');
   my $eject_failed = 0;
   my $eject_really_failed = 0;

   # For each mounted cdrom, check if it's vmware guest tools installer,
   # and if so, try to eject it, then verify.
   foreach my $candidate_mount (@candidate_mounts) {
      ($device, $mountpoint) = split('::::',$candidate_mount);
      if (checkMountForTools($mountpoint)) {
         debug("Found VMware Tools CDROM mounted at " .
	       "$mountpoint. Ejecting device $device ...\n");

         # Freebsd doesn't auto unmount along with eject.  So instead lets
	 # just unmount the mountpoint before we eject the device.
         unmountDevice($mountpoint);

	 my @output;
	 if ($eject_cmd ne '') {
	    my %shellRes = runShellCmd("$eject_cmd $device 2>&1");
	    @output = @{$shellRes{'output'}};
	    $eject_failed = $shellRes{'exitStatus'};
	 } else {
	    $eject_failed = 1;
	 }

         # For unknown reasons, eject can succeed, but return error, so
         # double check that it really failed before showing the output to
         # the user.  For more details see bug170327.
	 # XXX: Finish the rest of this function.!!!
         if ($eject_failed && checkMountForTools($mountpoint)) {
            foreach my $outputline (@output) {
               debug($outputline, 0);
            }

            # $eject_really_failed ensures this message is not printed
            # multiple times.
            if (not $eject_really_failed) {
	       if ($eject_cmd eq '') {
		  debug ("No eject (or equivilant) command could be " .
			 "located.\n");
	       }
	       warning ("Eject Failed:  If possible manually eject the " .
			"Tools installer from the guest cdrom mounted " .
			"at $mountpoint before canceling tools install " .
			"on the host.\n", 0);
	       $eject_really_failed = 1;
            }
         }
      }
   }
}


### END /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/coreFunctions//functions.pm ###

### BEGIN /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/coreFunctions//linux/functions.pm ###
#
######################################################
# Copyright (c) 2010-2015 VMware, Inc.  All rights reserved.
######################################################
#
# functions.pm
#
# Functions that are common to Linux
#

use strict;
no warnings 'redefine';

sub getVmwareSbinPath {
   my $vmwareLibDir = db_get_answer_if_exists('LIBDIR');
   my $sbinSuffix = is64BitUserLand() ? 'sbin64' : 'sbin32';
   my $path = join('/', $vmwareLibDir, $sbinSuffix);
   devel("Vmware sbin dir is $path.\n");
   return $path;
}


sub getCdMounts {
   my @candidateMounts = ();
   my $device;
   my $mountpoint;
   my $fstype;
   my $rest;

   if (open(MOUNTS, '</proc/mounts')) {
      while (<MOUNTS>) {
	 ($device, $mountpoint, $fstype, $rest) = split;
	 # note: /proc/mounts replaces spaces with \040
	 $device =~ s/\\040/\ /g;
	 $mountpoint =~ s/\\040/\ /g;
	 if ($fstype eq "iso9660" && $device !~ /loop/ ) {
	    push(@candidateMounts, "${device}::::${mountpoint}");
	 }
      }
      close(MOUNTS);
   }
   return @candidateMounts;
}


sub checkMountForTools {
   my $mountPoint = shift;
   my $foundIt = 0;

   if (opendir(DIR, $mountPoint)) {
      my @dirContents = readdir(DIR);
      foreach my $entry (@dirContents) {
	 if ($entry =~ /VMwareTools-.*\.tar\.gz$/) {
	    $foundIt = 1;
	    last;
	 }
      }
      closedir(DIR);
   }
   return $foundIt;
}


sub unmountDevice {
   my $path = shift;
   my $umountBin = internalWhich('umount');

   info("Unmounting $path.\n");
   my %cmdStatus = runShellCmd("$umountBin \"$path\" 2>&1");
   return $cmdStatus{'exitStatus'};
}


### END /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/coreFunctions//linux/functions.pm ###

### BEGIN /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/configModules/thinprint//functions.pm ###
#
######################################################
# Copyright (c) 2010-2015 VMware, Inc.  All rights reserved.
######################################################
#
# functions.pm
#
# A module that houses various functions used in
# other modules.
#

use strict;
no warnings 'redefine';

loadConfigFunction("editingUtils");

sub thinprintSetPermissions {
   my $file = shift;
   # add SETUID for file
   safeChmod(04755, $file);
}

sub thinprintSetSELinux {
   # No action is necessary.
   return 0;
}

sub configureThinPrint {
   my $lpadmin;
   my $cupsenable;
   my $cupsaccept;
   my $printerName = 'VMware_Virtual_Printer';
   my $printerURI = 'tpvmlp://VMware';
   my $cupsLibDir = (getArch() =~ /(x86_64|amd64)/ ? 'lib64' : 'lib');
   my $cupsDir = join('/', '/usr', $cupsLibDir, 'cups/backend');
   my $cupsConfDir = '/etc/cups';
   my $cupsPrinters = "$cupsConfDir/printers.conf";
   my $cupsConf = "$cupsConfDir/cupsd.conf";
   my @backends =  ("$cupsDir/tpvmlp", "$cupsDir/tpvmgp");
   my $addDummyPrinter = 'false';
   my $configText = <<EOF;
<Printer ${printerName}>
Info ${printerName}
DeviceURI ${printerURI}
State Idle
Accepting Yes
</Printer>
EOF

   # To continue, CUPS must be where we expect it on the guest.
   if (!fileNameExist($cupsDir) || !fileNameExist($cupsConf)) {
      return 0;
   }

   if (!fileNameExist($cupsPrinters)) {
      # XXX: Migrate these to core functions at a later date.
      system("touch $cupsPrinters");
      system("chmod --reference=$cupsConf $cupsPrinters");
      system("chown --reference=$cupsConf $cupsPrinters");
   }

   if (!fileNameExist($cupsPrinters)) {
      warning("Failed to create $cupsPrinters\n");
      return 0;
   }

   foreach(@backends) {
      system("chgrp --reference=/dev/ttyS0 $_"); # match serial port
      thinprintSetPermissions($_);
      restorecon($_);
   }

   # No-op here, but defined for RHEL systems.
   thinprintSetSELinux();

   if ($addDummyPrinter eq 'true') {
      blockRemove($cupsPrinters);
      blockAppend($cupsPrinters, $configText);
   }
}


### END /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/configModules/thinprint//functions.pm ###

### BEGIN /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/configFunctions/editingUtils//functions.pm ###
#
######################################################
# Copyright (c) 2010-2015 VMware, Inc.  All rights reserved.
######################################################
#
# functions.pm
#
# A module that houses various functions used in
# other modules.
#

use strict;
no warnings 'redefine';

# Constants
#
my $cBlockBegin = "# Beginning of the block added by the VMware software";
my $cBlockEnd = "# End of the block added by the VMware software";


sub blockAppend {
   my $file = shift;
   my $text = shift;
   my $begin = $cBlockBegin;
   my $end = $cBlockEnd;

   if (not open(BLOCK, '>>' . $file)) {
      return -1;
   }

   print BLOCK join("\n", $begin, $text, $end, '');

   if (not close(BLOCK)) {
     return 0;
   }

   return 1;
}


sub blockGetContents {
   my $file = shift;
   my @blockContents;
   my $begin = $cBlockBegin;
   my $end = $cBlockEnd;

   devel("Getting block contents from $file\n");

   if (not open(FH, $file)){
      debug("Unable to open $file\n.");
      return @blockContents;
   }

   my $inBlock = 0;
   for my $line (<FH>) {
      chomp $line;
      if ($line eq $begin) {
	 devel("Found beginning of block section\n");
	 $inBlock = 1;
      } elsif ($inBlock and $line eq $end) {
	 devel("Found end of block section\n");
	 last;
      } elsif ($inBlock and $line ne '') {
	 push @blockContents, $line;
	 devel("block contents += $line\n");
      }
   }

   close(FH);
   return @blockContents
}


sub blockGetContentsStr {
   my $path = shift;
   my @results = blockGetContents($path);
   if (@results) {
      return join("\n", @results);
   } else {
      return '';
   }
}


sub blockInsert {
   my $file = shift;
   my $block = shift;
   my $regexp = shift;
   my $lineAdded = 0;
   my $tmpDir = makeTmpDir('vmware-block-insert');
   my $tmpFile = $tmpDir . '/tmpFile';
   my $begin = $cBlockBegin;
   my $end = $cBlockEnd;

   debug("Inserting block text $block into $file\n");

   if (not open(BLOCK_IN, "<$file") or
       not open(BLOCK_OUT, ">$tmpFile")) {
      return 0;
   }

   foreach my $line (<BLOCK_IN>) {
      print BLOCK_OUT $line;
      if ($line =~ /($regexp)/ and not $lineAdded) {
	 print BLOCK_OUT join("\n", $begin, $block, $end, '');
	 $lineAdded = 1;
      }
   }

   if (not close(BLOCK_IN) or not close(BLOCK_OUT)) {
      return 0;
   }

   if (not internalMv($tmpFile, $file)) {
      return 0;
   }

   internalRm($tmpDir);

   # Our return status is 1 if successful, 0 if nothing was added.
   return $lineAdded;
}


sub blockRemove {
   my $file = shift;
   my $blocksRemoved = 0;
   my $inBlock = 0;
   my $tmpDir = makeTmpDir('vmware-block-remove');
   my $tmpFile = $tmpDir . '/tmpFile';
   my $begin = $cBlockBegin;
   my $end = $cBlockEnd;

   debug("Removing block text from $file\n");

   if (not open(BLOCK_IN, "<$file") or
       not open(BLOCK_OUT, ">$tmpFile")) {
      debug("Unable to open either $file or $tmpFile.\n");
      return 0;
   }

   chomp $begin;
   chomp $end;
   foreach my $line (<BLOCK_IN>) {
      chomp $line;
      if ($line eq $begin) {
        $inBlock = 1;
      } elsif ($inBlock and ($line eq $end)) {
        $inBlock = 0;
        $blocksRemoved++;
      } elsif (not $inBlock) {
        print BLOCK_OUT "$line\n";
      }
   }

   if (not close(BLOCK_IN) or not close(BLOCK_OUT)) {
      debug("Failed to close eithr $file or $tmpFile.\n");
      return 0;
   }

   my %shellResult = runShellCmd("mv $tmpFile $file");
   if ($shellResult{'exitStatus'} ne 0) {
      warning("mv command in blockRemove failed");
      return 0;
   }

   internalRm($tmpDir);

   # Our return status is 1 if successful, 0 if nothing was added.
   return $blocksRemoved;
}


sub removeDuplicateEntries {
   my $string = shift;
   my $delim = shift;
   my $newStr = '';

   if (not defined $string or not defined $delim) {
      error("Missing parameters in removeDuplicateEntries\n.");
   }

   debug("Removing duplicate entries from $string using delim $delim.\n");
   foreach my $subStr (split($delim, $string)) {
      if ($newStr !~ /(^|$delim)$subStr($delim|$)/ and $subStr ne '') {
	 if ($newStr ne '') {
	    $newStr = join($delim, $newStr, $subStr);
	 } else {
	    $newStr = $subStr;
	 }
      }
   }
   devel("New string is $newStr.\n");
   return $newStr;
}


# addTextToKVEntryInFile
#
# Despite the long and confusing function name, this function is very
# useful.  If you have a key value entry in a file, this function will
# all you to add an entry to it based on a special regular expression.
# This regular expression must capture the pre-text, the values, and any
# post text by using regex back references.
# @param - Path to file
# @param - The regular expression.  See example below...
# @param - The delimeter between values
# @param - The new entry
# @returns - True if the file was modified.
#
# For example, if I have
#   foo = 'bar,baz';
# I can add 'biz' to the values by calling this function with the proper
# regex.  A regex for this would look like '^(foo = ')(\.*)(;)$'.  The
# delimeter is ',' and the entry would be 'biz'.  The result should look
# like
#   foo = 'bar,baz,biz';
#

sub addTextToKVEntryInFile {
   my $file = shift;
   my $regex = shift;
   my $delim = shift;
   my $entry = shift;
   my $modified = 0;
   my $firstPart;
   my $origValues;
   my $newValues;
   my $lastPart;

   devel("Regex passed to addTextToKVEntryInFile is $regex\n");
   $regex = qr/$regex/;

   if (not open(INFILE, "<$file")) {
      warning("File $file not found\n");
      return 0;
   }

   my $tmpDir = makeTmpDir('vmware-file-mod');
   my $tmpFile = join('/', $tmpDir, 'new-file');
   if (not open(OUTFILE, ">$tmpFile")) {
      warning("Failed to open output file\n");
      return 0;
   }

   foreach my $line (<INFILE>) {
      if ($line =~ $regex and not $modified) {
         # We have a match.  $1 and $2 have to be deifined; $3 is optional
         if (not defined $1 or not defined $2) {
            debug ("Bad regex match in addTextToKBEntryInFile\n");
            return 0;
         }
         $firstPart = $1;
         $origValues = $2;
         $lastPart = ((defined $3) ? $3 : '');
         chomp $firstPart;
         chomp $origValues;
         chomp $lastPart;

         # Modify the origValues and remove duplicates
         # Handle white space as well.
         if ($origValues =~ /^\s*$/) {
            $newValues = $entry;
         } else {
            $newValues = join($delim, $origValues, $entry);
            $newValues = removeDuplicateEntries($newValues, $delim);
         }
         print OUTFILE join('', $firstPart, $newValues, $lastPart, "\n");

         # FIXME - add DB junk so we can auto-magically undo this stuff.

         $modified = 1;
      } else {
         print OUTFILE $line;
      }
   }

   close(INFILE);
   close(OUTFILE);

   if (not internalMv($tmpFile, $file)) {
      return 0;
   }

   # Our return status is 1 if successful, 0 if nothing was added.
   return $modified;
}


sub removeTextInKVEntryInFile {
   my $file = shift;
   my $regex = shift;
   my $delim = shift;
   my $entry = shift;
   my $modified = 0;
   my $firstPart;
   my $origValues;
   my $newValues = '';
   my $lastPart;

   devel("Regex passed to addTextToKVEntryInFile is $regex\n");
   $regex = qr/$regex/;

   if (not open(INFILE, "<$file")) {
      warning("File $file not found\n");
      return 0;
   }

   my $tmpFile = getTmpFile('remove-kv-file');
   if (not open(OUTFILE, ">$tmpFile")) {
      warning("Failed to open output file $tmpFile\n");
      return 0;
   }

   foreach my $line (<INFILE>) {
      if ($line =~ $regex and not $modified) {
         # We have a match.  $1 and $2 have to be defined; $3 is optional
         if (not defined $1 or not defined $2) {
            debug ("Bad regex match in addTextToKBEntryInFile\n");
            return 0;
         }
         $firstPart = $1;
         $origValues = $2;
         $lastPart = ((defined $3) ? $3 : '');
         chomp $firstPart;
         chomp $origValues;
         chomp $lastPart;

         # Modify the origValues and remove duplicates
         # If $origValues is just whitespace, no need to modify $newValues.
         if ($origValues !~ /^\s*$/) {
            foreach my $existingEntry (split($delim, $origValues)) {
               if ($existingEntry ne $entry) {
                  $newValues = join($delim, $newValues, $existingEntry);
               }
            }
         }
         print OUTFILE join('', $firstPart, $newValues, $lastPart, "\n");

         # FIXME - add DB junk so we can auto-magically undo this stuff.

         $modified = 1;
      } else {
         print OUTFILE $line;
      }
   }

   close(INFILE);
   close(OUTFILE);

   if (not internalMv($tmpFile, $file)) {
      return 0;
   }

   # Our return status is 1 if successful, 0 if nothing was added.
   return $modified;
}


### END /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/configFunctions/editingUtils//functions.pm ###

### BEGIN /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/configModules/thinprint//linux/onetime_config.pm ###
#
######################################################
# Copyright (c) 2010-2015 VMware, Inc.  All rights reserved.
######################################################
#
# onetime_config.pm
#
# The main logic for configuring thinprint
#

use strict;
no warnings 'redefine';


sub thinprint_onetime_config_main {
   # Set up ThinPrint
   configureThinPrint();
   return 0;
}


### END /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/configModules/thinprint//linux/onetime_config.pm ###

### BEGIN /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/configModules/thinprint//linux/deconfig.pm ###
#
######################################################
# Copyright (c) 2010-2015 VMware, Inc.  All rights reserved.
######################################################
#
# deconfig.pm
#
# The main logic for deconfiguring thinprint
#

use strict;
no warnings 'redefine';


sub thinprint_deconfig_main {
   return 0;
}


# Always return 1 at the end of a perl module
#
1;

### END /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/configModules/thinprint//linux/deconfig.pm ###

### BEGIN /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/runtimeModules//vmware-db.pm ###
#
######################################################
# Copyright (c) 2010-2015 VMware, Inc.  All rights reserved.
######################################################
#
# vmware-db.pm
#
# Database access for various portions of the Tools
# installer and programs.
#

use strict;
no warnings 'redefine';


sub runtime_main {
   info("Entering vmware-db runtime module.\n");

   addOption("--dbAddFile", "DBAddFile", undef, "list",
	     "A filepath,tag pair to enter into the database");
   addOption("--dbAddDir", "DBAddDir", undef, "list",
	     "A dirpath,tag pair to enter into the database");
   addOption("--dbAddAnswer", "DBAddAnswer", undef, "list",
	     "A key,value pair to enter into the database");
   addOption("--dbAppendAnswer", "DBAppendAnswer", undef, "list",
	     "A key,value pair to append to an entry in the database");
   addOption("--dbGetAnswer", "DBGetAnswer", undef, "str",
	     "A key whose associated value to retrieve");
   addOption("--dbDelAnswer", "DBDelAnswer", undef, "str",
	     "A key to remove from the database");
   addOption("--dbDelFilesWithTag", "DBDelFilesTag", undef, "str",
	     "Deletes files assoicated with the given tag.");

   parseOptionArgs();

   my $keyVal = undef;

   $keyVal = getOptionValue("DBAddFile");
   if (defined $keyVal) {
      my $path = shift @$keyVal;
      my @tag = @{$keyVal};
      dbAddFile($path, @tag);
   }

   $keyVal = getOptionValue("DBAddDir");
   if (defined $keyVal) {
      my $path = shift @$keyVal;
      my @tag = @{$keyVal};
      dbAddDir($path, @tag);
   }

   $keyVal = getOptionValue("DBAddAnswer");
   if (defined $keyVal) {
      my ($key, $val) = @{$keyVal};
      dbAddAnswer($key, $val);
   }

   $keyVal = getOptionValue("DBAppendAnswer");
   if (defined $keyVal) {
      my ($key, $val, $dlim) = @{$keyVal};
      my $currVal = dbGetAnswerIfExists($key);
      if (defined $currVal) {
         $currVal = join($dlim, $currVal, $val);
      } else {
         $currVal = $val;
      }
      dbAddAnswer($key, $currVal);
   }

   $keyVal = getOptionValue("DBGetAnswer");
   if (defined $keyVal) {
      my $answer = dbGetAnswerIfExists($keyVal);
      if (defined $answer) {
        print $answer;
      }
   }

   $keyVal = getOptionValue("DBDelAnswer");
   if (defined $keyVal) {
      dbRemoveAnswer($keyVal);
   }

   $keyVal = getOptionValue("DBDelFilesTag");
   if (defined $keyVal) {
      info("Removing all files associated with $keyVal tag.\n");
      foreach my $file (dbGetFilesWithTag($keyVal)) {
         internalRm($file);
         dbRemoveFile($file);
      }
   }

   info ("Successfully completed the config runtime.\n");
   return 0;
}


### END /build/mts/release/bora-2496486/bora-vmsoft/install/Linux/configurator/runtimeModules//vmware-db.pm ###

   # Stub out loadModule, loadConfigModule, and loadConfigFunction
   sub loadModule {return 1;}
   sub loadCoreModule {return 1;}
   sub loadConfigFunction {return 1;}

   # Initialize logging
   logging_init();

   # Add the options necessary for our configurator.
   addOSInfoOptions();
   addLoggingOptions();
   addDBOptions();

   # Parsing
   parseOptionArgs();
   parseDBOptions();
   parseLogLevelOptions();

   dbLoad();
   dbAppend();
# Call our code
runtime_main()
