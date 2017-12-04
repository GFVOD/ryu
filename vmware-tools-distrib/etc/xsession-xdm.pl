#!/usr/bin/perl -w
#
# Copyright (c) 2007-2015 VMware, Inc.  All rights reserved.
#

use strict;

#
# xsession-xdm.pl --
#   Massage xrdb(1) output of xdm-config to help determine the location of
#   the user's Xsession script.
#
# First extract the display number from the user's DISPLAY environment
# variable.  Then examine input looking for either of the following:
#   1.  Xsession script specific to this display.
#   2.  Wildcard Xsession resource (applies to all displays).
#
# If a display-specific resource was found, print its value.  Otherwise,
# if a generic resource was found, print its value.  If neither was found,
# there is no output.
#

my $sessionSpecific;    # Path to display-specific Xsession script.
my $sessionDefault;     # Path to default Xsession script.

my $display;    # Refers to user's display number.
my $spattern;   # Pattern generated at run-time (based on $display) to match
                # a display-specific DisplayManager*session line.

# The generic/default pattern.
my $gpattern = '^[^!]*DisplayManager\.?\*\.?session';

if (defined($ENV{'DISPLAY'}) && $ENV{'DISPLAY'} =~ /:([0-9]+)/) {
   # Based on the well-formed $DISPLAY, build our display-specific session
   # pattern thingy.
   $display = $1;
   $spattern = sprintf("^[^!]*DisplayManager._%d.session", $display);

   # Okay, patterns have been built.  Let's get our search on.
   while (<STDIN>) {
      chomp($_);

      if ($_ =~ /$spattern:\s*(.*)/) {
         $sessionSpecific = $1;
      } elsif ($_ =~ /$gpattern:\s*(.*)/) {
         $sessionDefault = $1;
      }
   }

   if ($sessionSpecific) {
      print "$sessionSpecific\n";
   } elsif ($sessionDefault) {
      print "$sessionDefault\n";
   }
}
