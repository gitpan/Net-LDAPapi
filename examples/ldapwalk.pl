#!/usr/bin/perl
#
#
#  ldapwalk.pl - Walks through Records Matching a Given Filter
#  Author:  Clayton Donley, Motorola, <donley@cig.mot.com>
#
#  Demonstration of Synchronous Searching in PERL5.
#
#  Rather than printing attribute and values directly, they are
#  stored in a Hash, where further manipulation would be very simple.
#  The output could then be printed to a file or standard output, or
#  simply run through the modify or add commands.
#
#  Usage:  ldapwalk.pl FILTER
#  Example:  ldapwalk.pl "sn=Donley"
#

use strict;
use Net::LDAPapi;

#  Define these values

my $ldap_server = "localhost";
my $BASEDN = "o=Org, c=US";
my $sizelimit = 100;            # Set to Maximum Number of Entries to Return
                                # Can set small to test error routines

#  Various Variable Declarations...
my $ld;
my $dn;
my $attr;
my $ent;
my $ber;
my @vals;
my %record;
my $rc;
my $result;

#
#  Initialize Connection to LDAP Server

if (($ld = new Net::LDAPapi($ldap_server)) == -1)
{
   die "Connection Failed!";
}

#
#  Bind as NULL User to LDAP connection $ld

if ($ld->bind_s != LDAP_SUCCESS)
{
   $ld->unbind;
   die "bind: $ld->errstring";
}

#  This will set the size limit to $sizelimit from above.  The command
#  is a Netscape addition, but I've programmed replacement versions for
#  other APIs.
$ld->set_option(LDAP_OPT_SIZELIMIT,$sizelimit);

#  This routine is COMPLETELY unnecessary in this application, since
#  the rebind procedure at the end of this program simply rebinds as
#  a NULL user.
$ld->set_rebind_proc(&rebindproc);

#
#  Specify Search Filter and List of Attributes to Return

my $filter = $ARGV[0];
my @attrs = ();

#
#  Perform Search
my $msgid = $ld->search($BASEDN,LDAP_SCOPE_SUBTREE,$filter,\@attrs,0);

if ($msgid < 0)
{
   $ld->unbind;
   die "search: $ld->errstring";
}

# Reset Number of Entries Counter
my $nentries = 0;

# Set no timeout.
my $timeout = -1;

#
#  Cycle Through Entries
while (($rc = $ld->result($msgid,0,$timeout)) == LDAP_RES_SEARCH_ENTRY)
{
  $nentries++;

  for ($ent = $ld->first_entry; $ent != 0; $ent = $ld->next_entry)
  {

#
#  Get Full DN

   if (($dn = $ld->get_dn) eq "")
   {
      $ld->unbind;
      die "get_dn: $ld->errstring";
   }

#
#  Cycle Through Each Attribute

   for ($attr = $ld->first_attribute; $attr ne ""; $attr = $ld->next_attribute)
   {

#
#  Notice that we're using get_values_len.  This will retrieve binary
#  as well as text data.  You can change to get_values to only get text
#  data.
#
      @vals = $ld->get_values_len($attr);
      $record{$dn}->{$attr} = [@vals];
   }
  }
  $ld->msgfree;

}
if ($rc == LDAP_RES_SEARCH_RESULT &&
     $ld->err != LDAP_SUCCESS)
{
   $ld->unbind;
   die "result: $ld->errstring";
}

print "Found $nentries records\n";

$ld->unbind;

foreach $dn (keys %record)
{
   my $item;
   print "dn: $dn\n";
   foreach $attr (keys %{$record{$dn}})
   {
      for $item ( @{$record{$dn}{$attr}})
      {
         if ($attr =~ /binary/ )
         {
	    print "$attr: <binary>\n";
	 } elsif ($attr eq "jpegphoto") {
#
#  Notice how easy it is to take a binary attribute and dump it to a file
#  or such.  Gotta love PERL.
#
	    print "$attr: JpegPhoto (length: " . length($item). ")\n";
	    open (TEST,">$dn.jpg");
	    print TEST $item;
	    close (TEST);
         } else {
            print "$attr: $item\n";
         }
      }
   }
}

exit;

sub rebindproc
{

   return("","",LDAP_AUTH_SIMPLE);
}

