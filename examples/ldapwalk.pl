#!/usr/misc/bin/perl5
#
#
#  ldapwalk.pl - Walks through Records Matching a Given Filter
#  Author:  Clayton Donley, Motorola, <donley@cig.mcel.mot.com>
#
#  Demonstration of Synchronous Searching in PERL5.
#
#  Rather than printing attribute and values directly, they are
#  stored in a Hash, where further manipulation would be very simple.
#  The output could then be printed in LDIF format for import, or
#  simply run through ldap_modify_s commands.
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
my %record = ();
my $rc;
my $result;

#
#  Initialize Connection to LDAP Server

if (($ld = ldap_open($ldap_server,LDAP_PORT)) eq "")
{
   die "ldap_init Failed!";
}

#
#  Bind as NULL,NULL to LDAP connection $ld

if ((ldap_simple_bind_s($ld,"","")) != LDAP_SUCCESS)
{
   ldap_perror($ld,"ldap_simple_bind_s");
   die;
}

#  This will set the size limit to $sizelimit from above.  The command
#  is a Netscape addition, but I've programmed replacement versions for
#  other APIs.
ldap_set_option($ld,LDAP_OPT_SIZELIMIT,$sizelimit);

#  This routine is COMPLETELY unnecessary in this application, since
#  the rebind procedure at the end of this program simply rebinds as
#  a NULL user.
# ldap_set_rebind_proc($ld,&rebindproc);

#
#  Specify Search Filter and List of Attributes to Return

my $filter = $ARGV[0];
my @attrs = ();

#
#  Perform Search
my $msgid = ldap_search($ld,$BASEDN,LDAP_SCOPE_SUBTREE,$filter,\@attrs,0);

if ($msgid < 0)
{
#  ldap_get_lderrno is another Netscape routine that I've made available
#   for other APIs, since we can't directly access the internals of the LDAP
#   structure to get error codes.
   my $blah1;
   my $blah2;
   my $err = ldap_get_lderrno($ld,$blah1,$blah2);
   print &ldap_err2string($err),"\n";
   ldap_unbind($ld);
   die;
}

# Reset Number of Entries Counter
my $nentries = 0;

# Set no timeout.
my $timeout = -1;

#
#  Cycle Through Entries
while (($rc = ldap_result($ld,$msgid,0,$timeout,$result)) == LDAP_RES_SEARCH_ENTRY)
{
  $nentries++;

  for ($ent = ldap_first_entry($ld,$result); $ent != 0; $ent = ldap_next_entry($ld,$ent))
  {

#
#  Get Full DN

   if (($dn = ldap_get_dn($ld,$ent)) eq "")
   {
      ldap_perror($ld, "ldap_get_dn");
   }

#
#  Cycle Through Each Attribute

   for ($attr = ldap_first_attribute($ld,$ent,$ber); $attr ne ""; $attr = ldap_next_attribute($ld,$ent,$ber))
   {

#
#  Notice that we're using ldap_get_values_len.  This will retrieve binary
#  as well as text data.  You can change to ldap_get_values to only get text
#  data.
#
      @vals = ldap_get_values_len($ld,$ent,$attr);
      $record{$dn}->{$attr} = [@vals];
   }
  }
  ldap_msgfree($result);

}
if ($rc == LDAP_RES_SEARCH_RESULT)
{
   my $err = ldap_result2error($ld,$result,0);
   if ($err != LDAP_SUCCESS)
   {
      my $texterr = ldap_err2string($err);
      print "Error: $texterr\n";
      die;
   }
}

print "Found $nentries records\n";

ldap_unbind($ld);

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
	    print "$attr: " . length($item). "\n";
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

