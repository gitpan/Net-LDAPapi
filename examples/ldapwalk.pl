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

use Net::LDAPapi;

#  Define these values

$ldap_server = "localhost";
$BASEDN = "o=Org, c=US";

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

#
#  Specify Attributes to Return, or @attrs = () for all

@attrs = ("cn","jpegphoto");

#
#  Specify what to Search For

$filter = $ARGV[0];

#
#  Perform Search

$msgid = ldap_search($ld,$BASEDN,LDAP_SCOPE_SUBTREE,$filter,\@attrs,0,);
if ($msgid == -1)
{
   ldap_perror($ld,"ldap_search");
}

$nentries = 0;

$timeout = -1;

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
      $record{$dn}{$attr} = [ @vals ];
   }
  }
  ldap_msgfree($result);

}
if ($rc == -1)
{
   ldap_perror($ld,"ldap_result");
   die;
}

print "Found $nentries records\n";

ldap_unbind($ld);

foreach $dn (keys %record)
{
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


