#!/usr/misc/bin/perl5 -w
#
#
#  ldapwalk2.pl - Walks through Records Matching a Given Filter
#  Author:  Clayton Donley, Motorola, <donley@cig.mcel.mot.com>
#
#  Demonstration of Synchronous Searching in PERL5.
#
#  Similar to ldapwalk.pl, only it uses synchronous calls and demostrates
#  the use of 'ldap_get_all_entries' to retrieve a hash containing all
#  matching entries.
#
#  Usage:  ldapwalk2.pl FILTER
#  Example:  ldapwalk2.pl "sn=Donley"
#

use strict;
use Net::LDAPapi;

#  Define these values

my $ldap_server = "localhost";
my $BASEDN = "o=Org, c=US";
my $sizelimit = 100;            # Set to Maximum Number of Entries to Return
                                # Can set small to test error routines

#  Various Variable Declarations
my $ld;
my $filter;
my $result;
my %record;
my $dn;
my $item;
my $attr;

#  Initialize Connection to LDAP Server

if (($ld = ldap_open($ldap_server,LDAP_PORT)) eq "")
{
   die "ldap_init Failed!";
}

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

#ldap_set_rebind_proc($ld,\&rebindproc);

#  Specify what to Search For

$filter = $ARGV[0];

#  Perform Search

if (ldap_search_s($ld,$BASEDN,LDAP_SCOPE_SUBTREE,$filter,[],0,$result)
       != LDAP_SUCCESS)
{

#  ldap_get_lderrno is another Netscape routine that I've made available
#   for other APIs, since we can't directly access the internals of the LDAP
#   structure to get error codes.

   my $errdn;
   my $extramsg;
   my $err = ldap_get_lderrno($ld,$errdn,$extramsg);
   print &ldap_err2string($err),"\n";
   ldap_unbind($ld);
   die;
}

#  Here we get a HASH of HASHes... All entries, keyed by DN and ATTRIBUTE.
#
#  Since a reference is returned, we simply make %record contain the HASH
#  that the reference points to.

%record = %{ldap_get_all_entries($ld,$result)};

ldap_unbind($ld);

# We can sort our resulting DNs quite easily...
my @dns = (sort keys %record);

# Print the number of entries returned.
print $#dns+1 . " entries returned.\n";

foreach $dn (@dns)
{
   print "dn: $dn\n";
   foreach $attr (keys %{$record{$dn}})
   {
      for $item ( @{$record{$dn}{$attr}})
      {
	 if ($attr =~ /binary/)
	 {
	    print "$attr: binary - length=" . length($item) . "\n";
	 }
	 elsif ($attr eq "jpegphoto")
         {
#
#  Notice how easy it is to take a binary attribute and dump it to a file
#  or such.  Gotta love PERL.
#
	    print "$attr: binary - length=" . length($item). "\n";
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

