#!/usr/bin/perl5 -w
#
#  testwrite.pl - Test of LDAP Modify Operations in Perl5
#  Author:  Clayton Donley <donley@cig.mcel.mot.com>
#
#  This utility is mostly to demonstrate all the write operations
#  that can be done with LDAP through this PERL5 module.
#


use strict;
use Net::LDAPapi;


# This is the entry we will be adding.  Do not use a pre-existing entry.
my $ENTRYDN = "cn=Test User, o=Org, c=US";

# This is the DN and password for an Administrator
my $ROOTDN = "cn=admin, o=Org, c=US";
my $ROOTPW = "";

# Set this to your LDAP server.
my $ldap_server = "localhost";

# This will be the handle for your LDAP session.
my $ld;


#
# Open connection to the LDAP server.
#
if (($ld = ldap_open($ldap_server,LDAP_PORT)) == 0)
{
   die "Can't Initialize LDAP Connection."
}

#
# Bind as the Administrator User
#
if ( ldap_simple_bind_s($ld,$ROOTDN,$ROOTPW) != LDAP_SUCCESS )
{
   ldap_perror($ld,"ldap_simple_bind_s");
   ldap_unbind($ld);
   die;
}

#
# Define one LDAP Modification for Adding a user
# 
my %testwrite = (
	"cn" => "Test User",
	"sn" => "User",
	"mail" => "abc123\@somewhere.com",
	"telephoneNumber" => ["888888","111111"],
	"objectClass" => ["person","organizationalPerson","inetOrgPerson"],
);

#
# Perform ADD function on $ENTRYDN using the %testwrite Data
#
if (ldap_add_s($ld,$ENTRYDN,\%testwrite) != LDAP_SUCCESS)
{
   ldap_perror($ld,"ldap_add_s");
   die;
}

print "Entry Added.\n";


#
# Recreate %testwrite to include an entry for modification
#
%testwrite = (
#
# Notice "a" for ADD
	"pager" => {"a",["554","665"]},
	"mail" => ["abc\@423.com","bca\@abb.gov"],
	"labeleduri" => "http://www.abb.com/",
);

#
# Perform Modify function on $ENTRYDN using %testwrite data
#
if (ldap_modify_s($ld,$ENTRYDN,\%testwrite) != LDAP_SUCCESS)
{
   ldap_perror($ld,"ldap_modify_s");
   die;
}

print "Entry Modified.\n";

#
# Delete the entry for $ENTRYDN
#
if (ldap_delete_s($ld,$ENTRYDN) != LDAP_SUCCESS)
{
   ldap_perror($ld,"ldap_delete_s");
   die;
}

print "Entry Deleted.\n";

# Unbind to LDAP server
ldap_unbind($ld);

exit;
