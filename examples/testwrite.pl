#!/usr/misc/bin/perl5
#
#  testwrite.pl - Test of LDAP Modify Operations in Perl5
#  Author:  Clayton Donley <donley@cig.mcel.mot.com>
#
#  This utility is mostly to demonstrate all the write operations
#  that can be done with LDAP through this PERL5 module.
#
#  It is not yet well documented, but you should easily be able to
#  follow some of the code to understand what is happening, especially
#  if you check the functions and examples in the man-page.
#


$ENTRYDN = "cn=Test User, o=Org, c=US";
$ROOTDN = "cn=Manager, o=Org, c=US";
$ROOTPW = "";
$ldap_server = "localhost";

use Net::LDAPapi;

if (($ld = ldap_open($ldap_server,LDAP_PORT)) == NULL)
{
   die "Can't Initialize LDAP Connection."
}

if ( ldap_simple_bind_s($ld,$ROOTDN,$ROOTPW) != LDAP_SUCCESS )
{
   ldap_perror($ld,"ldap_simple_bind_s");
   ldap_unbind($ld);
   die;
}

@phone = ("8888","1234","5555");
@objectclass = ("person","organizationalPerson","inetOrgPerson");

%testwrite = (
	"cn", "Test User",
	"sn", "User",
	"mail", "abc123\@somewhere.com",
	"telephoneNumber", \@phone,
	"objectClass", \@objectclass,
);

if (ldap_add_s($ld,$ENTRYDN,\%testwrite) != LDAP_SUCCESS)
{
   ldap_perror($ld,"ldap_add_s");
   die;
}

print "Entry Added.\n";


#
#  You could simply uncomment these lines to read a jpeg file, then uncomment
#  the jpegphoto line in %testmod to add it to the test entry.  The LDAP
#  PERL module automatically calculates the size of the buffer, so no need
#  to play with bervals structures in PERL or anything.
#

#open(TEST,"image.jpg");
#while ($stuff = <TEST>)
#{
#   $jpegphoto = $jpegphoto . $stuff;
#}
#close(TEST);

%testmod = (
#
# Notice "a" for ADD
#
	"pager",{"a",["554","665"]},
	"mail",["abc\@423.com","bca\@abb.gov"],
	"labeleduri","http://www.cig.mcel.mot.com/",
#
# Notice "rb" for REPLACE BINARY
#	"jpegPhoto",{"rb",[$jpegphoto]},
);

if (ldap_modify_s($ld,$ENTRYDN,\%testmod) != LDAP_SUCCESS)
{
   ldap_perror($ld,"ldap_modify_s");
   die;
}

print "Entry Modified.\n";

if (ldap_delete_s($ld,$ENTRYDN) != LDAP_SUCCESS)
{
   ldap_perror($ld,"ldap_delete_s");
   die;
}

print "Entry Deleted.\n";

ldap_unbind($ld);
exit;
