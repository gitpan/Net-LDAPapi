# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..8\n"; }
END {print "not ok 1\n" unless $loaded;}
use Net::LDAPapi;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

##
## Change these values for test to work...
##

$BASEDN    = "o=Test, c=US";
$filter    = "(cn=Manager)";
$ldap_host = "";

if ($ldap_host eq "")
{
   die "Please edit \$BASEDN, \$filter and \$ldap_host in test.pl.\n";
}

##
##  Initialize LDAP Connection
##

if (($ld = ldap_open($ldap_host,LDAP_PORT)) == 0)
{
   print "not ok 2\n";
}
print "ok 2\n";

##
##  Bind as DN, PASSWORD (NULL,NULL) on LDAP connection $ld
##

if ((ldap_simple_bind_s($ld,"","")) ne LDAP_SUCCESS)
{
   ldap_perror($ld,"ldap_simple_bind_s");
   print "not ok 3\n";
   exit -1;
}
print "ok 3\n";

##
## ldap_search_s - Synchronous Search
##

@attrs = ("cn");

if (ldap_search_s($ld,$BASEDN,LDAP_SCOPE_SUBTREE,$filter,\@attrs,0,$result) != LDAP_SUCCESS)
{
   ldap_perror($ld,"ldap_search_s");
   print  "not ok 4\n";
}
print "ok 4\n";

##
## ldap_count_entries - Count Matched Entries
##

if (($count = ldap_count_entries($ld,$result)) == -1)
{
   ldap_perror($ld,"count_entry");
   print "not ok 5\n";
}
print "ok 5\n";

##
## ldap_first_entry - Get First Matched Entry
## ldap_next_entry  - Get Next Matched Entry
##

   for ($ent = ldap_first_entry($ld,$result); $ent != ""; $ent = ldap_next_entry($ld,$ent))
   {
      
##
## ldap_get_dn  -  Get DN for Matched Entries
##

      if (($dn = ldap_get_dn($ld,$ent)) ne "" )
      {
         print "ok 6\n";
      } else {
         ldap_perror($ld, "get_dn");
         print "not ok 6\n";
      }

      if (($attr = ldap_first_attribute($ld,$ent,$ber)) ne "")
      {
         print "ok 7\n";

##
## ldap_get_values
##

         @vals = ldap_get_values($ld,$ent,$attr);
         if ($#vals >= 0)
         {
            print "ok 8\n";
         } else {
            print "not ok 8\n";
         }
      } else {
         print "not ok 7\n";
      }


   }

##
##  Unbind LDAP Connection
##

ldap_unbind($ld);

