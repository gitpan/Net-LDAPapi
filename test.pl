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

$BASEDN    = "o=Org,c=US";
$filter    = "(objectclass=*)";
$ldap_host = "";

if (!$ldap_host)
{
   die "Please edit \$BASEDN, \$filter and \$ldap_host in test.pl.\n";
}

##
##  Initialize LDAP Connection
##

if (($ld = new Net::LDAPapi(-host=>$ldap_host)) == -1)
{
   print "not ok 2\n";
   exit -1; 
}
print "ok 2\n";

##
##  Bind as DN, PASSWORD (NULL,NULL) on LDAP connection $ld
##

if ($ld->bind_s != LDAP_SUCCESS)
{
   $ld->perror("bind_s");
   print "not ok 3\n";
   exit -1;
}
print "ok 3\n";

##
## ldap_search_s - Synchronous Search
##

@attrs = ("mail");

if ($ld->search_s($BASEDN,LDAP_SCOPE_SUBTREE,$filter,\@attrs,0) != LDAP_SUCCESS)
{
   $ld->perror("search_s");
   print  "not ok 4\n";
}
print "ok 4\n";

##
## ldap_count_entries - Count Matched Entries
##

if ($ld->count_entries == -1)
{
   ldap_perror($ld,"count_entry");
   print "not ok 5\n";
}
print "ok 5\n";

##
## first_entry - Get First Matched Entry
## next_entry  - Get Next Matched Entry
##

   for ($ent = $ld->first_entry; $ent; $ent = $ld->next_entry)
   {
      
##
## ldap_get_dn  -  Get DN for Matched Entries
##

      if ($ld->get_dn ne "" )
      {
         print "ok 6\n";
      } else {
         $ld->perror("get_dn");
         print "not ok 6\n";
      }

      if (($attr = $ld->first_attribute) ne "")
      {
         print "ok 7\n";

##
## ldap_get_values
##

         @vals = $ld->get_values($attr);
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

$ld->unbind($ld);

