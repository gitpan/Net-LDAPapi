#!/usr/misc/bin/perl5
#
#
#  updatepw.pl - Synchronize Passwords from Unix to LDAP
#  Author:  Clayton Donley, Motorola, <donley@cig.mcel.mot.com>
#
#  Reads in a password file, checks for existing entries matching
#  username@domain.com in the mail attribute and populates the CRYPTed
#  password from Unix into the userPassword attribute for that DN.
#
#  Usage:  updatepw.pl username username ... username
#  Example:  updatepw.pl "donley"
#

use Net::LDAPapi;

#  Define these values

$ldap_server = "";
$PWFILE = "/etc/passwd";
$BASEDN = "o=Org, c=US";
$ROOTDN = "cn=Directory Manager, o=Org, c=US";
$ROOTPW = "abc123";
$MAILATTR = "mail";
$MYDOMAIN = "mycompany.com";

open(PASSWD,$PWFILE);
while($line = <PASSWD>)
{
   chop $line;

   ($user,$pass) = split(/:/,$line);
   $pwuser{$user} = $pass;
}
close(PASSWD);

#  Initialize Connection to LDAP Server

if (($ld = ldap_open($ldap_server,LDAP_PORT)) eq "")
{
   die "ldap_init Failed!";
}

#  Bind as the ROOT DIRECTORY USER to LDAP connection $ld

if ((ldap_simple_bind_s($ld,$ROOTDN,$ROOTPW)) != LDAP_SUCCESS)
{
   ldap_perror($ld,"ldap_simple_bind_s");
   die;
}


#  Specify what to Search For

foreach $username (@ARGV)
{

#  Perform Search
   $filter = "($MAILATTR=$username\@$MYDOMAIN)";
   if (ldap_search_s($ld,$BASEDN,LDAP_SCOPE_SUBTREE,$filter,["uid","userpassword","mail"],0,$result)
       != LDAP_SUCCESS)
   {

#  ldap_get_lderrno is another Netscape routine that I've made available
#   for other APIs, since we can't directly access the internals of the LDAP
#   structure to get error codes.

      $err = ldap_get_lderrno($ld,$errdn,$extramsg);
      print &ldap_err2string($err),"\n";
      ldap_unbind($ld);
      die;
   }

#  Here we get a HASH of HASHes... All entries, keyed by DN and ATTRIBUTE.
#
#  Since a reference is returned, we simply make %record contain the HASH
#  that the reference points to.

   if (($ent = ldap_first_entry($ld,$result)) == 0)
   {
      print "Not Found: $username\@cig.mcel.mot.com\n";
   } else {
      $dn = ldap_get_dn($ld,$ent);
      @pass = ldap_get_values($ld,$ent,'userpassword');
      if ($pass[0] ne "{CRYPT}$pwuser{$username}")
      {
         $modifyrec{"userpassword"} = [ "{CRYPT}$pwuser{$username}" ];
         if (ldap_modify_s($ld,$dn,\%modifyrec) != LDAP_SUCCESS)
         {
            print "Error: $dn Unsuccessful.\n";
            ldap_perror($ld,"ldap_modify_s");
         }
         print "Updated: $username\@cig.mcel.mot.com\n";
      } else {
         print "Matched: $username\@cig.mcel.mot.com\n";
      }
   }
}

ldap_unbind($ld);

exit;

sub rebindproc
{

   return("","",LDAP_AUTH_SIMPLE);
}

