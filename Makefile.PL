use ExtUtils::MakeMaker;

print "\n\nLDAP Perl5 Module - by Clayton Donley <donley\@cig.mcel.mot.com>\n\n";

unless ($sdk)
{
   print "Select your Development Kit:\n";
   print "  1.  Netscape (default)\n";
   print "  2.  University of Michigan\n";
   print "  3.  ISODE (compiled with LDAP)\n";
   print "Choose: ";
   $sdk = <>;
}

$version = ($sdk == 2 ? 'UMICH' :
            $sdk == 3 ? 'ISODE' :
            'NETSCAPE');

$lname = ($version eq 'ISODE' ? 'ISODE' : 'LDAP');

if ($include_ldap eq "")
{
   if ($version eq 'ISODE')
   {
      print "Location *above isode/ Include Dir (default: /usr/include):  ";
   } else {
      print "Location of $lname Include Files (default: /usr/include):  ";
   }
   $include_ldap = <> or $include_ldap = "/usr/include";
}

# Sigh... isode-8 has isode/ldap.h, isode IC has isode/ldap/ldap.h
if (-r "$include_ldap/ldap.h")
{
   if (-r "$include_ldap/isode/ldap.h")
   {
      $include_ldap .= " -I$include_ldap/isode";
   } elsif (-r "$include_ldap/isode/ldap/ldap.h") {
      $include_ldap .= " -I$include_ldap/isode/ldap";
   }
}

if ($lib_ldap eq "")
{
   print "Location of $lname Library Files (default: /usr/lib):  ";
   $lib_ldap = <> or $lib_ldap = "/usr/lib";
}

if ($version eq "UMICH" && $kerblibs eq "")
{
   print "Using Kerberos for Authentication (default: n)? ";
   $usekerb = <>;
   if ($usekerb =~ /^y.*/i)
   {
      $kerblibs = "-lkrb -ldes";
   }
}

sub MY::postamble
{
    '
constant.h:	constant.gen
	perl5 constant.gen >tmp.h && mv tmp.h constant.h
';
}

WriteMakefile(
	'NAME'		=> 	'Net::LDAPapi',
	'VERSION_FROM'	=> 	'LDAPapi.pm',
	'INC'		=>	"-I$include_ldap",
	($version eq "NETSCAPE" ? (
	'LIBS'		=> 	["-L$lib_ldap -lldap10"],
	'DEFINE'	=>	'-DNETSCAPE_LDAP',
	) : $version eq "ISODE" ? (
	'LIBS'		=>	["-L$lib_ldap -lldap -llber -lisode"],
	'DEFINE'	=>	'-DISODE_LDAP',
	) : (
	'LIBS'		=> 	["-L$lib_ldap -lldap -llber $kerblibs"],
	'DEFINE'	=> 	'',
	)),
	'depend'	=>	{ 'LDAPapi.o' => 'constant.h' },
	'clean'		=>	{ 'FILES'     => 'constant.h tmp.h' },
);
