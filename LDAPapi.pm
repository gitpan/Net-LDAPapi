package Net::LDAPapi;

use strict;
use Carp;
use vars qw($VERSION @ISA @EXPORT $AUTOLOAD);

require Exporter;
require DynaLoader;
require AutoLoader;

@ISA = qw(Exporter DynaLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
	ldap_open ldap_init ldap_set_option ldap_get_option ldap_unbind
	ldap_unbind_s ldap_version ldap_abandon ldap_add ldap_add_s
	ldap_set_rebind_proc ldap_simple_bind ldap_simple_bind_s
	ldap_modify ldap_modify_s ldap_modrdn ldap_modrdn_s ldap_modrdn2
	ldap_modrdn2_s ldap_compare ldap_compare_s ldap_delete
	ldap_delete_s ldap_search ldap_search_s ldap_search_st ldap_result
	ldap_msgfree ldap_msg_free ldap_msgid ldap_msgtype
	ldap_get_lderrno ldap_set_lderrno ldap_result2error ldap_err2string
	ldap_count_entries ldap_first_entry ldap_next_entry ldap_get_dn
	ldap_perror ldap_dn2ufn ldap_explode_dn ldap_explode_rdn
	ldap_explode_dns ldap_first_attribute ldap_next_attribute
	ldap_get_values ldap_get_values_len ldap_bind ldap_bind_s
	ldapssl_client_init ldapssl_init ldapssl_install_routines
	ldap_get_all_entries
	LDAPS_PORT
	LDAP_ADMIN_LIMIT_EXCEEDED
	LDAP_AFFECTS_MULTIPLE_DSAS
	LDAP_ALIAS_DEREF_PROBLEM
	LDAP_ALIAS_PROBLEM
	LDAP_ALREADY_EXISTS
	LDAP_API
	LDAP_AUTH_KRBV4
	LDAP_AUTH_KRBV41
	LDAP_AUTH_KRBV42
	LDAP_AUTH_KRBV41_30
	LDAP_AUTH_KRBV42_30
	LDAP_AUTH_NONE
	LDAP_AUTH_SIMPLE
	LDAP_AUTH_UNKNOWN
	LDAP_BUSY
	LDAP_CACHE_CHECK
	LDAP_CACHE_LOCALDB
	LDAP_CACHE_POPULATE
	LDAP_CALLBACK
	LDAP_COMPARE_FALSE
	LDAP_COMPARE_TRUE
	LDAP_CONNECT_ERROR
	LDAP_CONSTRAINT_VIOLATION
	LDAP_DECODING_ERROR
	LDAP_DEREF_ALWAYS
	LDAP_DEREF_FINDING
	LDAP_DEREF_NEVER
	LDAP_DEREF_SEARCHING
	LDAP_ENCODING_ERROR
	LDAP_FILTER_ERROR
	LDAP_FILT_MAXSIZ
	LDAP_INAPPROPRIATE_AUTH
	LDAP_INAPPROPRIATE_MATCHING
	LDAP_INSUFFICIENT_ACCESS
	LDAP_INVALID_CREDENTIALS
	LDAP_INVALID_DN_SYNTAX
	LDAP_INVALID_SYNTAX
	LDAP_IS_LEAF
	LDAP_LOCAL_ERROR
	LDAP_LOOP_DETECT
	LDAP_MOD_ADD
	LDAP_MOD_BVALUES
	LDAP_MOD_DELETE
	LDAP_MOD_REPLACE
	LDAP_NAMING_VIOLATION
	LDAP_NOT_ALLOWED_ON_NONLEAF
	LDAP_NOT_ALLOWED_ON_RDN
	LDAP_NO_LIMIT
	LDAP_NO_MEMORY
	LDAP_NO_OBJECT_CLASS_MODS
	LDAP_NO_SUCH_ATTRIBUTE
	LDAP_NO_SUCH_OBJECT
	LDAP_OBJECT_CLASS_VIOLATION
	LDAP_OPERATIONS_ERROR
	LDAP_OPT_CACHE_ENABLE
	LDAP_OPT_CACHE_FN_PTRS
	LDAP_OPT_CACHE_STRATEGY
	LDAP_OPT_DEREF
	LDAP_OPT_DESC
	LDAP_OPT_DNS
	LDAP_OPT_IO_FN_PTRS
	LDAP_OPT_OFF
	LDAP_OPT_ON
	LDAP_OPT_REBIND_ARG
	LDAP_OPT_REBIND_FN
	LDAP_OPT_REFERRALS
	LDAP_OPT_REFERRAL_HOP_LIMIT
	LDAP_OPT_RESTART
	LDAP_OPT_SIZELIMIT
	LDAP_OPT_SSL
	LDAP_OPT_THREAD_FN_PTRS
	LDAP_OPT_TIMELIMIT
	LDAP_OTHER
	LDAP_PARAM_ERROR
	LDAP_PARTIAL_RESULTS
	LDAP_PORT
	LDAP_PORT_MAX
	LDAP_PROTOCOL_ERROR
	LDAP_REFERRAL
	LDAP_RESULTS_TOO_LARGE
	LDAP_RES_ADD
	LDAP_RES_ANY
	LDAP_RES_BIND
	LDAP_RES_COMPARE
	LDAP_RES_DELETE
	LDAP_RES_EXTENDED
	LDAP_RES_MODIFY
	LDAP_RES_MODRDN
	LDAP_RES_RESUME
	LDAP_RES_SEARCH_ENTRY
	LDAP_RES_SEARCH_REFERENCE
	LDAP_RES_SEARCH_RESULT
	LDAP_RES_SESSION
	LDAP_SCOPE_BASE
	LDAP_SCOPE_ONELEVEL
	LDAP_SCOPE_SUBTREE
	LDAP_SECURITY_NONE
	LDAP_SERVER_DOWN
	LDAP_SIZELIMIT_EXCEEDED
	LDAP_STRONG_AUTH_NOT_SUPPORTED
	LDAP_STRONG_AUTH_REQUIRED
	LDAP_SUCCESS
	LDAP_TIMELIMIT_EXCEEDED
	LDAP_TIMEOUT
	LDAP_TYPE_OR_VALUE_EXISTS
	LDAP_UNAVAILABLE
	LDAP_UNAVAILABLE_CRITICAL_EXTN
	LDAP_UNDEFINED_TYPE
	LDAP_UNWILLING_TO_PERFORM
	LDAP_URL_ERR_BADSCOPE
	LDAP_URL_ERR_MEM
	LDAP_URL_ERR_NODN
	LDAP_URL_ERR_NOTLDAP
	LDAP_URL_ERR_PARAM
	LDAP_URL_OPT_SECURE
	LDAP_USER_CANCELLED
	LDAP_VERSION
	LDAP_VERSION1
	LDAP_VERSION2
);
$VERSION = '1.39a';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.

    my $constname;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    my $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
	if ($! =~ /Invalid/) {
	    $AutoLoader::AUTOLOAD = $AUTOLOAD;
	    goto &AutoLoader::AUTOLOAD;
	}
	else {
		croak "Your vendor has not defined LDAP macro $constname";
	}
    }
    eval "sub $AUTOLOAD { $val }";
    goto &$AUTOLOAD;
}

bootstrap Net::LDAPapi $VERSION;

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__

=head1 NAME

Net::LDAPapi - Perl5 Module Supporting LDAP API

=head1 SYNOPSIS

  use Net::LDAPapi;

  See individual items and Example Programs for Usage

=head1 DESCRIPTION

This module provides a PERL5 interface to the LDAP API.  It was written
to interface to the LDAP library supplied by Netscape or University of
Michigan.  It has recently been tested with ISODE v8 and ISODE IC libraries
and header files.

Please email me any bugs you find.  This is my first attempt at a
Perl5 dynamically loadable module, so any suggestions or comments
would be highly welcome.

=head1 GENERATING AN ADD/MODIFY HASH

  For the ldap_add* and ldap_modify* functions, you need to generate
  a list of attributes and values.

  You will do this by creating a HASH table.  Each attribute in the
  hash contains associated values.  These values can be one of three
  things.

    - SCALAR VALUE    (ex. "Clayton Donley")
    - ARRAY REFERENCE (ex. ["Clayton Donley","Clay Donley"])
    - HASH REFERENCE  (ex. {"r",["Clayton Donley"]}
         note:  the value inside the HASH REFERENCE must currently
	         be an ARRAY REFERENCE.

  The key inside the HASH REFERENCE must be one of the following for a
  modify operation:
    - "a" for LDAP_MOD_ADD (Add these values to the attribute)
    - "r" for LDAP_MOD_REPLACE (Replace these values in the attribute)
    - "d" for LDAP_MOD_DELETE (Delete these values from the attribute)

  Additionally, in add and modify operations, you may specify "b" if the
  attributes you are adding are BINARY (ex. "rb" to replace binary).

  Currently, it is only possible to do one operation per add/modify
  operation, meaning you can't do something like:

     {"d",["Clayton"],"a",["Clay"]}   <-- WRONG!

  Using any combination of the above value types, you can do things like:

  %ldap_modifications = (
     "cn", "Clayton Donley",                    # Replace 'cn' values
     "givenname", ["Clayton","Clay"],           # Replace 'givenname' values
     "mail", {"a",["donley\@cig.mcel.mot.com"],  #Add 'mail' values
     "jpegphoto", {"rb",[$jpegphotodata]},      # Replace Binary jpegPhoto
  );

  Then remember to call the ldap_modify* functions with a REFERENCE to
  this HASH.  Something like:

  $status = ldap_modify_s($ld,$modify_dn,\%ldap_modifications);

=head1 SPECIAL API FUNCTIONS

=item GETTING/SETTING LDAP INTERNAL VALUES

  In ISODE and UMICH versions of the LDAP C API, you would normally get
  status information and set options within an LDAP structure.

  In this PERL module, I have added calls normally available only in the
  Netscape API.  These options are all documented later in this MAN page.

     ldap_get_lderrno() - Get Recent Errors
     ldap_set_lderrno() - Set Error Messages
     ldap_get_option()  - Get Session Options
     ldap_set_option()  - Set Session Options
     ldap_msgid()       - Get MSGID from RESULT
     ldap_msgtype()     - Get MSGTYPE from RESULT

=item RETRIEVING ALL ENTRIES AS HASH OF HASHES

  Another new call with v1.36 is ldap_get_all_entries().  This is not in the
  C API, but is implemented in C within the module to allow an easy way to
  populate a hash of hashes keyed by DN and ATTRIBUTE.

  An example of using this call can be found in the ldapwalk2.pl example.

=head1 SSL SUPPORT

  When compiled with the Netscape SDK, this module now support Netscape's
  SSL calls.  I do not have an SSL capable server, so this feature is
  not tested yet.  The functions available are:

     ldapssl_client_init($certdbpath,$certdbhandle)
        - Initialize the secure parts (called only once)
     $ld = ldapssl_init($host,$port,$defsecure)
        - Initialize the LDAP library for SSL
     ldapssl_install_routines($ld)
        - Install I/O routines to make SSL over LDAP possible
        - Use after ldap_init() or just call ldapssl_init() instead

  I will add these to the main documentation section once they have been
  tested and verified to work.

=head1 SETTING REBIND PROCESS

  As of v1.35, you can use 'ldap_set_rebind_proc()' to set a PERL function
  to supply DN, PASSWORD, and AUTHTYPE for use when the server rebinds
  (for referals, etc...).  This has not been tested much, as my environment
  is pretty self-contained.

  Usage should be something like:
    ldap_set_rebind_proc($ld,\&my_rebind_proc);

  You can then create the procedure specified.  It should return 3 values.

  Example:
    sub my_rebind_proc
    {
       return($dn,$pass,LDAP_AUTH_SIMPLE);
    }

  Once this has been better tested, I will add further information to
  the supported API functions list.

=head1 SUPPORTED API FUNCTIONS

=item ldap_abandon SESSION MSGID

  This cancels an asynchronous LDAP operation that has not completed.  It
  returns an LDAP STATUS code upon completion.

  Example:

    $status = ldap_abandon($ld, $msgid);

=item ldap_add SESSION ENTRYDN ATTRIBUTES

  Begins an an asynchronous LDAP Add operation.  It returns a MSGID or -1
  upon completion.

  Example:

    @objclass = ("person", "organizationalPerson");

    %attributes = (
       "cn", ["Clayton Donley","Clay Donley"] #Add Multivalue cn
       "sn", "Donley",			      #Add sn
       "telephoneNumber", "+86-10-65551234",  #Add telephoneNumber
       "objectClass", \@objclass,        # Add Multivalue objectClass
       "jpegphoto", {"b",[$jpegphoto]},  # Add Binary jpegphoto
    );

    $entrydn = "cn=Clayton Donley, o=Motorola, c=US";

    $msgid = ldap_add($ld, $entrydn, \%attributes);

  Note that in most cases, you will need to be bound to the LDAP server
  as an administrator in order to add users.

=item ldap_add_s SESSION ENTRYDN ATTRIBUTES

  Synchronous version of the 'ldap_add' command.  Arguments are identical
  to the 'ldap_add' command, but this operation returns an LDAP STATUS,
  not a MSGID.

  Example:

    $result = ldap_add_s($ld, $entrydn, \%attributes);

  See the main LDAP page for how to populate the ATTRIBUTES field for Add
  and Modify operations.

=item ldap_bind SESSION DN CREDENTIALS METHOD

  Asynchronous command for binding to the LDAP server.  It returns a
  MSGID.

  Examples:

    $msgid = ldap_bind($ld,"","",LDAP_AUTH_SIMPLE);
    $msgid = ldap_bind($ld,"cn=Clayton Donley, o=Motorola, c=US", \
		"abc123",LDAP_AUTH_SIMPLE);


=item ldap_bind_s SESSION DN CREDENTIALS METHOD

  Synchronous command for binding to the LDAP server.  It returns
  an LDAP STATUS. 

  Examples:

    $status = ldap_bind_s($ld,"","",LDAP_AUTH_SIMPLE);
    $status = ldap_bind_s($ld,"cn=Clayton Donley, o=Motorola, c=US", \
		"abc123",LDAP_AUTH_SIMPLE);


=item ldap_compare SESSION ENTRYDN TYPE VALUE

  Asynchronous command for comparing a value with the value contained
  within ENTRYDN.  Returns a MSGID.

  Example:

    $msgid = ldap_compare($ld,"cn=Clayton Donley, o=Motorola, c=US", \
		$type,$value);

=item ldap_compare_s SESSION ENTRYDN TYPE VALUE

  Synchronous command for comparing a value with the value contained
  within ENTRYDN.  Returns an LDAP STATUS.

  Example:

    $result = ldap_compare_s($ld,"cn=Clayton Donley, o=Motorola, c=US", \
		$type, $value);


=item ldap_count_entries SESSION RESULT

  Calculates and returns the number of entries in an LDAP result chain.

  Example:

    $number = ldap_count_entries($ld,$result);

=item ldap_count_values OBSOLETE

  This command is not required in PERL.  The number of values returned by
  ldap_get_values can be gotten using the $# operator.  For example, if the
  results are in @values, the following statement would print the number of
  results returned:

    print "Entry contains " . $#values+1 . " values for this attribute.";

=item ldap_count_values_len OBSOLETE

  This command is not required in PERL.  The number of values returned by
  ldap_get_values_len can be gotten using the $# operator.  For example, if the
  results are in @values, the following statement would print the number of
  results returned:

    print "Entry contains " . $#values+1 . " values for this attribute.";


=item ldap_delete SESSION ENTRYDN

  Asynchronous command to delete ENTRYDN.  Returns a MSGID or -1 if error.

  Example:

    $msgid = ldap_delete($ld,"cn=Clayton Donley, o=Motorola, c=US");

=item ldap_delete_s SESSION ENTRYDN

  Synchronous command to deete ENTRYDN.  Returns an LDAP STATUS.

  Example:

    $status = ldap_delete_s($ld,"cn=Clayton Donley, o=Motorola, c=US");

=item ldap_dn2ufn DN

  Converts a Distinguished Name (DN) to a User Friendly Name (UFN).
  Returns a string with the UFN.

  Example:

    $ufn = ldap_dn2ufn("cn=Clayton Donley, o=Motorola, c=US");

=item ldap_err2string ERR

  Converts an LDAP error code number to a human readable error.
  Returns a string with the error message.

  Example:

    $errormsg = ldap_err2string($err);

=item ldap_explode_dn DN NOTYPES

  Splits the DN into an array comtaining the separate components of
  the DN.  Returns an Array.  NOTYPES is a 1 to remove attribute
  types and 0 to retain attribute types.

  Only available with Netscape SDK.

  Example:

    @components = ldap_explode_dn($dn,0);

=item ldap_explode_rdn RDN NOTYPES

  Same as ldap_explode_dn, except that the first argument is a
  Relative Distinguished Name.  NOTYPES is a 1 to remove attribute
  types and 0 to retain attribute types.  Returns an array with
  each component.

  Only available with Netscape SDK.

  Example:

    @components = ldap_explode_rdn($rdn,0);

=item ldap_first_attribute SESSION ENTRY BERVAL

  Returns pointer to first attribute found in ENTRY.  Note that this
  is only returning attribute names (ex: cn, mail, etc...).  BERVAL
  keeps track of the position within the ENTRY. ldap_first_attribute
  will initialize this pointer, so supply any unused variable name.
  Returns a string with the attribute name.

  Returns an empty string when no attributes are available.

  Example:

    $attr = ldap_first_attribute($ld,$entry,$berval);

=item ldap_first_entry SESSION RESULT

  Returns pointer to the first entry in a chain of results.  Returns
  an empty string when no entries are available.

  Example:

    $entry = ldap_first_entry($ld,$result);

=item ldap_get_dn SESSION ENTRY 

  Returns a string containing the DN for the specified entry or an
  empty string if an error occurs.

  Example:

    $dn = ldap_get_dn($ld,$entry);

=item ldap_msgid SESSION RESULT

  Extracts the MSGID from an LDAP result.

  Example:

    $msgid = ldap_getmsgid($ld,$result);

=item ldap_get_lderrno SESSION MATCHED MSG

  Returns information about the most recent LDAP error that occured.

  If MATCHED is set to a scalar variable, it will be set to contain a
  string containing the DN matched by the last LDAP operation.

  If MSG is set to a scalar variable, it will be set to contain a string
  containing the extra error message string that was returned by the server.

  Examples:

    $lderrno = ldap_get_lderrno($ld,$err_dn,$err_msg);

=item ldap_get_option SESSION OPTION OUT

  Retrieves the current setting of an LDAP session option.  You should
  only attempt to receive the values for the following OPTIONs under
  PERL.

	LDAP_OPT_DEREF
	LDAP_OPT_SIZELIMIT
	LDAP_OPT_TIMELIMIT
	LDAP_OPT_REFERRALS

  Returns zero on success, non-zero otherwise.  OUT is set to the
  value of the OPTION.

  Example:

    $return = ldap_get_option($ld,LDAP_OPT_SIZELIMIT,$size);

  After this command, $size would contain the value of LDAP_OPT_SIZELIMIT.

=item ldap_get_values SESSION ENTRY ATTRIBUTE

  Obtain a list of all values associated with a given attribute.
  Returns an empty list if none are available.

  Example:

    @values = ldap_get_values($ld,$entry,"cn");

  This would put all the 'cn' values for $entry into the array @values.

=item ldap_get_values_len SESSION ENTRY ATTRIBUTE

  Retrieves a set of binary values for the specified entry and attribute.

  Example:

    @values = ldap_get_values_len($ld,$entry,"jpegphoto");

  This would put all the 'jpegphoto' values for $entry into the array @values.
  These could then be written to a file, or further processed.


=item ldap_init HOST PORT

  Returns the SESSION handler for an LDAP connection.  PORT may be
  LDAP_PORT if you are simply using the default LDAP port.  HOST may
  be an IP or HOSTNAME.

  Only works with Netscape SDK.  Others use ldap_open.

  Example:

    $ld = ldap_init("ldap.abc.com",LDAP_PORT);

=item ldap_msgfree RESULT

  Frees an LDAP result message.  Returns the type of message freed.

  Example:

    $type = ldap_msgfree($result);

=item ldap_modify SESSION ENTRYDN MODS

  Asynchronous command to modify an LDAP entry.  ENTRYDN is the DN to
  modify and MODS contains a hash-table of attributes and values.  If
  multiple values need to be passed for a specific attribute, a
  reference to an array must be passed.

  Returns the MSGID of the modify operation.

  Example:

    %mods = (
      "telephoneNumber", "",     #remove telephoneNumber
      "sn", "Test",              #set SN to TEST
      "mail", ["me\@abc123.com","me\@second-home.com"],  #set multivalue 'mail'
      "pager", {"a",["1234567"]},  #Add a Pager Value
      "jpegphoto", {"rb",[$jpegphoto]},  # Replace Binary jpegphoto
    );

    $msgid = ldap_modify($ld,$entrydn,\%mods);

  The above would remove the telephoneNumber attribute from the entry
  and replace the "sn" attribute with "Test".  The value in the "mail"
  attribute for this entry would be replaced with both addresses
  specified in @mail.  The "jpegphoto" attribute would be replaced with
  the binary data in $jpegphoto.

=item ldap_modify_s SESSION ENTRYDN MODS

  Synchronous version of ldap_modify.  Returns an LDAP STATUS.  See the
  ldap_modify command for notes and examples of populating the MODS
  parameter.

  Example:

    $status = ldap_modify_s($ld,$entrydn,\%mods);

=item ldap_modrdn2 SESSION ENTRYDN NEWRDN DELETEOLDRDN

  Asynchronous command to change the name of an entry.  DELETEOLDRDN
  is non-zero if you wish to remove the attribute values from the
  old name.  Returns a MSGID.

  Example:

    $msgid = ldap_modrdn2($ld,"cn=Clayton Donley, o=Motorola, c=US", \
		"cn=Clay Donley",0);

=item ldap_modrdn2_s SESSION ENTRYDN NEWRDN DELETEOLDRDN

  Synchronous command to change the name of an entry.  DELETEOLDRDN is
  non-zero if you wish to remove the attribute values from the old
  name.  Returns an LDAP STATUS.

  Example:

    $status = ldap_modrdn2_s($ld,"cn=Clayton Donley, o=Motorola, c=US", \
		"cn=Clay Donley",0);

=item ldap_next_attribute SESSION ENTRY BERVAL

  Similar to ldap_first_attribute, but obtains next attribute.
  Returns a string comtaining the attribute name.  An empty string
  is returned when no further attributes exist.

  Example:

    $attr = ldap_next_attribute($ld,$entry,$berval);

=item ldap_next_entry SESSION RESULT PREVENTRY

  Returns the next entry in a chain of search results.  The value
  returned can be passed as PREVENTRY to obtain the next entry.

  Example:

    $entry = ldap_next_entry($ld,$result,$entry);

=item ldap_open HOST PORT

  Connects to the directory HOST on the specified PORT and returns
  the SESSION handle.

  Example:

    $ld = ldap_open("ldap.abc123.com",LDAP_PORT);

=item ldap_perror SESSION STRING

  If an error occurs while performing an LDAP function, this procedure
  will display it.  SESSION is an LDAP session handle returned by
  ldap_init or ldap_open.  STRING is an identifier to display in front
  of the error message.

  Note that this function does NOT terminate your program.  You would
  need to do any cleanup work on your own.

  Example:

    ldap_perror($ld,"ldap_simple_bind_s");

=item ldap_result SESSION MSGID ALL TIMEOUT RESULT

  Retrieves the result of an operation initiated using an asynchronous
  LDAP call.  Returns the type of result returned or -1 if error.

  MSGID is the MSGID returned by the Asynchronous LDAP call.  Set ALL to
  0 to receive entries as they arrive, or non-zero to receive all entries
  before returning.  Set TIMEOUT to the number of seconds to wait for the
  result, or -1 for no timeout.  RESULT will be set to the result chain.

  Example:

    $type = ldap_result($ld,$msgid,0,1,$result);

=item ldap_result2error SESSION RESULT FREEIT

  Returns the LDAP error code from an LDAP result message.  FREEIT will
  free the memory occupied by the RESULT if set non-zero.

  Example:

    $lderrno = ldap_result2error($ld,$result,0);

=item ldap_search SESSION BASE SCOPE FILTER ATTRS ATTRSONLY

  Begins an asynchronous LDAP search.  Returns a MSGID or -1 if an
  error occurs.  BASE is the base object for the search operation.
  FILTER is a string containing an LDAP search filter.  ATTRS is a
  reference to an array containing the attributes to return.  An
  empty array would return all attributes.  ATTRSONLY set to non-zero
  will only obtain the attribute types without values.

  SCOPE is one of the following:
		LDAP_SCOPE_BASE
		LDAP_SCOPE_ONELEVEL
		LDAP_SCOPE_SUBTREE
		
  Example:

    @attrs = ("cn","sn");    # Return specific attributes
    @attrs = ();             # Return all Attributes

    $msgid = ldap_search($ld,"o=Motorola, c=US",LDAP_SCOPE_SUBTREE, \
		"(sn=Donley),\@attrs,0);

=item ldap_search_s SESSION BASE SCOPE FILTER ATTRS ATTRSONLY RESULT

  Performs a synchronous LDAP search.  Returns an LDAP STATUS.  BASE
  is the base object for the search operation.  FILTER is a string
  containing an LDAP search filter.  ATTRS is a reference to an array
  containing the attributes to return.  An empty array would return all
  attributes.  ATTRSONLY set to non-zero will only obtain the attribute
  types without values.  Results are put into RESULTS.

  SCOPE is one of the following:
		LDAP_SCOPE_BASE
		LDAP_SCOPE_ONELEVEL
		LDAP_SCOPE_SUBTREE

  Example:

    @attrs = ("cn","sn");    # Return specific attributes
    @attrs = ();             # Return all attributes

    $status = ldap_search_s($ld,"o=Motorola, c=US",LDAP_SCOPE_SUBTREE, \
		"(sn=Donley)",\@attrs,0,$result);

=item ldap_search_st SESSION BASE SCOPE FILTER ATTRS ATTRSONLY TIMEOUT RESULT

  Performs a synchronous LDAP search with a TIMEOUT.  See ldap_search_s
  for a description of parameters.  Returns an LDAP STATUS.  Results are
  put into RESULTS.  TIMEOUT is a number of seconds to wait before giving
  up, or -1 for no timeout.

  Example:

    $status = ldap_search_st($ld,"o=Motorola, c=US",LDAP_SCOPE_SUBTREE, \
		"(sn=Donley),[],0,3,$result);

=item ldap_set_option SESSION OPTION IN

  Sets an LDAP option.  Only the following OPTIONs may be set in PERL:
		LDAP_OPT_DEREF
		LDAP_OPT_SIZELIMIT
		LDAP_OPT_TIMELIMIT
		LDAP_OPT_REFERRALS

  IN is an integer representing a new value or LDAP_OPT_ON/LDAP_OPT_OFF
  for LDAP_OPT_REFERRALS.  Returns 0 on success and non-zero otherwise.

  Example:

    $stat = ldap_set_option($ld,LDAP_OPT_REFERRALS,LDAP_OPT_ON);

=item ldap_simple_bind SESSION DN PASSWORD

  Asynchronous operation to bind to the LDAP server with a specific DN
  and PASSWORD.  You can specify empty strings for DN and PASSWORD for
  anonymous login.  SESSION is the LDAP session handle returned by
  ldap_init or ldap_open.

  This operation returns a MSGID.

  Example:

    $msgid = ldap_simple_bind($ld,"","");

=item ldap_simple_bind_s SESSION DN PASSWORD

  Synchronous operation to bind to the LDAP server with a specific DN
  and PASSWORD.  You can specify empty strings for DN and PASSWORD
  for anonymous login.  SESSION is the LDAP session handle returned
  by ldap_init or ldap_open.

  This operation returns an LDAP STATUS.

  Example:

    if ((ldap_simple_bind_s($ld,"","")) != LDAP_SUCCESS)
    {
       ldap_perror($ld,"ldap_simple_bind_s");
       die;
    }

=item ldap_unbind SESSION

  Unbind LDAP connection with specified SESSION handler.

  Example:

    ldap_unbind($ld);

=head1 AUTHOR

Clayton Donley, Motorola, donley@cig.mcel.mot.com

=head1 SEE ALSO

perl(1).

=cut
