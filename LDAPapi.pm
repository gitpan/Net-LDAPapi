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
$VERSION = '1.40';

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

sub new
{
   my ($this,$host,$port) = @_;
   my $class = ref($this) || $this;
   my $self = {};
   my $ld;
   bless $self, $class;

   $host = "localhost" unless $host;
   $port = $self->LDAP_PORT unless $port;
   $ld = ldap_open($host,$port);
   if ($ld == 0)
   {
       return -1;
   }
   $self->{"ld"} = $ld;
   $self->{"err"} = 0;
   $self->{"errstring"} = undef;
   return $self;
}

sub DESTROY {};

sub abandon
{
   my ($self,$msgid) = @_;

   my ($errdn,$extramsg,$status);

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if ($msgid < 0)
   {
      croak("Invalid MSGID");
   }

   if (($status = ldap_abandon($self->{"ld"},$msgid)) != $self->LDAP_SUCCESS)
   {
      $self->{"errno"} = ldap_get_lderrno($self->{"ld"},$errdn,$extramsg);
      $self->{"errstring"} = ldap_err2string($self->{"errno"});
   }
   return $status;
}

sub add
{
   my ($self,$dn,$mod) = @_;

   my ($errdn,$extramsg,$msgid);

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if ($dn eq "")
   {
      croak("No DN Specified");
   }

   if (ref($mod) ne "HASH")
   {
      croak("LDAP Modify Structure Not a HASH Reference");
   }

   if (($msgid = ldap_add($self->{"ld"},$dn,$mod)) < 0)
   {
      $self->{"errno"} = ldap_get_lderrno($self->{"ld"},$errdn,$extramsg);
      $self->{"errstring"} = ldap_err2string($self->{"errno"});
   }
   return $msgid;
}

sub add_s
{
   my ($self,$dn,$mod) = @_;

   my ($errdn,$extramsg,$status);

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if ($dn eq "")
   {
      croak("No DN Specified");
   }

   if (ref($mod) ne "HASH")
   {
      croak("LDAP Modify Structure Not a HASH Reference");
   }

   if (($status = ldap_add_s($self->{"ld"},$dn,$mod)) != $self->LDAP_SUCCESS)
   {
      $self->{"errno"} = ldap_get_lderrno($self->{"ld"},$errdn,$extramsg);
      $self->{"errstring"} = ldap_err2string($self->{"errno"});
   }
   return $status;
}

sub bind
{
   my ($self,$dn,$pass,$authtype) = @_;

   my ($errdn,$extramsg,$msgid);

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP connection open");
   }

   $dn = "" unless $dn;
   $pass = "" unless $pass;
   $authtype = $self->LDAP_AUTH_SIMPLE unless $authtype;

   $msgid = ldap_bind($self->{"ld"},$dn,$pass,$authtype);

   if ($msgid < 0)
   {
      $self->{"errno"} = ldap_get_lderrno($self->{"ld"},$errdn,$extramsg);
      $self->{"errstring"} = ldap_err2string($self->{"errno"});
   }
   return($msgid);
}

sub bind_s
{
   my ($self,$dn,$pass,$authtype) = @_;

   my ($errdn,$extramsg,$status);

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP connection open");
   }

   $dn = "" unless $dn;
   $pass = "" unless $pass;
   $authtype = $self->LDAP_AUTH_SIMPLE unless $authtype;

   $status = ldap_bind_s($self->{"ld"},$dn,$pass,$authtype);

   if ($status != $self->LDAP_SUCCESS)
   {
      $self->{"errno"} = ldap_get_lderrno($self->{"ld"},$errdn,$extramsg);
      $self->{"errstring"} = ldap_err2string($self->{"errno"});
   }
   return $status;
}

sub compare
{
   my ($self,$dn,$attr,$value) = @_;

   my ($errdn,$extramsg,$msgid);

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if ($dn eq "")
   {
      croak("No DN Specified");
   }

   $msgid = ldap_compare($self->{"ld"},$dn,$attr,$value);

   if ($msgid < 0)
   {
      $self->{"errno"} = ldap_get_lderrno($self->{"ld"},$errdn,$extramsg);
      $self->{"errstring"} = ldap_err2string($self->{"errno"});
   }
   return($msgid);
}

sub compare_s
{
   my ($self,$dn,$attr,$value) = @_;

   my ($errdn,$extramsg,$status);

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if ($dn eq "")
   {
      croak("No DN Specified");
   }

   if (($status = ldap_compare_s($self->{"ld"},$dn,$attr,$value))
      != $self->LDAP_SUCCESS)
   {
      $self->{"errno"} = ldap_get_lderrno($self->{"ld"},$errdn,$extramsg);
      $self->{"errstring"} = ldap_err2string($self->{"errno"});
   }
   return $status;
}

sub count_entries
{
   my ($self) = @_;

   my ($number);

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if ($self->{"result"} == 0)
   {
      croak("No Current Result");
   }

   $number = ldap_count_entries($self->{"ld"},$self->{"result"});
   return $number;
}

sub delete
{
   my ($self,$dn) = @_;

   my ($errdn,$extramsg,$msgid);

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if ($dn eq "")
   {
      croak("No DN Specified");
   }

   $msgid = ldap_delete($self->{"ld"},$dn);

   if ($msgid < 0)
   {
      $self->{"errno"} = ldap_get_lderrno($self->{"ld"},$errdn,$extramsg);
      $self->{"errstring"} = ldap_err2string($self->{"errno"});
   }
   return($msgid);
}

sub delete_s
{
   my ($self,$dn) = @_;

   my ($errdn,$extramsg,$status);

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if ($dn eq "")
   {
      croak("No DN Specified");
   }

   if (($status = ldap_delete_s($self->{"ld"},$dn)) != $self->LDAP_SUCCESS)
   {
      $self->{"errno"} = ldap_get_lderrno($self->{"ld"},$errdn,$extramsg);
      $self->{"errstring"} = ldap_err2string($self->{"errno"});
   }
   return $status;
}

sub dn2ufn
{
   my ($self,$dn) = @_;

   my ($ufn);

   $ufn = ldap_dn2ufn($dn);
   return $ufn;
}

sub explode_dn
{
   my ($self,$dn,$notypes) = @_;

   my (@components);

   @components = ldap_explode_dn($dn,$notypes);
   return @components;
}

sub explode_rdn
{
   my ($self,$rdn,$notypes) = @_;

   my (@components);

   @components = ldap_explode_rdn($rdn,$notypes);
   return @components;
}

sub first_entry
{
   my ($self) = @_;

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if ($self->{"result"} == 0)
   {
      croak("No Current Result");
   }

   $self->{"entry"} = ldap_first_entry($self->{"ld"},$self->{"result"});

   return $self->{"entry"};
}

sub next_entry
{
   my ($self) = @_;

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if ($self->{"entry"} == 0)
   {
      croak("No Current Entry");
   }

   $self->{"entry"} = ldap_next_entry($self->{"ld"},$self->{"entry"});

   return $self->{"entry"};
}

sub first_attribute
{
   my ($self) = @_;

   my ($attr,$ber);

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if ($self->{"entry"} == 0)
   {
      croak("No Current Entry");
   }

   $attr = ldap_first_attribute($self->{"ld"},$self->{"entry"},$ber);

   $self->{"ber"} = $ber;

   return $attr;
}

sub next_attribute
{
   my ($self) = @_;

   my ($attr);

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if ($self->{"entry"} == 0)
   {
      croak("No Current Entry");
   }

   if ($self->{"ber"} == 0)
   {
      croak("Empty Ber Value");
   }

   $attr = ldap_next_attribute($self->{"ld"},$self->{"entry"},$self->{"ber"});

   if (!$attr)
   {
      ber_free($self->{"ber"},0);
      $self->{"ber"} = 0;
   }
   return $attr;
}

sub perror
{
   my ($self,$msg) = @_;

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   ldap_perror($self->{"ld"},$msg);
}

sub get_dn
{
   my ($self) = @_;

   my ($dn);

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if ($self->{"entry"} == 0)
   {
      croak("No Current Entry");
   }

   $dn = ldap_get_dn($self->{"ld"},$self->{"entry"});

   return $dn;
}

sub get_values
{
   my ($self,$attr) = @_;

   my (@vals);

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if ($self->{"entry"} == 0)
   {
      croak("No Current Entry");
   }

   if ($attr eq "")
   {
      croak("No Attribute Specified");
   }

   @vals = ldap_get_values($self->{"ld"},$self->{"entry"},$attr);

   return @vals;
}

sub get_values_len
{
   my ($self,$attr) = @_;

   my (@vals);

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if ($self->{"entry"} == 0)
   {
      croak("No Current Entry");
   }

   if ($attr eq "")
   {
      croak("No Attribute Specified");
   }

   @vals = ldap_get_values_len($self->{"ld"},$self->{"entry"},$attr);

   return @vals;
}

sub msgfree
{
   my ($self) = @_;
   my ($type);

   if ($self->{"result"} eq "")
   {
      croak("No current result");
   }

   $type = ldap_msgfree($self->{"result"});

   return $type;
}

sub modify
{
   my ($self,$dn,$mod) = @_;

   my ($errdn,$extramsg,$msgid);

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if ($dn eq "")
   {
      croak("No DN Specified");
   }

   if (ref($mod) ne "HASH")
   {
      croak("LDAP Modify Structure Not a Reference");
   }

   $msgid = ldap_modify($self->{"ld"},$dn,$mod);

   if ($msgid < 0)
   {
      $self->{"errno"} = ldap_get_lderrno($self->{"ld"},$errdn,$extramsg);
      $self->{"errstring"} = ldap_err2string($self->{"errno"});
   }
   return $msgid;
}

sub modify_s
{
   my ($self,$dn,$mod) = @_;

   my ($errdn,$extramsg,$status);

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if ($dn eq "")
   {
      croak("No DN Specified");
   }

   if (ref($mod) ne "HASH")
   {
      croak("LDAP Modify Structure Not a Reference");
   }

   if (($status = ldap_modify_s($self->{"ld"},$dn,$mod)) != $self->LDAP_SUCCESS)
   {
      $self->{"errno"} = ldap_get_lderrno($self->{"ld"},$errdn,$extramsg);
      $self->{"errstring"} = ldap_err2string($self->{"errno"});
   }
   return $status;
}

sub modrdn2
{
   my ($self,$dn,$newrdn,$delete) = @_;
   my ($msgid,$errdn,$extramsg);

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   $msgid = ldap_modrdn2($self->{"ld"},$dn,$newrdn,$delete);
   if ($msgid < 0)
   {
      $self->{"errno"} = ldap_get_lderrno($self->{"ld"},$errdn,$extramsg);
      $self->{"errstring"} = ldap_err2string($self->{"errno"});
   }
   return $msgid;
}

sub modrdn2_s
{
   my ($self,$dn,$newrdn,$delete) = @_;
   my ($status,$errdn,$extramsg);

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   $status = ldap_modrdn2_s($self->{"ld"},$dn,$newrdn,$delete);
   if ($status != $self->LDAP_SUCCESS)
   {
      $self->{"errno"} = ldap_get_lderrno($self->{"ld"},$errdn,$extramsg);
      $self->{"errstring"} = ldap_err2string($self->{"errno"});
   }
   return $status;
}


sub result
{
   my ($self,$msgid,$allnone,$timeout) = @_;
   my ($result,$status,$err);

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP connection open");
   }

   if ($msgid < 0)
   {
      croak("Invalid MSGID");
   }

   $status = ldap_result($self->{"ld"},$msgid,$allnone,$timeout,$result);
   $self->{"result"} = $result;
   if ($status == $self->LDAP_RES_SEARCH_RESULT)
   {
      $err = ldap_result2error($self->{"ld"},$self->{"result"},0);
      if ($err != $self->LDAP_SUCCESS)
      {
         $self->{"err"} = $err;
         $self->{"errstring"} = ldap_err2string($err);
      }
   }
   return $status;
}

sub result2error
{
   my ($self,$freeit) = @_;

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if (!$self->{"result"})
   {
      croak("No Current Result");
   }

   $self->{"err"} = ldap_result2error($self->{"ld"},$self->{"result"},$freeit);
   $self->{"errstring"} = ldap_err2string($self->{"err"});
   return $self->{"err"};
}

sub search
{
   my ($self,$basedn,$scope,$filter,$attrs,$attrsonly) = @_;
   my ($msgid,$errdn,$extramsg);

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP connection open");
   }

   if ($filter eq "")
   {
      croak("No Filter Passed as Argument 3");
   }

#   if ($basedn eq "")
#   {
#      croak("No Base DN Passed as Argument 1");
#   }
   $msgid = ldap_search($self->{"ld"},$basedn,$scope,$filter,$attrs,$attrsonly);

   if ($msgid < 0)
   {
      $self->{"errno"} = ldap_get_lderrno($self->{"ld"},$errdn,$extramsg);
      $self->{"errstring"} = ldap_err2string($self->{"errno"});
   }
   return($msgid);
}

sub search_s
{
   my ($self,$basedn,$scope,$filter,$attrs,$attrsonly) = @_;
   my ($result,$status,$errdn,$extramsg);

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP connection open");
   }

   if ($filter eq "")
   {
      croak("No Filter Passed as Argument 3");
   }

#   if ($basedn eq "")
#   {
#      croak("No Base DN Passed as Argument 1");
#   }

   $status = ldap_search_s($self->{"ld"},$basedn,$scope,$filter,$attrs,
      $attrsonly,$result);
   if ($status != $self->LDAP_SUCCESS)
   {
      $self->{"errno"} = ldap_get_lderrno($self->{"ld"},$errdn,$extramsg);
      $self->{"errstring"} = ldap_err2string($self->{"errno"});
   }
   $self->{"result"} = $result;
   return $status;
}   

sub search_st
{
   my ($self,$basedn,$scope,$filter,$attrs,$attrsonly,$timeout) = @_;
   my ($result,$status,$errdn,$extramsg);

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP connection open");
   }

   if ($filter eq "")
   {
      croak("No Filter Passed as Argument 3");
   }

#   if ($basedn eq "")
#   {
#      croak("No Base DN Passed as Argument 1");
#   }

   $status = ldap_search_st($self->{"ld"},$basedn,$scope,$filter,$attrs,
      $attrsonly,$result,$timeout);
   if ($status != $self->LDAP_SUCCESS)
   {
      $self->{"errno"} = ldap_get_lderrno($self->{"ld"},$errdn,$extramsg);
      $self->{"errstring"} = ldap_err2string($self->{"errno"});
   }
   $self->{"result"} = $result;
   return $status;
}

sub get_option
{
   my ($self,$option,$optdata) = @_;
   my ($status);

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP connection open");
   }

   $status = ldap_get_option($self->{"ld"},$option,$$optdata);

   return $status;
}

sub set_option
{
   my ($self,$option,$optdata) = @_;
   my ($status);

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP connection open");
   }

   $status = ldap_set_option($self->{"ld"},$option,$optdata);

   return $status;
}

sub set_rebind_proc
{
   my ($self,$rebindproc) = @_;
   my ($status);

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP connection open");
   }

   $status = ldap_set_rebind_proc($self->{"ld"},$rebindproc);
}

sub get_all_entries
{
   my ($self) = shift;
   my $record;

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   if ($self->{"result"} == 0)
   {
      croak("NULL Result");
   }

   $record = ldap_get_all_entries($self->{"ld"},$self->{"result"});
   return $record;
}

sub unbind
{
   my ($self) = @_;

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   ldap_unbind($self->{"ld"});
   $self = {};
}

sub ssl_client_init
{
   my ($self,$certdbpath,$certdbhandle) = @_;
   my ($status);

   $status = ldapssl_client_init($certdbpath,$certdbhandle);
   return($status);
}

sub ssl
{
   my ($self) = @_;
   my ($status);

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   $status = ldapssl_install_routines($self->{"ld"});
   return $status;
}

sub entry
{
   my ($self) = @_;
   if (not ref $self)
   {
      croak("$self is not a reference");
   }
   return $self->{"entry"};
}

sub err
{
   my ($self) = @_;
   if (not ref $self)
   {
      croak("$self is not a reference");
   }
   return $self->{"err"};
}

sub errstring
{
   my ($self) = @_;
   if (not ref $self)
   {
      croak("$self is not a reference");
   }
   return $self->{"errstring"};
}

sub ld
{
   my ($self) = @_;
   if (not ref $self)
   {
      croak("$self is not a reference");
   }
   return $self->{"ld"};
}

sub msgid
{
   my ($self) = @_;

   my ($msgid);

   if (not ref $self)
   {
      croak("$self is not a reference");
   }

   if ($self->{"ld"} == 0)
   {
      croak("No LDAP Connection Open");
   }

   $msgid = ldap_msgid($self->{"ld"},$self->{"result"});
   return $msgid;
} 

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

  This module allows Perl programmers to access and manipulate an LDAP
  based Directory.

  Versions beginning with 1.40 support both the original "C API" and
  new "Perl OO" style interface methods.

  The new "Perl OO" style interface methods are covered by the man page.
  The old manpage is included as a text file for those still using the old
  "C API" interface.

=head1 THE INTIAL CONNECTION

  All connections to the LDAP server are started by creating a new
  "blessed object" in the Net::LDAPapi class.  This can be done quite
  easily by the following type of statement.

  $ld = new Net::LDAPapi($hostname);

  Where $hostname is the name of your LDAP server.  If you are not using
  the standard LDAP port (389), you will also need to supply the portnumber.

  $ld = new Net::LDAPapi($hostname,15555);

=head1 BINDING

  After creating a connection to the LDAP server, you will always need to
  bind to the server prior to performing any LDAP related functions.  This
  can be done with the 'bind' methods.

  An anonymous bind can be performed without arguments:

  $status = $ld->bind_s;

  A simple bind can be performed by specifying the DN and PASSWORD of
  the user you are authenticating as:

  $status = $ld->bind_s($dn,$password);

  Note that if $password above was "", you would be doing a reference bind,
  which would return success even if the password in the directory was
  non-null.  Thus if you were using the bind to check a password entered
  with one in the directory, you should first check to see if $password was
  NULL.

  If your LDAP C Library supports Kerberos, you can also do Kerberos binds
  simply by adding the LDAP_AUTH_KRBV4 option.  For example:

  $status = $ld->bind_s($dn,$password,LDAP_AUTH_KRBV4);

  For all of the above operations, you could compare $status to LDAP_SUCCESS
  to see if the operation was successful.

  Additionally, you could use 'bind' rather than 'bind_s' if you wanted to
  use the Asynchronous LDAP routines.  The asynchronous routines would return
  a MSGID rather than a status.  To find the status of an Asynchronous bind,
  you would need to first obtain the result with a call to $ld->result.  See
  the entry for result later in the man page, as well as the 'ldapwalk.pl'
  example for further information on obtaining results from Asynchronous
  operations.
  

=head1 GENERATING AN ADD/MODIFY HASH

  For the add and modify routines you will need to generate
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

  Then remember to call the add or modify operations with a REFERENCE to
  this HASH.  Something like:

  $ld->modify_s($modify_dn,\%ldap_modifications);

=head1 GETTING/SETTING LDAP INTERNAL VALUES

  The following methods exist to obtain internal values within a
  Net::LDAPapi object:

  o err - The last error-number returned by the LDAP library for this
    connection.
          ex:  print "Error Number: " . $ld->err . "\n";

  o errstring - The string equivalent of 'err'.
          ex:  print "Error: " . $ld->errstring . "\n";

  o ld - Reference to the actual internal LDAP structure.  Only useful if
    you needed to obtain this pointer for use in non-OO routines.
          ex:  $ldptr = $ld->ld;
  
  o entry - Reference to the current entry.  Not typically needed, but method
    supplied, just in case.
          ex:  $entry = $ld->entry;

  o msgid - Get msgid from an LDAP Result.
          ex:  $msgid = $ld->msgid;  #  msgid of current result
          ex:  $msgid = $ld->msgid($result) # msgid of $result

  o msgtype - Get msgtype from an LDAP Result.
	  ex:  $msgtype = $ld->msgtype;  # msgtype of current result
          ex:  $msgtype = $ld->msgtype($result) # msgtype of $result

  These methods are only useful for GETTING internal information, not setting
  it.  No methods are currently available for SETTING these internal values.

=head1 GETTING AND SETTING LDAP SESSION OPTIONS

  The get_option and set_option methods can be used to get and set LDAP
  session options.

  The following LDAP options can be set or gotten with these methods:
	LDAP_OPT_DEREF - Dereference
	LDAP_OPT_SIZELIMIT - Maximum Number of Entries to Return
	LDAP_OPT_TIMELIMIT - Timeout for LDAP Operations
	LDAP_OPT_REFERRALS - Follow Referrals

  For both get and set operations, the first argument is the relivant
  option.  In get, the second argument is a reference to a scalar variable
  that will contain the current value of the option.  In set, the second
  argument is the value at which to set this option.

  Examples:
    $ld->set_option(LDAP_OPT_SIZELIMIT,50);
    $ld->get_option(LDAP_OPT_SIZELIMIT,\$size);

  When setting LDAP_OPT_REFERRALS, the second argument is either LDAP_OPT_ON
  or LDAP_OPT_OFF.  Other options require a number.

  Both get_option and set_option return 0 on success and non-zero otherwise.

=head1 SSL SUPPORT

  When compiled with the Netscape SDK, this module now supports SSL.
  I do not have an SSL capable server, but I'm told this works.  The
  functions available are:

  o ssl - Turn on SSL for this connection.
    Install I/O routines to make SSL over LDAP possible
  o ssl_client_init($certdbpath,$certdbhandle)
    Initialize the secure parts (called only once)

  Example:
    $ld = new Net::LDAPapi("host",LDAPS_PORT);
    $ld->ssl_client_init($certdbpath,$certdbhandle);
    $ld->ssl;

=head1 SETTING REBIND PROCESS

  The set_rebind_proc method is used to set a PERL function to supply DN,
  PASSWORD, and AUTHTYPE for use when the server rebinds (for referals,
  etc...).

  Usage should be something like:
    $ld->set_rebind_proc(\&my_rebind_proc);

  You can then create the procedure specified.  It should return 3 values.

  Example:
    sub my_rebind_proc
    {
       return($dn,$pass,LDAP_AUTH_SIMPLE);
    }


=head1 SUPPORTED METHODS

=item abandon MSGID

  This cancels an asynchronous LDAP operation that has not completed.  It
  returns an LDAP STATUS code upon completion.

  Example:

    $status = ldap_abandon($ld, $msgid);

=item add ENTRYDN ATTRIBUTES

  Begins an an asynchronous LDAP Add operation.  It returns a MSGID or -1
  upon completion.

  Example:

    %attributes = (
       "cn", ["Clayton Donley","Clay Donley"] #Add Multivalue cn
       "sn", "Donley",			      #Add sn
       "telephoneNumber", "+86-10-65551234",  #Add telephoneNumber
       "objectClass", ["person","organizationalPerson"],
                        # Add Multivalue objectClass
       "jpegphoto", {"b",[$jpegphoto]},  # Add Binary jpegphoto
    );

    $entrydn = "cn=Clayton Donley, o=Motorola, c=US";

    $msgid = $ld->add($entrydn, \%attributes);

  Note that in most cases, you will need to be bound to the LDAP server
  as an administrator in order to add users.

=item add_s ENTRYDN ATTRIBUTES

  Synchronous version of the 'add' method.  Arguments are identical
  to the 'add' method, but this operation returns an LDAP STATUS,
  not a MSGID.

  Example:

    $ld->add_s($entrydn, \%attributes);

  See the section on creating the modify structure for more information
  on populating the ATTRIBUTES field for Add and Modify operations.

=item bind DN CREDENTIALS METHOD

  Asynchronous method for binding to the LDAP server.  It returns a
  MSGID.

  Examples:

    $msgid = $ld->bind;
    $msgid = $ld->bind("cn=Clayton Donley, o=Motorola, c=US", "abc123");


=item bind_s DN CREDENTIALS METHOD

  Synchronous method for binding to the LDAP server.  It returns
  an LDAP STATUS. 

  Examples:

    $status = $ld->bind_s;
    $status = $ld->bind_s("cn=Clayton Donley, o=Motorola, c=US", "abc123");


=item compare ENTRYDN TYPE VALUE

  Asynchronous method for comparing a value with the value contained
  within ENTRYDN.  Returns a MSGID.

  Example:

    $msgid = $ld->compare("cn=Clayton Donley, o=Motorola, c=US", \
		$type,$value);

=item compare_s ENTRYDN TYPE VALUE

  Synchronous method for comparing a value with the value contained
  within ENTRYDN.  Returns an LDAP STATUS.

  Example:

    $status = $ld->compare_s("cn=Clayton Donley, o=Motorola, c=US", \
		$type, $value);


=item count_entries

  Calculates and returns the number of entries in an LDAP result chain.

  Example:

    $number = $ld->count_entries;

=item delete ENTRYDN

  Asynchronous method to delete ENTRYDN.  Returns a MSGID or -1 if error.

  Example:

    $msgid = $ld->delete("cn=Clayton Donley, o=Motorola, c=US");

=item delete_s ENTRYDN

  Synchronous method to delete ENTRYDN.  Returns an LDAP STATUS.

  Example:

    $status = $ld->delete_s("cn=Clayton Donley, o=Motorola, c=US");

=item dn2ufn DN

  Converts a Distinguished Name (DN) to a User Friendly Name (UFN).
  Returns a string with the UFN.

  Since this operation doesn't require an LDAP object to work, you
  could technically access the function directly as 'ldap_dn2ufn' rather
  that the object oriented form.

  Example:

    $ufn = $ld->dn2ufn("cn=Clayton Donley, o=Motorola, c=US");

=item explode_dn DN NOTYPES

  Splits the DN into an array comtaining the separate components of
  the DN.  Returns an Array.  NOTYPES is a 1 to remove attribute
  types and 0 to retain attribute types.

  Can also be accessed directly as 'ldap_explode_dn' if no session is
  initialized and you don't want the object oriented form.

  Only available when compiled with Netscape SDK.

  Example:

    @components = $ld->explode_dn($dn,0);

=item explode_rdn RDN NOTYPES

  Same as explode_dn, except that the first argument is a
  Relative Distinguished Name.  NOTYPES is a 1 to remove attribute
  types and 0 to retain attribute types.  Returns an array with
  each component.

  Can also be accessed directly as 'ldap_explode_rdn' if no session is
  initialized and you don't want the object oriented form.

  Only available with Netscape SDK.

  Example:

    @components = $ld->explode_rdn($rdn,0);

=item first_attribute

  Returns pointer to first attribute name found in the current entry.
  Note that this only returning attribute names (ex: cn, mail, etc...).
  Returns a string with the attribute name.

  Returns an empty string when no attributes are available.

  Example:

    $attr = $ld->first_attribute;

=item first_entry

  Sets internal pointer to the first entry in a chain of results.  Returns
  an empty string when no entries are available.

  Example:

    $entry = $ld->first_entry;

=item get_dn

  Returns a string containing the DN for the specified entry or an
  empty string if an error occurs.

  Example:

    $dn = $ld->get_dn;

=item get_values ATTRIBUTE

  Obtain a list of all values associated with a given attribute.
  Returns an empty list if none are available.

  Example:

    @values = $ld->get_values("cn");

  This would put all the 'cn' values for $entry into the array @values.

=item get_values_len SESSION ENTRY ATTRIBUTE

  Retrieves a set of binary values for the specified attribute.

  Example:

    @values = $ld->get_values_len("jpegphoto");

  This would put all the 'jpegphoto' values for $entry into the array @values.
  These could then be written to a file, or further processed.


=item msgfree

  Frees the current LDAP result.  Returns the type of message freed.

  Example:

    $type = $ld->msgfree;

=item modify ENTRYDN MODS

  Asynchronous method to modify an LDAP entry.  ENTRYDN is the DN to
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

    $msgid = $ld->modify($entrydn,\%mods);

  The above would remove the telephoneNumber attribute from the entry
  and replace the "sn" attribute with "Test".  The value in the "mail"
  attribute for this entry would be replaced with both addresses
  specified in @mail.  The "jpegphoto" attribute would be replaced with
  the binary data in $jpegphoto.

=item modify_s ENTRYDN MODS

  Synchronous version of modify method.  Returns an LDAP STATUS.  See the
  modify method for notes and examples of populating the MODS
  parameter.

  Example:

    $status = $ld->modify_s($entrydn,\%mods);

=item modrdn2 ENTRYDN NEWRDN DELETEOLDRDN

  Asynchronous method to change the name of an entry.  DELETEOLDRDN
  is non-zero if you wish to remove the attribute values from the
  old name.  Returns a MSGID.

  Example:

    $msgid = $ld->modrdn2("cn=Clayton Donley, o=Motorola, c=US", \
		"cn=Clay Donley",0);

=item modrdn2_s ENTRYDN NEWRDN DELETEOLDRDN

  Synchronous method to change the name of an entry.  DELETEOLDRDN is
  non-zero if you wish to remove the attribute values from the old
  name.  Returns an LDAP STATUS.

  Example:

    $status = $ld->modrdn2_s("cn=Clayton Donley, o=Motorola, c=US", \
		"cn=Clay Donley",0);

=item next_attribute

  Similar to first_attribute, but obtains next attribute.
  Returns a string comtaining the attribute name.  An empty string
  is returned when no further attributes exist.

  Example:

    $attr = $ld->next_attribute;

=item next_entry

  Moves internal pointer to the next entry in a chain of search results.

  Example:

    $entry = $ld->next_entry;

=item perror STRING

  If an error occurs while performing an LDAP function, this procedure
  will display it.  You can also use the err and errstring methods to
  manipulate the error number and error string in other ways.

  Note that this function does NOT terminate your program.  You would
  need to do any cleanup work on your own.

  Example:

    $ld->perror("add_s");

=item result MSGID ALL TIMEOUT

  Retrieves the result of an operation initiated using an asynchronous
  LDAP call.  Returns the type of result returned or -1 if error.

  MSGID is the MSGID returned by the Asynchronous LDAP call.  Set ALL to
  0 to receive entries as they arrive, or non-zero to receive all entries
  before returning.  Set TIMEOUT to the number of seconds to wait for the
  result, or -1 for no timeout.

  Example:

    $type = $ld->result($msgid,0,1);

=item result2error FREEIT

  Returns the LDAP error code from an LDAP result message.  FREEIT will
  free the memory occupied by the result if set non-zero.

  This routine also updates message returned by err and errstring
  methods.

  Example:

    $lderrno = $ld->result2error(0);

=item search BASE SCOPE FILTER ATTRS ATTRSONLY

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

    $msgid = $ld->search("o=Motorola, c=US",LDAP_SCOPE_SUBTREE, \
		"(sn=Donley),\@attrs,0);

=item search_s BASE SCOPE FILTER ATTRS ATTRSONLY

  Performs a synchronous LDAP search.  Returns an LDAP STATUS.  BASE
  is the base object for the search operation.  FILTER is a string
  containing an LDAP search filter.  ATTRS is a reference to an array
  containing the attributes to return.  An empty array would return all
  attributes.  ATTRSONLY set to non-zero will only obtain the attribute
  types without values.

  SCOPE is one of the following:
		LDAP_SCOPE_BASE
		LDAP_SCOPE_ONELEVEL
		LDAP_SCOPE_SUBTREE

  Example:

    @attrs = ("cn","sn");    # Return specific attributes
    @attrs = ();             # Return all attributes

    $status = $ld->search_s("o=Motorola, c=US",LDAP_SCOPE_SUBTREE, \
		"(sn=Donley)",\@attrs,0);

=item search_st BASE SCOPE FILTER ATTRS ATTRSONLY TIMEOUT

  Performs a synchronous LDAP search with a TIMEOUT.  See search_s
  for a description of parameters.  Returns an LDAP STATUS.  Results are
  put into RESULTS.  TIMEOUT is a number of seconds to wait before giving
  up, or -1 for no timeout.

  Example:

    $status = $ld->search_st("o=Motorola, c=US",LDAP_SCOPE_SUBTREE, \
		"(sn=Donley),[],0,3);

=item unbind SESSION

  Unbind LDAP connection with specified SESSION handler.

  Example:

    $ld->unbind;

=head1 AUTHOR

Clayton Donley, donley@wwa.com
http://miso.wwa.com/~donley/

=head1 SEE ALSO

perl(1).

=cut
