#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#ifdef __cplusplus
}
#endif

#include <lber.h>
#include <ldap.h>

/* Netscape prototypes declare things as "const char *" while   */
/*      UM-LDAP uses "char *"                                   */
	
#ifdef NETSCAPE_LDAP
 #define LDAP_CHAR const char
 #include <ldap_ssl.h>
#else
 #include "ldap_compat.h"
 #define LDAP_CHAR char
 #if defined(ISODE_LDAP) && !defined(IC_LDAP_CONFIG_H)
 # define ISODE8_LDAP
 #endif
#endif


/* Function Prototypes for Internal Functions */

static char **av2modvals(AV *ldap_value_array_av, int ldap_isa_ber);
static LDAPMod *parse1mod(SV *ldap_value_ref,char *ldap_current_attribute,
	int ldap_add_func);
static LDAPMod **hash2mod(HV *ldap_change,int ldap_add_func);

#ifdef NETSCAPE_LDAP
   static int internal_rebind_proc(LDAP *ld, char **dnp, char **pwp,
	   int *authmethodp, int freeit, void *arg);
   static int LDAP_CALL ns_internal_rebind_proc(LDAP *ld, char **dnp,
            char **pwp, int *authmethodp, int freeit, void *arg)
   {
      return internal_rebind_proc(ld,dnp,pwp,authmethodp,freeit,arg);
   }
#else
   static int internal_rebind_proc(LDAP *ld, char **dnp, char **pwp,
	   int *authmethodp, int freeit);
#endif

/* The Name of the PERL function to return DN, PASSWD, AUTHTYPE on Rebind */
/* Set using 'set_rebind_proc()' */
SV *ldap_perl_rebindproc = NULL;


/* ISODE8 doesn't include the ldap_mods_free function */

#ifdef ISODE8_LDAP
   #define ldap_mods_free(x,y) safefree(x);
#endif


/* Use constant.h generated from constant.gen */
/* Courtesy of h.b.furuseth@usit.uio.no       */

#include "constant.h"

/* av2modvals - Takes a single Array Reference (AV *) and returns */
/*    a null terminated list of char pointers.                    */

static
char **av2modvals(AV *ldap_value_array_av, int ldap_isa_ber)
{
   I32 ldap_arraylen;
   char **ldap_ch_modvalues = NULL;
   char *ldap_current_value_char = NULL;
   struct berval **ldap_bv_modvalues = NULL;
   struct berval *ldap_current_bval = NULL;
   SV **ldap_current_value_sv;
   int ldap_value_count = 0,ldap_pvlen;

   ldap_arraylen = av_len(ldap_value_array_av);
   if (ldap_arraylen < 0)
      return(NULL);

   if (ldap_isa_ber == 1)
   {
      ldap_bv_modvalues =
	(struct berval **)safemalloc((2+ldap_arraylen)*sizeof(struct berval *));
   } else {
      ldap_ch_modvalues = (char **)safemalloc((2+ldap_arraylen)*sizeof(char *));
   }
   for (ldap_value_count = 0; ldap_value_count <=ldap_arraylen;
	ldap_value_count++)
   {
      ldap_current_value_sv = av_fetch(ldap_value_array_av,ldap_value_count,0);
      ldap_current_value_char = SvPV(*ldap_current_value_sv,na);
      ldap_pvlen = SvCUR(*ldap_current_value_sv);
      if (ldap_isa_ber == 1)
      {
	 ldap_current_bval =
	   (struct berval *)safemalloc(sizeof(struct berval));
	 ldap_current_bval->bv_len = ldap_pvlen;
	 ldap_current_bval->bv_val = ldap_current_value_char;
	 ldap_bv_modvalues[ldap_value_count] = ldap_current_bval;
      } else {
         ldap_ch_modvalues[ldap_value_count] = ldap_current_value_char;
      }
      /* if (ldap_current_value_char != NULL)
         safefree(ldap_current_value_char);
      if (ldap_current_value_sv != NULL)
         safefree(ldap_current_value_sv); */
   }
   if (ldap_isa_ber == 1)
   {
      ldap_bv_modvalues[ldap_value_count] = NULL;
      return ((char **)ldap_bv_modvalues);
   } else {
      ldap_ch_modvalues[ldap_value_count] = NULL;
      return (ldap_ch_modvalues);
   }
}


/* parse1mod - Take a single reference, figure out if it is a HASH, */
/*   ARRAY, or SCALAR, then extract the values and attributes and   */
/*   return a single LDAPMod pointer to this data.                  */

static
LDAPMod *parse1mod(SV *ldap_value_ref,char *ldap_current_attribute,
   int ldap_add_func)
{
   LDAPMod *ldap_current_mod = safemalloc(sizeof(LDAPMod));
   HV *ldap_current_values_hv;
   HE *ldap_change_element;
   char *ldap_current_modop;
   SV *ldap_current_value_sv;
   I32 keylen;
   int ldap_isa_ber = 0;
 
   if (ldap_current_attribute == NULL)
      return(NULL);
   ldap_current_mod->mod_type = ldap_current_attribute;
   if (SvROK(ldap_value_ref))
   {
     if (SvTYPE(SvRV(ldap_value_ref)) == SVt_PVHV)
     {
      ldap_current_values_hv = (HV *) SvRV(ldap_value_ref);
      hv_iterinit(ldap_current_values_hv);
      if ((ldap_change_element = hv_iternext(ldap_current_values_hv)) == NULL)
	 return(NULL);
      ldap_current_modop = hv_iterkey(ldap_change_element,&keylen);
      ldap_current_value_sv = hv_iterval(ldap_current_values_hv,
	ldap_change_element);
      if (ldap_add_func == 1)
      {
	 ldap_current_mod->mod_op = 0;
      } else {
	 if (strchr(ldap_current_modop,'a') != NULL)
	 {
	    ldap_current_mod->mod_op = LDAP_MOD_ADD;
	 } else if (strchr(ldap_current_modop,'r') != NULL)
	 {
	    ldap_current_mod->mod_op = LDAP_MOD_REPLACE;
	 } else if (strchr(ldap_current_modop,'d') != NULL) {
	    ldap_current_mod->mod_op = LDAP_MOD_DELETE;
	 } else {
	    return(NULL);
	 }
      }
      if (strchr(ldap_current_modop,'b') != NULL)
      {
	 ldap_isa_ber = 1;
	 ldap_current_mod->mod_op = ldap_current_mod->mod_op | LDAP_MOD_BVALUES;
      }
      if (SvTYPE(SvRV(ldap_current_value_sv)) == SVt_PVAV)
      {
	 if (ldap_isa_ber == 1)
	 {
	    ldap_current_mod->mod_values =
	      av2modvals((AV *)SvRV(ldap_current_value_sv),ldap_isa_ber);
	 } else {
	    ldap_current_mod->mod_values =
	      av2modvals((AV *)SvRV(ldap_current_value_sv),ldap_isa_ber);
	 }
      }
     } else if (SvTYPE(SvRV(ldap_value_ref)) == SVt_PVAV) {
      ldap_current_mod->mod_op = LDAP_MOD_REPLACE;
      ldap_current_mod->mod_type = ldap_current_attribute;
      ldap_current_mod->mod_values = av2modvals((AV *)SvRV(ldap_value_ref),0);
      if (ldap_current_mod->mod_values == NULL)
      {
	 ldap_current_mod = NULL;
      }
     }
   } else {
      if (strcmp(SvPV(ldap_value_ref,na),"") == 0)
      {
	 ldap_current_mod->mod_op = LDAP_MOD_DELETE;
	 ldap_current_mod->mod_type = ldap_current_attribute;
	 ldap_current_mod->mod_values = NULL;
      } else {
	 ldap_current_mod->mod_op = LDAP_MOD_REPLACE;
	 ldap_current_mod->mod_type = ldap_current_attribute;
	 ldap_current_mod->mod_values = (char **)safemalloc(2*sizeof(char *));
	 ldap_current_mod->mod_values[0] = SvPV(ldap_value_ref,na);
	 ldap_current_mod->mod_values[1] = NULL;
      }
   }
   return(ldap_current_mod);
}


/* hash2mod - Cycle through all the keys in the hash and properly call */
/*    the appropriate functions to build a NULL terminated list of     */
/*    LDAPMod pointers.                                                */

static
LDAPMod ** hash2mod(HV *ldap_change,int ldap_add_func)
{
   LDAPMod **ldapmod = NULL;
   LDAPMod *ldap_current_mod;
   int ldap_attribute_count = 0;
   HE *ldap_change_element;
   char *ldap_current_attribute;
   SV *ldap_current_value_sv;
   I32 keylen;

   hv_iterinit(ldap_change);
   while((ldap_change_element = hv_iternext(ldap_change)) != NULL)
   {
      ldap_current_attribute = hv_iterkey(ldap_change_element,&keylen);
      ldap_current_value_sv = hv_iterval(ldap_change,ldap_change_element);
      ldap_current_mod = parse1mod(ldap_current_value_sv,
	ldap_current_attribute,ldap_add_func);
      ldap_attribute_count = ldap_attribute_count + 1;
      ldapmod = (LDAPMod **)
      (ldapmod
	? saferealloc(ldapmod,(1+ldap_attribute_count)*sizeof(LDAPMod *))
	: safemalloc (        (1+ldap_attribute_count)*sizeof(LDAPMod *)));
      ldapmod[ldap_attribute_count - 1] =
	(LDAPMod *)safemalloc(sizeof(LDAPMod));
      Copy(ldap_current_mod,ldapmod[ldap_attribute_count-1],
	sizeof(LDAPMod *),LDAPMod *);
      if (ldap_current_mod != NULL)
	 safefree(ldap_current_mod);
   }
   ldapmod[ldap_attribute_count] = NULL;
   return ldapmod;
}

/* internal_rebind_proc - Wrapper to call a PERL rebind process             */
/*   ldap_set_rebind_proc is slightly different between Netscape and UMICH  */

int
#ifdef NETSCAPE_LDAP
internal_rebind_proc(LDAP *ld, char **dnp, char **pwp, int *authmethodp,
  int freeit, void *arg)
#else
internal_rebind_proc(LDAP *ld, char **dnp, char **pwp, int *authmethodp,
  int freeit)
#endif
{
   int count = 0;
   if (freeit == 0)
   {

      dSP;

      ENTER ;
      SAVETMPS ;

      count = perl_call_sv(ldap_perl_rebindproc,G_NOARGS);

      SPAGAIN;

      if (count != 3)
	 croak("ldap_perl_rebindproc: Expected DN, PASSWORD, and AUTHTYPE returned.\n");

      *dnp = strdup(SvPV(POPs,na));
      *pwp = strdup(SvPV(POPs,na));
      *authmethodp = POPi;

      FREETMPS ;
      LEAVE ;
   } else {
      if ( *dnp != NULL )
      {
	 safefree(*dnp);
	 safefree(*pwp);
      }
   }
   return(LDAP_SUCCESS);
}


MODULE = Net::LDAPapi           PACKAGE = Net::LDAPapi

PROTOTYPES: ENABLE

double
constant(name,arg)
	char *          name
	int             arg


LDAP *
ldap_open(host,port)
	LDAP_CHAR *     host
	int             port

LDAP *
ldap_init(defhost,defport)
	LDAP_CHAR *     defhost
	int             defport
	CODE:
	{
#ifdef ISODE8_LDAP
	   warn("ldap_init() not provided with isode-8 ldap.");
	   errno = EINVAL;
	   RETVAL = NULL;
#else
	   RETVAL = ldap_init(defhost, defport);
#endif
	}
	OUTPUT:
	RETVAL

#ifdef NETSCAPE_LDAP

int
ldap_set_option(ld,option,optdata)
	LDAP *          ld
	int             option
	int             optdata
	CODE:
	{
	   RETVAL = ldap_set_option(ld,option,&optdata);
	}
	OUTPUT:
	RETVAL

int
ldap_get_option(ld,option,optdata)
	LDAP *          ld
	int             option
	int             optdata = NO_INIT
	CODE:
	{
	   RETVAL = ldap_get_option(ld,option,&optdata);
	}
	OUTPUT:
	RETVAL
	optdata

#else

int
ldap_set_option(ld,option,optdata)
	LDAP *          ld
	int             option
	int             optdata
	CODE:
	{
	   RETVAL = 0;
	   switch (option)
	   {
	      case LDAP_OPT_DEREF: ld->ld_deref = optdata; break;
	      case LDAP_OPT_SIZELIMIT: ld->ld_sizelimit = optdata; break;
	      case LDAP_OPT_TIMELIMIT: ld->ld_timelimit = optdata; break;
	      case LDAP_OPT_REFERRALS: if (optdata == LDAP_OPT_ON)
		    ld->ld_options &= LDAP_OPT_REFERRALS; else 
		      ld->ld_options &= ~LDAP_OPT_REFERRALS; break;
	      break;
	   }
	}
	OUTPUT:
	RETVAL

int
ldap_get_option(ld,option,optdata)
	LDAP *          ld
	int             option
	int             optdata = NO_INIT
	CODE:
	{
	   RETVAL = 0;
	   switch (option)
	   {
	      case LDAP_OPT_DEREF: optdata = ld->ld_deref; break;
	      case LDAP_OPT_SIZELIMIT: optdata = ld->ld_sizelimit; break;
	      case LDAP_OPT_TIMELIMIT: optdata = ld->ld_timelimit; break;
	      case LDAP_OPT_REFERRALS: if (ld->ld_options & LDAP_OPT_REFERRALS)
		    optdata = LDAP_OPT_ON; else optdata = LDAP_OPT_OFF;
		    break;
	      break;
	   }
	}
	OUTPUT:
	RETVAL
	optdata
	

#endif

int
ldap_unbind(ld)
	LDAP *          ld
	
int
ldap_unbind_s(ld)
	LDAP *          ld

#ifdef NETSCAPE_LDAP

int
ldap_version(ver)
	LDAPVersion     *ver

#endif

int
ldap_abandon(ld,msgid)
	LDAP *          ld
	int             msgid

int
ldap_add(ld,dn,ldap_change_ref)
	LDAP *          ld
	LDAP_CHAR *     dn
	SV *            ldap_change_ref
	CODE:
	{
	   LDAPMod **mods;

	   if (SvTYPE(SvRV(ldap_change_ref)) != SVt_PVHV)
	   {
	      croak("Net::LDAPapi::ldap_add needs HASH reference as argument 3.");
	      XSRETURN(1);
	   }
	   mods = hash2mod((HV *)SvRV(ldap_change_ref),1);
	   RETVAL = ldap_add(ld,dn,mods);
	   /* ldap_mods_free(mods,0); */
	}
	OUTPUT:
	RETVAL

int
ldap_add_s(ld,dn,ldap_change_ref)
	LDAP *          ld
	LDAP_CHAR *     dn
	SV *            ldap_change_ref
	CODE:
	{
	   LDAPMod **mods;

	   if (SvTYPE(SvRV(ldap_change_ref)) != SVt_PVHV)
	   {
	      croak("Net::LDAPapi::ldap_add_s needs HASH reference as argument 3.");
	      XSRETURN(1);
	   }
	   mods = hash2mod((HV *)SvRV(ldap_change_ref),1);
	   RETVAL = ldap_add_s(ld,dn,mods);
	   /* ldap_mods_free(mods,0); */
	}
	OUTPUT:
	RETVAL

int
ldap_bind(ld,who,passwd,type)
	LDAP *          ld
	LDAP_CHAR *     who
	LDAP_CHAR *     passwd
	int             type

int
ldap_bind_s(ld,who,passwd,type)
	LDAP *          ld
	LDAP_CHAR *     who
	LDAP_CHAR *     passwd
	int             type

int
ldap_simple_bind(ld,who,passwd)
	LDAP *          ld
	LDAP_CHAR *     who
	LDAP_CHAR *     passwd

int
ldap_simple_bind_s(ld,who,passwd)
	LDAP *          ld
	LDAP_CHAR *     who
	LDAP_CHAR *     passwd

int
ldap_modify(ld,dn,ldap_change_ref)
	LDAP *          ld
	LDAP_CHAR *     dn
	SV *            ldap_change_ref
	CODE:
	{
	   LDAPMod **mods;

	   if (SvTYPE(SvRV(ldap_change_ref)) != SVt_PVHV)
	   {
	      croak("Net::LDAPapi::ldap_modify needs HASH reference as argument 3.");
	      XSRETURN(1);
	   }
	   mods = hash2mod((HV *)SvRV(ldap_change_ref),0);
	   RETVAL = ldap_modify(ld,dn,mods);
	   /* ldap_mods_free(mods,0); */
	}
	OUTPUT:
	RETVAL

int
ldap_modify_s(ld,dn,ldap_change_ref)
	LDAP *          ld
	LDAP_CHAR *     dn
	SV *            ldap_change_ref
	CODE:
	{
	   LDAPMod **mods;

	   if (SvTYPE(SvRV(ldap_change_ref)) != SVt_PVHV)
	   {
	      croak("Net::LDAPapi::ldap_modify_s needs HASH reference as argument 3.");
	      XSRETURN(1);
	   }
	   mods = hash2mod((HV *)SvRV(ldap_change_ref),0);
	   RETVAL = ldap_modify_s(ld,dn,mods);
	   /* ldap_mods_free(mods,0); */
	}
	OUTPUT:
	RETVAL

int
ldap_modrdn(ld,dn,newrdn)
	LDAP *          ld
	LDAP_CHAR *     dn
	LDAP_CHAR *     newrdn

int
ldap_modrdn_s(ld,dn,newrdn)
	LDAP *          ld
	LDAP_CHAR *     dn
	LDAP_CHAR *     newrdn

int
ldap_modrdn2(ld,dn,newrdn,deleteoldrdn)
	LDAP *          ld
	LDAP_CHAR *     dn
	LDAP_CHAR *     newrdn
	int             deleteoldrdn

int
ldap_modrdn2_s(ld,dn,newrdn,deleteoldrdn)
	LDAP *          ld
	LDAP_CHAR *     dn
	LDAP_CHAR *     newrdn
	int             deleteoldrdn

int
ldap_compare(ld,dn,attr,value)
	LDAP *          ld
	LDAP_CHAR *     dn
	LDAP_CHAR *     attr
	LDAP_CHAR *     value

int
ldap_compare_s(ld,dn,attr,value)
	LDAP *          ld
	LDAP_CHAR *     dn
	LDAP_CHAR *     attr
	LDAP_CHAR *     value

int
ldap_delete(ld,dn)
	LDAP *          ld
	LDAP_CHAR *     dn

int
ldap_delete_s(ld,dn)
	LDAP *          ld
	LDAP_CHAR *     dn

int
ldap_search(ld,base,scope,filter,attrs,attrsonly)
	LDAP *          ld
	LDAP_CHAR *     base
	int             scope
	LDAP_CHAR *     filter
	SV *            attrs
	int             attrsonly
	CODE:
	{
	   char **attrs_char;
	   SV **current;
	   int arraylen,count;

	   if (SvTYPE(SvRV(attrs)) != SVt_PVAV)
	   {
	      croak("Net::LDAPapi::ldap_search needs ARRAY reference as argument 5.");
	      XSRETURN(1);
	   }
	   if ((arraylen = av_len((AV *)SvRV(attrs))) < 0)
	   {
	      attrs_char = (char **)safemalloc(2 * sizeof(char *));
	      attrs_char[0] = NULL;
	   } else {
	      attrs_char = (char **)safemalloc((arraylen+2)*sizeof(char *));
	      for (count=0;count <= arraylen; count++)
	      {
		 current = av_fetch((AV *)SvRV(attrs),count,0);
		 attrs_char[count] = SvPV(*current,na);
	      }
	      attrs_char[arraylen+1] = NULL;
	   }
	   RETVAL = ldap_search(ld,base,scope,filter,attrs_char,attrsonly);
	   safefree(attrs_char);
	}
	OUTPUT:
	RETVAL

int
ldap_search_s(ld,base,scope,filter,attrs,attrsonly,res)
	LDAP *          ld
	LDAP_CHAR *     base
	int             scope
	LDAP_CHAR *     filter
	SV *            attrs
	int             attrsonly
	LDAPMessage *   res = NO_INIT
	CODE:
	{
	   char **attrs_char;
	   SV **current;
	   int arraylen,count;

	   if (SvTYPE(SvRV(attrs)) == SVt_PVAV)
	   {
	      if ((arraylen = av_len((AV *)SvRV(attrs))) < 0)
	      {
		 attrs_char = (char **)safemalloc(2*sizeof(char *));
		 attrs_char[0] = NULL;
	      } else {
		 attrs_char = (char **)safemalloc((arraylen+2)*sizeof(char *));
		 for (count=0;count <= arraylen; count++)
		 {
		    current = av_fetch((AV *)SvRV(attrs),count,0);
		    attrs_char[count] = SvPV(*current,na);
		 }
		 attrs_char[arraylen+1] = NULL;
	      }
	   } else {
	      croak("Net::LDAPapi::ldap_search_s needs ARRAY reference as argument 5.");
	      XSRETURN(1);
	   }
	   RETVAL = ldap_search_s(ld,base,scope,filter,attrs_char,attrsonly,&res);
	   safefree(attrs_char);
	}
	OUTPUT:
	RETVAL
	res

int
ldap_search_st(ld,base,scope,filter,attrs,attrsonly,timeout,res)
	LDAP *          ld
	LDAP_CHAR *    base
	int             scope
	LDAP_CHAR *    filter
	SV *            attrs
	int             attrsonly
	LDAP_CHAR *     timeout
	LDAPMessage *   res = NO_INIT
	CODE:
	{
	   struct timeval *tv_timeout = NULL, timeoutbuf;
	   char **attrs_char;
	   SV **current;
	   int arraylen,count;

	   if (SvTYPE(SvRV(attrs)) != SVt_PVAV)
	   {
	      croak("Net::LDAPapi::ldap_search_st needs ARRAY reference as argument 5.");
	      XSRETURN(1);
	   }
	   if ((arraylen = av_len((AV *)SvRV(attrs))) < 0)
	   {
	      attrs_char = (char **)safemalloc(2*sizeof(char *));
	      attrs_char[0] = NULL;
	   } else {
	      attrs_char = (char **)safemalloc((arraylen+2)*sizeof(char *));
	      for (count=0;count <= arraylen; count++)
	      {
		 current = av_fetch((AV *)SvRV(attrs),count,0);
		 attrs_char[count] = SvPV(*current,na);
	      }
	      attrs_char[arraylen+1] = NULL;
	   }
	   if (timeout && *timeout)
	   {
	      tv_timeout = &timeoutbuf;
	      tv_timeout->tv_sec = atof(timeout);
	      tv_timeout->tv_usec = 0;
	   }
	   RETVAL = ldap_search_st(ld,base,scope,filter,attrs_char,attrsonly,
		tv_timeout,&res);
	}
	OUTPUT:
	RETVAL
	res

int
ldap_result(ld,msgid,all,timeout,result)
	LDAP *          ld
	int             msgid
	int             all
	LDAP_CHAR *     timeout
	LDAPMessage *   result = NO_INIT
	CODE:
	{
	   struct timeval *tv_timeout = NULL,timeoutbuf;
	   if (atof(timeout) > 0 && timeout && *timeout)
	   {
	      tv_timeout = &timeoutbuf;
	      tv_timeout->tv_sec = atof(timeout);
	      tv_timeout->tv_usec = 0;
	   }
	   RETVAL = ldap_result(ld,msgid,all,tv_timeout,&result);
	}
	OUTPUT:
	RETVAL
	result

int
ldap_msgfree(lm)
	LDAPMessage *   lm

void
ber_free(ber,freebuf)
	BerElement *ber
	int freebuf

#ifdef NETSCAPE_LDAP

int
ldap_msgid(lm)
	LDAPMessage *   lm

int
ldap_msgtype(lm)
	LDAPMessage *   lm

int
ldap_get_lderrno(ld,m,s)
	LDAP *          ld
	char *          m = NO_INIT
	char *          s = NO_INIT
	CODE:
	{
	   RETVAL = ldap_get_lderrno(ld,&m,&s);
	}
	OUTPUT:
	RETVAL
	m
	s

int
ldap_set_lderrno(ld,e,m,s)
	LDAP *          ld
	int             e
	char *          m
	char *          s

#else

int
ldap_msgid(lm)
	LDAPMessage *   lm
	CODE:
	{
	   RETVAL = lm->lm_msgid;
	}
	OUTPUT:
	RETVAL

int
ldap_msgtype(lm)
	LDAPMessage *   lm
	CODE:
	{
	   RETVAL = lm->lm_msgtype;
	}
	OUTPUT:
	RETVAL

int
ldap_get_lderrno(ld,m,s)
	LDAP *          ld
	char *          m = NO_INIT
	char *          s = NO_INIT
	CODE:
	{
	   RETVAL = ld->ld_errno;
	   m = ld->ld_matched;
	   s = ld->ld_error;
	}
	OUTPUT:
	RETVAL
	m
	s

int
ldap_set_lderrno(ld,e,m,s)
	LDAP *          ld
	int             e
	char *          m
	char *          s
	CODE:
	{
	   RETVAL = 0;
	   ld->ld_errno = e;
	   ld->ld_matched = m;
	   ld->ld_error = s;
	}
	OUTPUT:
	RETVAL

#endif

int
ldap_result2error(ld,r,freeit)
	LDAP *          ld
	LDAPMessage *   r
	int             freeit

char *
ldap_err2string(err)
	int err

int
ldap_count_entries(ld,result)
	LDAP *          ld
	LDAPMessage *   result

LDAPMessage *
ldap_first_entry(ld,result)
	LDAP *          ld
	LDAPMessage *   result

LDAPMessage *
ldap_next_entry(ld,preventry)
	LDAP *          ld
	LDAPMessage *   preventry

char *
ldap_get_dn(ld,entry)
	LDAP *          ld
	LDAPMessage *   entry
	PREINIT:
	   char * dn;
	CODE:
	{
	   dn = ldap_get_dn(ld, entry);
	   RETVAL = dn;
	}
	OUTPUT:
	RETVAL

void
ldap_perror(ld,s)
	LDAP *          ld
	LDAP_CHAR *     s


char *
ldap_dn2ufn(dn)
	LDAP_CHAR *     dn

#ifdef NETSCAPE_LDAP

void
ldap_explode_dn(dn,notypes)
	char *          dn
	int             notypes
	PPCODE:
	{
	   char ** LDAPGETVAL;
	   int i;

	   if ((LDAPGETVAL = ldap_explode_dn(dn,notypes)) != NULL)
	   {
	       for (i = 0; LDAPGETVAL[i] != NULL; i++)
	       {
		  EXTEND(sp,1);
		  PUSHs(sv_2mortal(newSVpv(LDAPGETVAL[i],strlen(LDAPGETVAL[i]))));
	       }
	      ldap_value_free(LDAPGETVAL);
	   }
	}

void
ldap_explode_rdn(dn,notypes)
	char *          dn
	int     notypes
	PPCODE:
	{
	   char ** LDAPGETVAL;
	   int i;

	   if ((LDAPGETVAL = ldap_explode_rdn(dn,notypes)) != NULL)
	   {
	       for (i = 0; LDAPGETVAL[i] != NULL; i++)
	       {
		  EXTEND(sp,1);
		  PUSHs(sv_2mortal(newSVpv(LDAPGETVAL[i],strlen(LDAPGETVAL[i]))));
	       }
	      ldap_value_free(LDAPGETVAL);
	   }
	}

void
ldap_explode_dns(dn)
	char *          dn
	PPCODE:
	{
	   char ** LDAPGETVAL;
	   int i;

	   if ((LDAPGETVAL = ldap_explode_dns(dn)) != NULL)
	   {
	       for (i = 0; LDAPGETVAL[i] != NULL; i++)
	       {
		  EXTEND(sp,1);
		  PUSHs(sv_2mortal(newSVpv(LDAPGETVAL[i],strlen(LDAPGETVAL[i]))));
	       }
	      ldap_value_free(LDAPGETVAL);
	   }
	}

#endif

char *
ldap_first_attribute(ld,entry,ber)
	LDAP *          ld
	LDAPMessage *   entry
	BerElement *    ber = NO_INIT
	CODE:
	{
	   RETVAL = ldap_first_attribute(ld,entry,&ber);
	}
	OUTPUT:
	RETVAL
	ber

char *
ldap_next_attribute(ld,entry,ber)
	LDAP *          ld
	LDAPMessage *   entry
	BerElement *    ber
	CODE:
	{
	   RETVAL = ldap_next_attribute(ld,entry,ber);
	}
	OUTPUT:
	RETVAL
	ber


void
ldap_get_values(ld,entry,attr)
	LDAP *          ld
	LDAPMessage *   entry
	char *          attr
	PPCODE:
	{
	   char ** LDAPGETVAL;
	   int i;

	   if ((LDAPGETVAL = ldap_get_values(ld,entry,attr)) != NULL)
	   {
	      for (i = 0; LDAPGETVAL[i] != NULL; i++)
	      {
	         EXTEND(sp,1);
	         PUSHs(sv_2mortal(newSVpv(LDAPGETVAL[i],strlen(LDAPGETVAL[i]))));
	      }
	      ldap_value_free(LDAPGETVAL);
	   }
	}

void
ldap_get_values_len(ld,entry,attr)
	LDAP *          ld
	LDAPMessage *   entry
	char *          attr
	PPCODE:
	{
	   struct berval ** LDAPGETVAL;
	   int i;

	   if ((LDAPGETVAL = ldap_get_values_len(ld,entry,attr)) != NULL)
	   {
	       for (i = 0; LDAPGETVAL[i] != NULL; i++)
	       {
		  EXTEND(sp,1);
		  PUSHs(sv_2mortal(newSVpv(LDAPGETVAL[i]->bv_val,LDAPGETVAL[i]->bv_len)));
	       }
	   }
	}

#ifdef NETSCAPE_LDAP

int
ldapssl_client_init(certdbpath,certdbhandle)
	char *          certdbpath
	void *          certdbhandle

LDAP *
ldapssl_init(defhost,defport,defsecure)
	char *          defhost
	int             defport
	int             defsecure

int
ldapssl_install_routines(ld)
	LDAP *          ld

#endif

void
ldap_set_rebind_proc(ld,rebind_function)
	LDAP *          ld
	SV *            rebind_function
	CODE:
	{
	   if (rebind_function == NULL)
	   {
#ifdef NETSCAPE_LDAP
	      ldap_set_rebind_proc(ld,NULL,NULL);
#else
	      ldap_set_rebind_proc(ld,NULL);
#endif
	   } else {
	      ldap_perl_rebindproc = rebind_function;
#ifdef NETSCAPE_LDAP
	      ldap_set_rebind_proc(ld,ns_internal_rebind_proc,NULL);
#else
	      ldap_set_rebind_proc(ld,internal_rebind_proc);
#endif
	   }
	}

HV *
ldap_get_all_entries(ld,result)
	LDAP *          ld
	LDAPMessage *   result
	CODE:
	{
	   LDAPMessage *entry = NULL;
	   char *dn = NULL, *attr = NULL;
	   struct berval **vals = NULL;
	   BerElement *ber = NULL;
	   int count = 0;
	   HV*   FullHash = newHV();

	   for ( entry = ldap_first_entry(ld, result); entry != NULL;
		entry = ldap_next_entry(ld, entry) )
	   {
	      HV* ResultHash = newHV();
	      SV* HashRef = newRV((SV*) ResultHash);

	      if ((dn = ldap_get_dn(ld, entry)) == NULL)
		 continue; 

	      for ( attr = ldap_first_attribute(ld, entry, &ber);
		  attr != NULL;
		  attr = ldap_next_attribute(ld, entry, ber) )
	      {

		 AV* AttributeValsArray = newAV();
		 SV* ArrayRef = newRV((SV*) AttributeValsArray);
		 if ((vals = ldap_get_values_len(ld, entry, attr)) != NULL)
		 {
		    for (count=0; vals[count] != NULL; count++)
		    {
		       SV* SVval = newSVpv(vals[count]->bv_val, vals[count]->bv_len);
		       av_push(AttributeValsArray, SVval);
		    }
		 }
		 hv_store(ResultHash, attr, strlen(attr), ArrayRef, 0);
	         if (vals != NULL)
		    ldap_value_free_len(vals);
	      }
	      if (attr != NULL)
	         ldap_memfree(attr);
	      hv_store(FullHash, dn, strlen(dn), HashRef, 0);
	      if (dn != NULL)
	         ldap_memfree(dn);
	      if (ber != NULL)
	         ber_free(ber,0);
	   }
	   RETVAL = FullHash;
	}
	OUTPUT:
	RETVAL

