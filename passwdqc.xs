#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "passwdqc.h"

SV *
password_generate(const char *packed_params)
{
    const char *pass;
    const passwdqc_params_qc_t *params = (passwdqc_params_qc_t *) packed_params;

    pass = passwdqc_random(params);

    if (!pass)
        return &PL_sv_undef;
     return newSVpvn(pass, strlen(pass));
}

SV *
password_check(const char *packed_params, const char *new_pass, const char *old_pass)
{
    const char *reason;
    const passwdqc_params_qc_t *params = (passwdqc_params_qc_t *) packed_params;

    reason = passwdqc_check(params, new_pass, old_pass, NULL);

    if (!reason)
        return &PL_sv_undef;
    return newSVpvn(reason, strlen(reason));
}


MODULE = Data::Password::passwdqc		PACKAGE = Data::Password::passwdqc		

PROTOTYPES: DISABLE


SV *
password_generate (packed_params)
        const char * packed_params

SV *
password_check (packed_params, new_pass, ...)
        const char * packed_params
        const char * new_pass
    CODE:
        if (items > 2)
            RETVAL = password_check(packed_params, new_pass, (char *)SvPV_nolen(ST(2)));
        else
            RETVAL = password_check(packed_params, new_pass, NULL);
    OUTPUT:
        RETVAL

