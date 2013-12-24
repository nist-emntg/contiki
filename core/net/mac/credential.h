#ifndef CREDENTIAL_H
#define CREDENTIAL_H

#include "certificate.h"

extern uint8_t raw_cacert [];
extern uint8_t raw_cert [];

extern s_certificate * cert;
extern s_pub_certificate * cacert;

void init_crypto(void);

#endif // CREDENTIAL_H
