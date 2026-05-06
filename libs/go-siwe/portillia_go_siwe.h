#ifndef PORTILLIA_GO_SIWE_H
#define PORTILLIA_GO_SIWE_H

#ifdef __cplusplus
extern "C" {
#endif

int PortilliaGoSiweVerify(const char *message, const char *signature, const char *expected_address);

#ifdef __cplusplus
}
#endif

#endif /* PORTILLIA_GO_SIWE_H */
