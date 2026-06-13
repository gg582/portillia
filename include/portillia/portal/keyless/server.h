#ifndef PORTILLIA_KEYLESS_SERVER_H
#define PORTILLIA_KEYLESS_SERVER_H

#include <cwist/sys/app/app.h>

/* Set up keyless TLS endpoints on the cwist app.
 * identity_path is the directory containing identity.json and certificate files.
 */
void portillia_keyless_server_setup(cwist_app *app, const char *identity_path);

/* Issue a JWT ES256K lease token compatible with the Go SDK.
 * Returns a JSON string {"token":"...","claims":{...}} or NULL on failure.
 * Caller must free the returned string.
 */
char *portillia_issue_lease_token(const char *name, const char *address, int ttl_seconds);

/* Verify a JWT ES256K lease token. Returns the claims JSON or NULL on failure.
 * Caller must free the returned string.
 */
char *portillia_verify_lease_token(const char *token);

#endif // PORTILLIA_KEYLESS_SERVER_H
