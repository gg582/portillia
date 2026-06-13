#ifndef PORTILLIA_API_SERVER_H
#define PORTILLIA_API_SERVER_H

/* Set the keyless signer URL exposed to SDK clients in register responses.
 * Typically the public HTTPS URL of the relay API listener.
 */
void portillia_server_set_keyless_url(const char *url);

#endif // PORTILLIA_API_SERVER_H
