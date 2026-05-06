#ifndef PORTILLIA_AGENT_CONTROL_H
#define PORTILLIA_AGENT_CONTROL_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Run the agent HTTP control server until shutdown is requested.
 * @param control_addr Bind address (e.g. "127.0.0.1:4019"). NULL uses default.
 * @return 0 on clean shutdown, -1 on error.
 */
int portillia_agent_control_server_run(const char *control_addr);

#ifdef __cplusplus
}
#endif

#endif /* PORTILLIA_AGENT_CONTROL_H */
