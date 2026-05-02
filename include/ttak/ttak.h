#ifndef TTAK_TTAK_H
#define TTAK_TTAK_H

#include <stdint.h>

typedef struct ttak_task ttak_task_t;

void ttak_init(void);
void ttak_run(void);
void ttak_sleep(int ms);
void ttak_schedule(void (*func)(ttak_task_t *, void *), void *arg);

#endif /* TTAK_TTAK_H */
