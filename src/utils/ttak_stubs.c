#include <ttak/ttak.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

void ttak_init(void) {}

void ttak_run(void) {
    // Placeholder for an event loop
    while(1) {
        sleep(60);
    }
}

void ttak_sleep(int ms) {
    usleep(ms * 1000);
}

typedef struct {
    void (*func)(ttak_task_t *, void *);
    void *arg;
} task_wrapper_t;

static void *task_thread(void *arg) {
    task_wrapper_t *w = (task_wrapper_t *)arg;
    if (w->func) {
        w->func(NULL, w->arg);
    }
    free(w);
    return NULL;
}

void ttak_schedule(void (*func)(ttak_task_t *, void *), void *arg) {
    pthread_t tid;
    task_wrapper_t *w = malloc(sizeof(task_wrapper_t));
    w->func = func;
    w->arg = arg;
    if (pthread_create(&tid, NULL, task_thread, w) != 0) {
        free(w);
    } else {
        pthread_detach(tid);
    }
}
