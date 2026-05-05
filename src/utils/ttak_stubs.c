#include <ttak/ttak.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>

typedef struct task_node {
    void (*func)(ttak_task_t *, void *);
    void *arg;
    struct task_node *next;
} task_node_t;

static pthread_mutex_t task_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t task_cond = PTHREAD_COND_INITIALIZER;
static task_node_t *task_head = NULL;
static task_node_t *task_tail = NULL;
static bool task_loop_running = false;

void ttak_init(void) {}

void ttak_run(void) {
    task_loop_running = true;
    while (task_loop_running) {
        pthread_mutex_lock(&task_mu);
        while (!task_head && task_loop_running) {
            pthread_cond_wait(&task_cond, &task_mu);
        }
        task_node_t *node = task_head;
        if (node) {
            task_head = node->next;
            if (!task_head) task_tail = NULL;
        }
        pthread_mutex_unlock(&task_mu);
        if (node) {
            if (node->func) {
                node->func(NULL, node->arg);
            }
            free(node);
        }
    }
}

void ttak_sleep(int ms) {
    usleep(ms * 1000);
}

void ttak_schedule(void (*func)(ttak_task_t *, void *), void *arg) {
    task_node_t *node = malloc(sizeof(task_node_t));
    if (!node) return;
    node->func = func;
    node->arg = arg;
    node->next = NULL;
    pthread_mutex_lock(&task_mu);
    if (task_tail) {
        task_tail->next = node;
    } else {
        task_head = node;
    }
    task_tail = node;
    pthread_cond_signal(&task_cond);
    pthread_mutex_unlock(&task_mu);
}
