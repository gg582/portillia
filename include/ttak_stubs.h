#define ttak_mem_alloc_safe(a, b, c, d, e, f, g, h) malloc(a)
#define ttak_mem_free(a) free(a)
#define ttak_mem_realloc_safe(a, b, c, d, e, f, g, h) realloc(a, b)
#define ttak_mem_tree_add(a, b, c, d, e) (void*)0
#define ttak_mem_tree_remove(a, b) (void)0
#define ttak_mem_tree_init(a) (void)0
#define ttak_mem_tree_destroy(a) (void)0
#define ttak_mem_node_release(a) (void)0
#define ttak_mem_node_acquire(a) (void)0
#define ttak_owner_create(a) (void*)1
#define ttak_owner_register_resource(a, b, c) 1
#define ttak_owner_register_func(a, b, c) 1
#define ttak_owner_destroy(a) (void)0
#define ttak_owner_execute(a, b, c, d) 1
