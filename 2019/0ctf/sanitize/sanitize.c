#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

typedef struct _Node
{
    uint8_t key;
    uint32_t degree;
    struct _Node *parent;
    struct _Node *child;
    struct _Node *sibling;
} Node;

typedef struct _Heap
{
    Node *head;
} Heap;

#ifdef DEBUG
void print_node(Node *node, Node *parent, uint32_t depth, uint8_t is_child)
{
    if (!node)
        return;

    while (node)
    {
        if (is_child)
            printf("[%d : %d] : %d <= %d Child\n", depth, node->degree, node->key, parent->key);
        else
            printf("[%d : %d] : %d <= %d Sibling\n", depth, node->degree, node->key, parent->key);


        if (node->child)
            print_node(node->child, node, depth+1, 1);

        node = node->sibling;
        is_child = 0;
    }
}

void print_heap(Heap *h)
{
    // printf("head: %p\n", h->head);
    Node *p = h->head;
    printf("-----------------START-----------------\n");
    while (p)
    {
        printf("------------ Tree Degree %d --------\n", p->degree);
        printf("root: %d\n", p->key);
        print_node(p->child, p, 1, 1);
        p = p->sibling;
    }
    printf("-----------------END-------------------\n");
}
#endif

Heap * new_heap()
{
    Heap *h = (Heap *)malloc(sizeof(Heap));
    if (!h)
        _exit(-3);
    h->head = NULL;
    return h;
}

void free_node(Node *x)
{
    if (!x)
        return ;
    Node *tmp;
    Node *n = x;
    while (n)
    {
        free_node(n->child);
        n->key = 0;
        n->degree = 0;
        n->parent = NULL;
        n->child = NULL;
        tmp = n->sibling;
        n->sibling = NULL;
        free(n);
        n = tmp;
    }
}

void free_heap(Heap *h)
{
    Node *p = h->head;
    while (p)
    {
        free_node(p->child);
        Node *tmp = p;
        p = p->sibling;
        tmp->sibling = tmp->parent = tmp->child = NULL;
        tmp->key = tmp->degree = 0;
        free(tmp);
    }
    h->head = NULL;
    free(h);
}

Node * heap_min_value(Heap *p)
{
    Node *y = NULL;
    Node *x = p->head;
    uint16_t min_value = 0x100;
    while (x)
    {
        if (x->key < min_value)
        {
            min_value = (uint16_t)(x->key);
            y = x;
        }
        x = x->sibling;
    }
    return y;
}

#define BINOMIAL_LINK(y, z) do {\
    if (y == z ) break; \
    y->parent = z; \
    y->sibling = z->child; \
    z->child = y; \
    z->degree++; \
} while(0)

#define MOVE(p) do {\
    if (!(h->head)) {\
        h->head = p; \
    } else { \
        o->sibling = p; \
    } \
    o = p; \
    Node *tmp = p->sibling; \
    p->sibling = NULL; \
    p = tmp; \
} while (0)

Heap * heap_merge(Heap *h1, Heap *h2)
{
    if (!h1 || !h2)
        return NULL;
    Node *p1 = h1->head;
    Node *p2 = h2->head;
    Heap *h = new_heap();
    Node *o = h->head;
    while (p1 && p2)
    {
        if (p1->degree <= p2->degree)
        {
            MOVE(p1);
        }
        else
        {
            MOVE(p2);
        }
    }
#ifdef DDEBUG
    printf("h->head: %p\n", h->head);
    if (o)
        printf("o: %p o->sibling: %p\n", o, o->sibling);
    if (p1)
        printf("p1 has remain\n");
    if (p2)
        printf("p2 has remain\n");
#endif
    while (p1)
    {
        MOVE(p1);
    }
    while (p2)
    {
        MOVE(p2);
    }
    h1->head = NULL;
    h2->head = NULL;
    free_heap(h1);
    free_heap(h2);

    return h;
}

Heap * heap_union(Heap *h1, Heap *h2)
{
    Heap *h = heap_merge(h1, h2);
    if (!h->head)
        return h;
    Node *prev = NULL;
    Node *x = h->head;
    Node *next = x->sibling;
    while (next)
    {
        if ((x->degree != next->degree) || (next->sibling && next->sibling->degree == x->degree))
        {
            prev = x;
            x = next;
        }
        else if (x->key <= next->key)
        {
            x->sibling = next->sibling;
            BINOMIAL_LINK(next, x);
        }
        else
        {
            if (!prev)
                h->head = next;
            else
                prev->sibling = next;
            BINOMIAL_LINK(x, next);
            x = next;
        }
        next = x->sibling;
    }
    return h;
}

void insert(Heap **ph, uint8_t data)
{
    Heap *h = *ph;
    Node *x = (Node *)malloc(sizeof(Node));
    if (!x)
        _exit(-3);
    x->child = x->sibling = x->parent = NULL;
    x->degree = 0;
    x->key = data;
    Heap *h2 = new_heap();
    h2->head = x;
    *ph = heap_union(h, h2);
}

Node * extract_min(Heap **ph)
{
    Heap *h = *ph;
    Node *p = h->head;
    uint32_t min_value = 0x10000;
    Node *min_node = NULL;

    while (p)
    {
        if (p->key < min_value)
        {
            min_value = p->key;
            min_node = p;
        }
        p = p->sibling;
    }

    if (!min_node)
        return NULL;

    Heap *h2 = new_heap();
    h2->head = min_node->child;
    p = min_node->child;
    while (p)
    {
        p->parent = NULL;
        p = p->sibling;
    }

    *ph = heap_union(h, h2);
    free_heap(h2);
    return min_node;
}

void heap_decrease_key(Node *x, int32_t k)
{
    if (!x || k > x->key)
    {
        return;
    }
    x->key = (uint8_t)k;
    Node *y = x;
    Node *z = y->parent;
    while (z && y->key < z->key)
    {
        uint8_t tmp = y->key;
        y->key = z->key;
        z->key = tmp;
        y = z;
        z = y->parent;
    }
}

void heap_delete_node(Heap **ph, Node *x)
{
    heap_decrease_key(x, -1000);
    extract_min(ph);
}

#ifdef TEST
void test(uint8_t *a, int size)
{
    Heap *h = new_heap();
    int i;
    for (i = 0; i < size; ++i)
    {
        insert(&h, a[i]);
    }
    print_heap(h);
    free_heap(h);
}

int main()
{
    uint8_t a[] = {12, 7, 25, 15, 28, 41, 33};
    uint8_t b[] = {18, 3, 37, 6, 8, 29, 10, 44, 30, 23, 22, 48, 31, 17, 45, 32, 24, 50, 55};
    uint8_t c[] = {10, 1, 6, 12, 25, 8, 14, 29, 18, 11, 17, 38, 27};
    test(a, sizeof(a) / sizeof(uint8_t));
    test(b, sizeof(b) / sizeof(uint8_t));
    test(c, sizeof(c) / sizeof(uint8_t));
    return 0;
}
#endif

#ifdef RELEASE

uint32_t *g_start = NULL;
uint32_t *g_stop = NULL;

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    if (start == stop || *start) return;  // Initialize only once.
    for (uint32_t *x = start; x < stop; x++)
        *x = 0;
    g_start = start;
    g_stop = stop;
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
  ++*guard;
}

void dtor()
{
    if ((!g_start)
        || (!g_stop)
        || g_start >= g_stop)
        return;

#ifdef DEBUG
    for (uint32_t *x = g_start; x < g_stop; x++)
        printf("%p %x\n", x, *x);
#endif
    uint8_t *p = (uint8_t *)g_start;
    while (p < (uint8_t *)g_stop)
    {
        printf("%02x", *p);
        p++;
    }
    puts("");
}

size_t read_user_heap(uint8_t *user_input, size_t max_size)
{
    size_t i = 0;
    char *ret = fgets((char *)user_input, 0x20, stdin);
    if (!ret)
    {
        _exit(-1);
    }

    // check user input
    size_t length = strlen((char *)user_input);
    if (length < 4)
    {
        _exit(-1);
    }

    if (user_input[length-1] == '\n')
    {
        user_input[length-1] = '\x00';
        length--;
    }
    for (i = 0; i < length; ++i)
    {
        if (user_input[i] < '\x20' || user_input[i] > '\x7e')
        {
            fprintf(stderr, "Invalid Character\n");
            _exit(-2);
        }
    }
    return length;
}

uint32_t read_flag_locations(uint32_t *locs, size_t max_size)
{
    uint8_t *used = (uint8_t *)malloc(max_size+1);
    if (!used)
    {
        _exit(-1);
    }
    memset(used, 0, max_size+1);

    // read flag count
    uint32_t i = 0;
    uint32_t times = 0;
    scanf("%d", &times);
    if (times < 3 || times > max_size)
    {
        fprintf(stderr, "Invalid\n");
        _exit(-3);
    }

#ifdef DEBUG
    printf("times: %d\n", times);
#endif

    // read flag locations
    for (i = 0; i < times; ++i)
    {
        uint32_t loc = 0;
        scanf("%d", &loc);
        loc %= max_size;
#ifdef DEBUG
        printf("loc: %d\n", loc);
#endif
        if (used[loc] != 0)
        {
            fprintf(stderr, "Invalid\n");
            _exit(-4);
        }
        used[loc] = 1;
        locs[i] = loc;
    }
    free(used);
    return times;
}

int main(int argc, char *argv[])
{
    alarm(10);
    // do my initialization
    atexit(dtor);

    // read flag
    FILE *file = fopen("flag", "r");
    if (!file)
    {
        fprintf(stderr, "open flag failed\n");
        _exit(-1);
    }

    fseek(file, 0, SEEK_END);
    long flag_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *flag = (char *)malloc(flag_size+1);
    if (!flag)
    {
        _exit(-1);
    }
    memset(flag, 0, flag_size+1);
    fread(flag, 1, flag_size, file);
    fclose(file);

    size_t i;
    uint8_t user_input[0x40] = {0};
    uint32_t *locs = (uint32_t *)malloc((flag_size+1)*sizeof(uint32_t));
    if (!locs)
    {
        _exit(-1);
    }
    memset(locs, 0, (flag_size+1)*sizeof(uint32_t));

    // read user input
    size_t length = read_user_heap(user_input, 0x40);
    uint32_t times = read_flag_locations(locs, flag_size);

    // insert user input into heap first
    Heap *h = new_heap();
    for (i = 0; i < length; ++i)
    {
        insert(&h, user_input[i]);
    }

    // insert flag into heap
    for (i = 0; i < times; ++i)
    {
        insert(&h, flag[locs[i]]);
    }

#ifdef DEBUG
    print_heap(h);
#endif

    free(flag);
    flag = NULL;
    free(locs);
    locs = NULL;
    free_heap(h);
    h = NULL;
    return 0;
}
#endif
