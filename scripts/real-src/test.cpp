// Real-world heap test program for naksheap validation.
// Allocates a variety of live objects (linked list, polymorphic classes,
// std::string SSO + heap, std::vector, large mmap allocation, thread arena),
// frees a few to create tcache/freed chunks, prints exact allocation
// addresses as ground truth, then crashes with SIGSEGV so a real kernel core
// dump is produced with registers/stack rooted in the heap.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <malloc.h>

struct Node {
    int id;
    Node* next;
    char tag[16];
    Node(int i) : id(i), next(nullptr) { std::snprintf(tag, 16, "node-%d", i); }
};

struct Base {
    virtual ~Base() {}
    virtual const char* name() const = 0;
    virtual int kind() const = 0;
};

struct Worker : Base {
    int id;
    std::string label;
    explicit Worker(int i)
        : id(i), label(std::string("worker-") + std::to_string(i)) {}
    const char* name() const override { return "Worker"; }
    int kind() const override { return 1; }
};

struct Manager : Base {
    int level;
    std::string label;
    explicit Manager(int l)
        : level(l),
          label("manager-label-that-is-longer-than-the-sso-buffer-15") {}
    const char* name() const override { return "Manager"; }
    int kind() const override { return 2; }
};

static Node* g_head = nullptr;
static Base* g_worker = nullptr;
static Base* g_manager = nullptr;
static std::vector<std::string>* g_vec = nullptr;
static char* g_big = nullptr;
static std::string g_sso = "hello";
static std::vector<Worker*>* g_thread_workers = nullptr;

static void boom(Node* n) {
    asm volatile("" : : "r"(n)); // keep a heap pointer live in a register
    volatile int* p = (int*)nullptr;
    *p = 42; // SIGSEGV
}

static void thread_alloc(void) {
    // Spawn a real thread so glibc may create a non-main arena (with a
    // heap_info header) and leave live allocations behind when it exits.
    std::thread t([] {
        g_thread_workers = new std::vector<Worker*>();
        for (int i = 0; i < 3; i++) {
            g_thread_workers->push_back(new Worker(100 + i));
        }
    });
    t.join();
}

int main(int argc, char**) {
    if (argc > 1) {
        // "gcore" mode: just allocate and sleep so a live snapshot can be taken.
        thread_alloc();
        g_head = new Node(1);
        g_head->next = new Node(2);
        g_head->next->next = new Node(3);
        g_head->next->next->next = g_head;
        g_worker = new Worker(7);
        g_manager = new Manager(2);
        g_vec = new std::vector<std::string>();
        for (int i = 0; i < 8; i++) g_vec->push_back(std::string("item-") + std::to_string(i));
        g_big = (char*)malloc(1 << 20);
        std::memset(g_big, 0x42, 1 << 20);
        std::printf("GT head=%p worker=%p manager=%p vec=%p big=%p sso=%p tworkers=%p\n",
                    (void*)g_head, (void*)g_worker, (void*)g_manager, (void*)g_vec,
                    (void*)g_big, (void*)&g_sso, (void*)g_thread_workers);
        std::fflush(stdout);
        malloc_info(0, stdout);
        std::fflush(stdout);
        for (;;) std::this_thread::sleep_for(std::chrono::hours(1));
    }

    thread_alloc();
    g_head = new Node(1);
    g_head->next = new Node(2);
    g_head->next->next = new Node(3);
    g_head->next->next->next = g_head;
    g_worker = new Worker(7);
    g_manager = new Manager(2);
    g_vec = new std::vector<std::string>();
    for (int i = 0; i < 8; i++) g_vec->push_back(std::string("item-") + std::to_string(i));
    g_big = (char*)malloc(1 << 20);
    std::memset(g_big, 0x42, 1 << 20);

    // Freed chunks (tcache entries on modern glibc).
    void* f1 = malloc(0x50);
    void* f2 = malloc(0x80);
    void* f3 = malloc(0x20);
    std::free(f1);
    std::free(f2);
    std::free(f3);

    std::printf("GT head=%p worker=%p manager=%p vec=%p big=%p sso=%p tworkers=%p\n",
                (void*)g_head, (void*)g_worker, (void*)g_manager, (void*)g_vec,
                (void*)g_big, (void*)&g_sso, (void*)g_thread_workers);
    std::fflush(stdout);

    boom(g_head);
    return 0;
}
