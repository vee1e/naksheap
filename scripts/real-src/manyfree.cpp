#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <list>
#include <unistd.h>

// Lots of allocations + frees to exercise tcache AND bin consolidation, plus
// std::map/std::list nodes. Crashes with a live heap state.
static std::map<int, std::string>* g_map = nullptr;
static std::list<std::string>* g_list = nullptr;
static std::vector<char*>* g_ptrs = nullptr;

int main(int argc, char**) {
    g_map = new std::map<int, std::string>();
    g_list = new std::list<std::string>();
    g_ptrs = new std::vector<char*>();
    for (int i = 0; i < 20; i++) {
        (*g_map)[i] = std::string("key-value-") + std::to_string(i * 7);
        g_list->push_back(std::string("list-item-") + std::to_string(i));
    }
    // Many allocations of varied sizes, then free half of them (tcache) and a
    // few large ones (bins), then keep the other half live.
    for (int i = 0; i < 64; i++) {
        char* p = (char*)malloc(0x20 + (i % 5) * 0x30);
        memset(p, 0x61 + i % 26, 0x20);
        g_ptrs->push_back(p);
    }
    for (int i = 0; i < 64; i += 2) free((*g_ptrs)[i]);
    // Some large allocations. big2 is served by mmap (>= 128 KiB? no: 0x4000
    // is 16 KiB, but this glibc's mmap threshold may be lower), so free(big2)
    // unmaps it and the chunk vanishes from the dump. big1/big3 stay live.
    void* big1 = malloc(0x2000);
    void* big2 = malloc(0x4000);
    void* big3 = malloc(0x8000);
    free(big2);
    printf("GT map=%p list=%p ptrs=%p big1=%p big3=%p\n",
           (void*)g_map, (void*)g_list, (void*)g_ptrs, big1, big3);
    fflush(stdout);
    if (argc > 1) { for (;;) usleep(1000000); }
    volatile int* p = (int*)nullptr;
    *p = 42; // SIGSEGV so a real crash core is produced
}
