#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <atomic>
#include <iostream>
#include <thread>
#include <vector>

static std::atomic<uint64_t> count;
static std::atomic<int> threads_launched;

static void run(int num_threads, int num_iterations)
{
    threads_launched++;
    while (threads_launched != num_threads) {
        /* active wait */
    }

    uint64_t res = 0;
    for (int i = 0; i < num_iterations; ++i) {
        res += 1;
    }
    count += res;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        std::cout << "usage: num_threads num_iterations\n";
        exit(EXIT_FAILURE);
    }

    const int num_threads = std::stoi(argv[1]);
    const int num_iterations = std::stoi(argv[2]);
    std::vector<std::thread> threads;

    for (int i = 0; i < num_threads; ++i) {
        threads.push_back(std::thread(run, num_threads, num_iterations));
    }
    for (auto & t : threads) {
        t.join();
    }
    assert(count == num_iterations * num_threads);
}
