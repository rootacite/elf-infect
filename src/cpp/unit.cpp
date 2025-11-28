// test_fifo.cpp
// C++ test harness that compares the C FIFO implementation against std::deque.
// Compile with: g++ -std=c++17 test_fifo.cpp fifo.c -o test_fifo
// (Assumes fifo.h and fifo.c are available and implement the API used below.)

#include <iostream>
#include <deque>
#include <random>
#include <vector>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <cstring>

// If you have fifo.h, include it. It should declare struct fifo_node and the functions:
//   struct fifo_node* fifo_mk_empty();
//   int fifo_size(struct fifo_node* head);
//   int fifo_push(struct fifo_node* head, uint64_t data);
//   int fifo_pop(struct fifo_node* head, uint64_t* data);
#include "../c/fifo.h"

// In case the header is missing or has different guards, you can uncomment a minimal
// forward-declaration block below — but prefer to use the real fifo.h.
// extern "C" {
// struct fifo_node { uint64_t data; struct fifo_node* next; struct fifo_node* prev; };
// struct fifo_node* fifo_mk_empty();
// int fifo_size(struct fifo_node* head);
// int fifo_push(struct fifo_node* head, uint64_t data);
// int fifo_pop(struct fifo_node* head, uint64_t* data);
// }

struct Operation {
    enum Type { PUSH, POP, SIZE_CHECK, INVALID_ARGS } type;
    uint64_t value; // for push
};

static void dump_last_ops(const std::vector<Operation>& ops, size_t upto = 200) {
    size_t start = ops.size() > upto ? ops.size() - upto : 0;
    for (size_t i = start; i < ops.size(); ++i) {
        const auto& op = ops[i];
        if (op.type == Operation::PUSH) {
            std::cout << "PUSH(" << op.value << ")";
        } else if (op.type == Operation::POP) {
            std::cout << "POP";
        } else if (op.type == Operation::SIZE_CHECK) {
            std::cout << "SIZE_CHECK";
        } else {
            std::cout << "INVALID_ARGS";
        }
        if (i + 1 < ops.size()) std::cout << " -> ";
    }
    std::cout << "\n";
}

int run_one_trial(std::mt19937_64 &rng, size_t ops_per_trial, uint64_t trial_id) {
    struct fifo_node* head = fifo_mk_empty();
    if (!head) {
        std::cerr << "[FATAL] fifo_mk_empty() returned NULL on trial " << trial_id << "\n";
        return -1;
    }

    std::deque<uint64_t> ref;
    std::vector<Operation> ops_record;
    ops_record.reserve(ops_per_trial);

    std::uniform_int_distribution<int> op_choice(0, 99);
    std::uniform_int_distribution<int> push_val_choice(0, 3); // choose source of value variety
    std::uniform_int_distribution<uint64_t> small_val(0, 1024);
    std::uniform_int_distribution<uint64_t> wide_val; // full 64-bit

    for (size_t step = 0; step < ops_per_trial; ++step) {
        int pick = op_choice(rng);
        // Probability strategy:
        // - If empty: more likely to PUSH, but still sometimes attempt POP to test empty-pop handling.
        // - If non-empty: mix of PUSH/POP/SIZE_CHECK.
        Operation op;
        if (ref.empty()) {
            if (pick < 80) {
                op.type = Operation::PUSH;
            } else if (pick < 95) {
                op.type = Operation::POP;
            } else {
                op.type = Operation::SIZE_CHECK;
            }
        } else {
            if (pick < 45) {
                op.type = Operation::PUSH;
            } else if (pick < 85) {
                op.type = Operation::POP;
            } else {
                op.type = Operation::SIZE_CHECK;
            }
        }

        if (op.type == Operation::PUSH) {
            // generate a push value with some edge cases
            uint64_t v;
            int src = push_val_choice(rng);
            if (src == 0) v = 0;
            else if (src == 1) v = (uint64_t)-1;
            else if (src == 2) v = small_val(rng);
            else v = wide_val(rng);
            op.value = v;
            ops_record.push_back(op);

            int rc = fifo_push(head, v);
            if (rc != 0) {
                std::cerr << "[ERROR] fifo_push returned " << rc << " (expected 0). Trial " << trial_id << " step " << step << "\n";
                dump_last_ops(ops_record);
                free(head);
                return -1;
            }
            ref.push_back(v); // enqueue at back
        } else if (op.type == Operation::POP) {
            ops_record.push_back(op);
            uint64_t popped = 0;
            int rc = fifo_pop(head, &popped);
            if (ref.empty()) {
                // should be error for empty queue
                if (rc == 0) {
                    std::cerr << "[ERROR] fifo_pop succeeded on empty queue (returned 0). Trial " << trial_id << " step " << step << "\n";
                    std::cerr << "popped value = " << popped << "\n";
                    dump_last_ops(ops_record);
                    free(head);
                    return -1;
                }
                // rc != 0 is acceptable
            } else {
                if (rc != 0) {
                    std::cerr << "[ERROR] fifo_pop failed (rc=" << rc << ") but queue was non-empty. Trial " << trial_id << " step " << step << "\n";
                    dump_last_ops(ops_record);
                    free(head);
                    return -1;
                }
                uint64_t expect = ref.front();
                if (popped != expect) {
                    std::cerr << "[ERROR] fifo_pop returned wrong value. got=" << popped << " expected=" << expect << "\n";
                    std::cerr << "Trial " << trial_id << " step " << step << "\n";
                    dump_last_ops(ops_record);
                    free(head);
                    return -1;
                }
                ref.pop_front();
            }
        } else { // SIZE_CHECK
            ops_record.push_back(op);
            int s = fifo_size(head);
            if (s < 0) {
                std::cerr << "[ERROR] fifo_size returned negative (" << s << "). Trial " << trial_id << " step " << step << "\n";
                dump_last_ops(ops_record);
                free(head);
                return -1;
            }
            if ((size_t)s != ref.size()) {
                std::cerr << "[ERROR] fifo_size mismatch. fifo_size=" << s << " expected=" << ref.size() << "\n";
                std::cerr << "Trial " << trial_id << " step " << step << "\n";
                dump_last_ops(ops_record);
                free(head);
                return -1;
            }
        }

        // Periodically (rare) run some invalid-argument checks to test defensive returns
        if ((step & 0x3FF) == 0) { // every 1024 steps
            // fifo_size(nullptr)
            int s_null = fifo_size(nullptr);
            if (s_null != -1) {
                std::cerr << "[ERROR] fifo_size(nullptr) returned " << s_null << " (expected -1). Trial " << trial_id << " step " << step << "\n";
                dump_last_ops(ops_record);
                free(head);
                return -1;
            }
            // fifo_push(nullptr, x)
            if (fifo_push(nullptr, 0) == 0) {
                std::cerr << "[ERROR] fifo_push(nullptr, 0) returned 0 (expected -1). Trial " << trial_id << " step " << step << "\n";
                dump_last_ops(ops_record);
                free(head);
                return -1;
            }
            // fifo_pop(nullptr, &x)
            uint64_t tmp = 0;
            if (fifo_pop(nullptr, &tmp) == 0) {
                std::cerr << "[ERROR] fifo_pop(nullptr, &tmp) returned 0 (expected -1). Trial " << trial_id << " step " << step << "\n";
                dump_last_ops(ops_record);
                free(head);
                return -1;
            }
            // fifo_pop(head, nullptr) should return -1
            if (fifo_pop(head, nullptr) == 0) {
                std::cerr << "[ERROR] fifo_pop(head, nullptr) returned 0 (expected -1). Trial " << trial_id << " step " << step << "\n";
                dump_last_ops(ops_record);
                free(head);
                return -1;
            }
        }
    } // end steps

    // final size check
    int final_s = fifo_size(head);
    if (final_s < 0) {
        std::cerr << "[ERROR] fifo_size returned negative at end of trial " << trial_id << "\n";
        free(head);
        return -1;
    }
    if ((size_t)final_s != ref.size()) {
        std::cerr << "[ERROR] final size mismatch. fifo_size=" << final_s << " expected=" << ref.size() << "\n";
        dump_last_ops(ops_record);
        free(head);
        return -1;
    }

    // drain remaining items and compare sequence
    while (!ref.empty()) {
        uint64_t val = 0;
        int rc = fifo_pop(head, &val);
        if (rc != 0) {
            std::cerr << "[ERROR] fifo_pop failed while draining. Trial " << trial_id << "\n";
            free(head);
            return -1;
        }
        uint64_t expect = ref.front();
        if (val != expect) {
            std::cerr << "[ERROR] mismatch while draining. got=" << val << " expect=" << expect << "\n";
            dump_last_ops(ops_record);
            free(head);
            return -1;
        }
        ref.pop_front();
    }

    // now queue should be empty; fifo_pop should fail
    uint64_t tmp = 0;
    if (fifo_pop(head, &tmp) == 0) {
        std::cerr << "[ERROR] fifo_pop succeeded after draining (expected failure). Trial " << trial_id << "\n";
        free(head);
        return -1;
    }

    // free the sentinel head
    free(head);
    return 0;
}

int main(int argc, char** argv) {
    size_t trials = 1000;
    size_t ops_per_trial = 2000;
    uint64_t seed = (uint64_t)std::time(nullptr);

    if (argc >= 2) trials = std::stoull(argv[1]);
    if (argc >= 3) ops_per_trial = std::stoull(argv[2]);
    if (argc >= 4) seed = (uint64_t)std::stoull(argv[3]);

    std::cout << "FIFO test harness\n";
    std::cout << "trials = " << trials << ", ops_per_trial = " << ops_per_trial << ", seed = " << seed << "\n";

    std::mt19937_64 rng(seed);

    for (size_t t = 0; t < trials; ++t) {
        int rc = run_one_trial(rng, ops_per_trial, (uint64_t)t);
        if (rc != 0) {
            std::cerr << "Test failed on trial " << t << ". Seed=" << seed << " (use argv[3] to reproduce)\n";
            return 2;
        }
        if ((t & 0x3FF) == 0) {
            std::cout << "Completed trial " << t << "\n";
        }
    }

    std::cout << "All tests passed. Seed used: " << seed << "\n";
    return 0;
}
