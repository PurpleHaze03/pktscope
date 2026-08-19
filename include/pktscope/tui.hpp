// Live ncurses dashboard: protocol mix, top talkers, and a scrolling alert
// feed, refreshed a few times per second while capture runs on another thread.
#pragma once

#include <atomic>
#include <mutex>
#include <vector>

#include "pktscope/detect.hpp"
#include "pktscope/flow.hpp"
#include "pktscope/stats.hpp"

namespace pktscope {

// Thread-safe snapshot store the capture thread writes and the UI thread reads.
class Dashboard {
public:
    void update(const Stats& s, const FlowTable& flows);
    void push_alert(const Alert& a);

    // Run the ncurses render loop on the CALLING thread until quit or stop().
    // Returns immediately (doing nothing) if stdout is not a TTY.
    void run_ui(const std::string& source, std::atomic<bool>& running);

    static bool has_tty();

private:
    std::mutex mu_;
    Stats stats_;
    std::vector<Flow> top_;
    std::size_t flow_count_ = 0;
    std::vector<Alert> alerts_;
};

}  // namespace pktscope
