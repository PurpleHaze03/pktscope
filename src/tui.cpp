#include "pktscope/tui.hpp"

#include <ncurses.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>

namespace pktscope {

bool Dashboard::has_tty() { return isatty(STDOUT_FILENO) != 0; }

void Dashboard::update(const Stats& s, const FlowTable& flows) {
    std::lock_guard<std::mutex> lock(mu_);
    stats_ = s;
    flow_count_ = flows.size();
    top_ = flows.top_by_bytes(8);
}

void Dashboard::push_alert(const Alert& a) {
    std::lock_guard<std::mutex> lock(mu_);
    alerts_.push_back(a);
    if (alerts_.size() > 200) alerts_.erase(alerts_.begin());
}

// color pairs
enum { CP_HEADER = 1, CP_KEY, CP_BAR, CP_CRIT, CP_WARN, CP_INFO };

static void draw_bar(int row, const char* label, std::uint64_t n,
                     std::uint64_t total, int width) {
    mvprintw(row, 2, "%-6s %8llu", label, static_cast<unsigned long long>(n));
    double frac = total ? static_cast<double>(n) / total : 0.0;
    int fill = static_cast<int>(frac * width);
    attron(COLOR_PAIR(CP_BAR));
    for (int i = 0; i < fill; ++i) mvaddch(row, 18 + i, ACS_CKBOARD);
    attroff(COLOR_PAIR(CP_BAR));
    mvprintw(row, 18 + width + 1, "%.1f%%", frac * 100.0);
}

void Dashboard::run_ui(const std::string& source, std::atomic<bool>& running) {
    if (!has_tty()) return;  // report mode handles the non-interactive case

    initscr();
    cbreak();
    noecho();
    curs_set(0);
    nodelay(stdscr, TRUE);  // non-blocking getch
    keypad(stdscr, TRUE);
    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(CP_HEADER, COLOR_BLACK, COLOR_CYAN);
        init_pair(CP_KEY, COLOR_CYAN, -1);
        init_pair(CP_BAR, COLOR_GREEN, -1);
        init_pair(CP_CRIT, COLOR_WHITE, COLOR_RED);
        init_pair(CP_WARN, COLOR_YELLOW, -1);
        init_pair(CP_INFO, COLOR_CYAN, -1);
    }

    while (running) {
        int ch = getch();
        if (ch == 'q' || ch == 'Q') { running = false; break; }

        Stats s;
        std::vector<Flow> top;
        std::vector<Alert> alerts;
        std::size_t flow_count;
        {
            std::lock_guard<std::mutex> lock(mu_);
            s = stats_; top = top_; alerts = alerts_; flow_count = flow_count_;
        }

        erase();
        int H = getmaxy(stdscr), W = getmaxx(stdscr);

        // header bar
        attron(COLOR_PAIR(CP_HEADER) | A_BOLD);
        for (int i = 0; i < W; ++i) mvaddch(0, i, ' ');
        mvprintw(0, 1, " pktscope  |  %s  |  %llu pkt  %.1f pkt/s  %.2f Mbit/s  |  q=quit",
                 source.c_str(), static_cast<unsigned long long>(s.packets),
                 s.pps(), s.mbps());
        attroff(COLOR_PAIR(CP_HEADER) | A_BOLD);

        // protocol breakdown
        attron(COLOR_PAIR(CP_KEY) | A_BOLD);
        mvprintw(2, 2, "PROTOCOLS");
        attroff(COLOR_PAIR(CP_KEY) | A_BOLD);
        int barw = std::min(30, W / 3);
        draw_bar(3, "ARP", s.arp, s.packets, barw);
        draw_bar(4, "IPv4", s.ipv4, s.packets, barw);
        draw_bar(5, "IPv6", s.ipv6, s.packets, barw);
        draw_bar(6, "TCP", s.tcp, s.packets, barw);
        draw_bar(7, "UDP", s.udp, s.packets, barw);
        draw_bar(8, "ICMP", s.icmp, s.packets, barw);
        draw_bar(9, "DNS", s.dns, s.packets, barw);

        // top talkers
        attron(COLOR_PAIR(CP_KEY) | A_BOLD);
        mvprintw(11, 2, "TOP TALKERS (%zu flows)", flow_count);
        attroff(COLOR_PAIR(CP_KEY) | A_BOLD);
        int row = 12;
        for (const auto& f : top) {
            if (row >= H - 8) break;
            mvprintw(row++, 2, "%-46.46s %10llu B  %6llu pkt  %s",
                     f.describe().c_str(), static_cast<unsigned long long>(f.bytes),
                     static_cast<unsigned long long>(f.packets),
                     f.proto == 6 ? tcp_state_name(f.state) : "");
        }

        // alerts pane (bottom)
        int alert_top = H - 6;
        attron(COLOR_PAIR(CP_KEY) | A_BOLD);
        mvprintw(alert_top - 1, 2, "ALERTS (%zu)", alerts.size());
        attroff(COLOR_PAIR(CP_KEY) | A_BOLD);
        int shown = 0;
        for (auto it = alerts.rbegin(); it != alerts.rend() && shown < 5; ++it, ++shown) {
            int cp = it->severity == Severity::Critical ? CP_CRIT
                     : it->severity == Severity::Warning ? CP_WARN : CP_INFO;
            attron(COLOR_PAIR(cp));
            mvprintw(alert_top + shown, 2, "[%s] %-11s %-.*s",
                     severity_name(it->severity), it->kind.c_str(),
                     W - 24, it->detail.c_str());
            attroff(COLOR_PAIR(cp));
        }

        refresh();
        napms(250);  // ~4 fps
    }

    endwin();
}

}  // namespace pktscope
