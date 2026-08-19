// pktscope -- a live network packet analyzer with security detections.
#include <atomic>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <thread>

#include "pktscope/capture.hpp"
#include "pktscope/detect.hpp"
#include "pktscope/flow.hpp"
#include "pktscope/report.hpp"
#include "pktscope/stats.hpp"
#include "pktscope/tui.hpp"

using namespace pktscope;

namespace {
std::atomic<bool> g_running{true};
void on_signal(int) { g_running = false; }

struct Options {
    std::string iface;
    std::string file;
    std::string bpf;
    std::string json_path;
    bool report = false;   // force text report even with a TTY
    bool verbose = false;  // print every packet (tcpdump-style)
    long max = 0;
};

void usage() {
    std::cout <<
        "pktscope -- network packet analyzer with security detections\n\n"
        "USAGE:\n"
        "  pktscope -r FILE [options]        analyze a .pcap file\n"
        "  pktscope -i IFACE [options]       capture live (needs root/CAP_NET_RAW)\n\n"
        "OPTIONS:\n"
        "  -r, --read FILE      read packets from a pcap file\n"
        "  -i, --iface IFACE    capture from a network interface\n"
        "  -f, --filter BPF     BPF capture filter, e.g. \"tcp port 80\"\n"
        "  -n, --count N        stop after N packets\n"
        "      --report         print a text report (default when no terminal)\n"
        "      --json FILE      write a JSON summary to FILE\n"
        "  -v, --verbose        print a line per packet\n"
        "  -h, --help           show this help\n\n"
        "EXAMPLES:\n"
        "  pktscope -r capture.pcap                 report + detections from a file\n"
        "  pktscope -r capture.pcap --json out.json machine-readable summary\n"
        "  sudo pktscope -i eth0                     live dashboard\n"
        "  sudo pktscope -i eth0 -f \"port 53\"        live, DNS only\n";
}

bool parse_args(int argc, char** argv, Options& o) {
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) { std::cerr << name << " needs a value\n"; std::exit(2); }
            return argv[++i];
        };
        if (a == "-h" || a == "--help") { usage(); std::exit(0); }
        else if (a == "-r" || a == "--read") o.file = next("--read");
        else if (a == "-i" || a == "--iface") o.iface = next("--iface");
        else if (a == "-f" || a == "--filter") o.bpf = next("--filter");
        else if (a == "-n" || a == "--count") o.max = std::stol(next("--count"));
        else if (a == "--report") o.report = true;
        else if (a == "--json") o.json_path = next("--json");
        else if (a == "-v" || a == "--verbose") o.verbose = true;
        else { std::cerr << "unknown argument: " << a << "\n\n"; usage(); return false; }
    }
    if (o.file.empty() && o.iface.empty()) {
        std::cerr << "error: specify -r FILE or -i IFACE\n\n";
        usage();
        return false;
    }
    return true;
}
}  // namespace

int main(int argc, char** argv) {
    Options opt;
    if (!parse_args(argc, argv, opt)) return 2;
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    Stats stats;
    FlowTable flows;
    Detector detector;
    Dashboard dashboard;

    const bool live = !opt.iface.empty();
    const std::string source = live ? ("iface " + opt.iface) : opt.file;
    const bool interactive = live && !opt.report && Dashboard::has_tty();

    try {
        Capture cap = live ? Capture::live(opt.iface) : Capture::offline(opt.file);
        if (!opt.bpf.empty()) cap.set_filter(opt.bpf);

        auto handle = [&](const Packet& p) {
            stats.add(p);
            if (!p.malformed && (p.l3 == L3::IPv4 || p.l3 == L3::IPv6 || p.l3 == L3::Arp))
                flows.update(p);
            for (const Alert& a : detector.inspect(p)) {
                if (interactive) dashboard.push_alert(a);
            }
            if (opt.verbose) {
                std::printf("%.6f  %s\n", p.timestamp, p.summary().c_str());
            }
            if (interactive && (stats.packets % 32 == 0)) dashboard.update(stats, flows);
        };

        if (interactive) {
            // Capture on a worker thread; render on the main thread.
            std::thread worker([&] {
                cap.run(handle, opt.max);
                g_running = false;  // file/interface ended
            });
            dashboard.run_ui(source, g_running);
            cap.stop();
            worker.join();
            // fall through to a final report after the UI closes
        } else {
            cap.run(handle, opt.max);
        }
    } catch (const CaptureError& e) {
        std::cerr << "capture error: " << e.what() << "\n";
        return 1;
    }

    // Final text report (always for offline/report mode; also after a live UI).
    if (!interactive || opt.report) {
        write_report(std::cout, stats, flows, detector.all_alerts(), source);
    } else {
        // brief tail summary after the dashboard closes
        write_report(std::cout, stats, flows, detector.all_alerts(), source);
    }

    if (!opt.json_path.empty()) {
        std::ofstream js(opt.json_path);
        if (!js) { std::cerr << "cannot write " << opt.json_path << "\n"; return 1; }
        write_json(js, stats, flows, detector.all_alerts(), source);
        std::cerr << "wrote JSON summary to " << opt.json_path << "\n";
    }

    // Non-zero exit if anything critical was detected -- handy for scripts/CI.
    for (const auto& a : detector.all_alerts())
        if (a.severity == Severity::Critical) return 3;
    return 0;
}
