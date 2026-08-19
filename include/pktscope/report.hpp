// Non-interactive output: a text report and a JSON dump (for offline analysis,
// CI, and scripting). Used when there's no TTY or --report/--json is given.
#pragma once

#include <ostream>
#include <string>

#include "pktscope/detect.hpp"
#include "pktscope/flow.hpp"
#include "pktscope/stats.hpp"

namespace pktscope {

void write_report(std::ostream& os, const Stats& stats, const FlowTable& flows,
                  const std::vector<Alert>& alerts, const std::string& source);

void write_json(std::ostream& os, const Stats& stats, const FlowTable& flows,
                const std::vector<Alert>& alerts, const std::string& source);

}  // namespace pktscope
