// Copyright 2026 KISTI-GSDC
// SPDX-License-Identifier: Apache-2.0
#ifndef X509MAP_RULES_HH
#define X509MAP_RULES_HH

#include <cstdint>
#include <sys/types.h>
#include <regex>
#include <string>
#include <vector>

namespace X509Map {

// One line of the local-DN map:
//   "<exact DN>"            account
//   glob  "<DN glob>"       account-or-template
//   regex "<ECMAScript re>" account-or-template
struct LocalRule {
    enum Kind { Exact, Glob, Regex };
    Kind        kind = Exact;
    std::string pattern;   // as written, for logging
    std::string target;    // account, or template with $1..$9 / ${n}
    std::regex  re;        // compiled for Glob (translated) and Regex
    int         lineno = 0;
};

// One line of the VOMS map (voms-mapfile syntax):
//   "/vo/group/Role=r/Capability=NULL" account
struct VomsRule {
    std::vector<std::string> path;   // FQAN split on '/'
    std::string              target;
    int                      lineno = 0;
};

// Immutable once published by the mapper.
struct RuleSet {
    std::vector<LocalRule> local;
    std::vector<VomsRule>  voms;
    uint64_t               generation = 0;
};

// Parse one local-map line. Returns true and fills `rule` on success.
// Returns false with an empty `err` for blank/comment lines, and false with
// a non-empty `err` for malformed lines.
bool ParseLocalLine(const std::string &line, LocalRule &rule, std::string &err);

// Verbatim port of XrdVomsMapfile::ParseLine: returns true if the line
// yielded a (possibly empty) path and target.
bool ParseVomsLine(const std::string &line, std::vector<std::string> &path,
                   std::string &target);

// Port of XrdOucString::matches(): '*'-only wildcard with the same (loose)
// token-search semantics so existing voms-mapfiles behave identically.
bool GlobStarMatch(const std::string &pattern, const std::string &s);

// Port of XrdVomsMapfile::Compare.
bool VomsCompare(const VomsRule &rule, const std::vector<std::string> &fqan);

// "/cms/Role=production/Capability=NULL" -> {"cms","Role=production","Capability=NULL"}
std::vector<std::string> SplitFqan(const std::string &fqan);

// Same rule as XrdSciTokens IsSafeUsername: [A-Za-z0-9_.@-], not starting with '-'.
bool IsSafeUsername(const std::string &user);

// Translate a DN glob ('*' any run, '?' one char, '(...)' capture group) into
// an anchored ECMAScript regex.
std::string GlobToRegex(const std::string &glob);

// Expand $1..$9, ${n} and $$ in `tmpl` from a regex match. Returns false if a
// referenced group does not exist.
bool ExpandTemplate(const std::string &tmpl, const std::smatch &m, std::string &out);

} // namespace X509Map

#endif
