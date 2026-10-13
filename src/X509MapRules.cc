// Copyright 2026 KISTI-GSDC
// SPDX-License-Identifier: Apache-2.0
#include "X509MapRules.hh"

#include <cctype>
#include <cstring>

namespace X509Map {

namespace {

// Skip leading whitespace starting at idx.
void SkipSpace(const std::string &s, size_t &idx)
{
    while (idx < s.size() && isspace(static_cast<unsigned char>(s[idx]))) idx++;
}

// Read a bare word (up to whitespace or end).
std::string ReadWord(const std::string &s, size_t &idx)
{
    size_t start = idx;
    while (idx < s.size() && !isspace(static_cast<unsigned char>(s[idx]))) idx++;
    return s.substr(start, idx - start);
}

// Read a double-quoted string starting at s[idx] == '"'. Escapes follow
// XrdVomsMapfile::ParseLine (\' \" \/ \f \n \r \t) plus "\\". When
// `keepUnknown` is set (regex lines) any other escape is kept verbatim so
// that regex escapes such as "\." or "\d" survive.
bool ReadQuoted(const std::string &s, size_t &idx, bool keepUnknown,
                std::string &out, std::string &err)
{
    if (idx >= s.size() || s[idx] != '"') {
        err = "expected a double-quoted pattern";
        return false;
    }
    idx++;
    out.clear();
    for (; idx < s.size(); idx++) {
        char c = s[idx];
        if (c == '"') {
            idx++;
            return true;
        }
        if (c == '\\') {
            if (idx + 1 == s.size()) {
                err = "dangling backslash";
                return false;
            }
            char e = s[++idx];
            switch (e) {
            case '\'': out += '\''; break;
            case '"':  out += '"';  break;
            case '/':  out += '/';  break;
            case 'f':  out += keepUnknown ? "\\f" : "\f"; break;
            case 'n':  out += keepUnknown ? "\\n" : "\n"; break;
            case 'r':  out += keepUnknown ? "\\r" : "\r"; break;
            case 't':  out += keepUnknown ? "\\t" : "\t"; break;
            case '\\': out += keepUnknown ? "\\\\" : "\\"; break;
            default:
                if (!keepUnknown) {
                    err = std::string("unknown escape sequence \\") + e;
                    return false;
                }
                out += '\\';
                out += e;
            }
            continue;
        }
        if (!isprint(static_cast<unsigned char>(c))) {
            err = "non-printable character in pattern";
            return false;
        }
        out += c;
    }
    err = "unterminated quoted pattern";
    return false;
}

bool HasTemplateRef(const std::string &t)
{
    return t.find('$') != std::string::npos;
}

} // namespace

std::string GlobToRegex(const std::string &glob)
{
    std::string re = "^";
    for (char c : glob) {
        switch (c) {
        case '*': re += ".*"; break;
        case '?': re += '.';  break;
        case '(': re += '(';  break;
        case ')': re += ')';  break;
        case '.': case '^': case '$': case '+': case '[': case ']':
        case '{': case '}': case '|': case '\\':
            re += '\\';
            re += c;
            break;
        default:
            re += c;
        }
    }
    re += '$';
    return re;
}

bool ParseLocalLine(const std::string &line, LocalRule &rule, std::string &err)
{
    err.clear();
    size_t idx = 0;
    SkipSpace(line, idx);
    if (idx == line.size() || line[idx] == '#') return false;

    rule = LocalRule();
    if (line[idx] != '"') {
        std::string kw = ReadWord(line, idx);
        if (kw == "glob") rule.kind = LocalRule::Glob;
        else if (kw == "regex") rule.kind = LocalRule::Regex;
        else {
            err = "unknown rule keyword '" + kw + "' (expected glob, regex or a quoted DN)";
            return false;
        }
        SkipSpace(line, idx);
    }

    if (!ReadQuoted(line, idx, rule.kind == LocalRule::Regex, rule.pattern, err)) return false;
    if (rule.pattern.empty()) {
        err = "empty pattern";
        return false;
    }

    if (idx < line.size() && !isspace(static_cast<unsigned char>(line[idx]))) {
        err = "missing whitespace after pattern";
        return false;
    }
    SkipSpace(line, idx);
    if (idx == line.size() || line[idx] == '#') {
        err = "missing target account";
        return false;
    }
    rule.target = ReadWord(line, idx);
    SkipSpace(line, idx);
    if (idx < line.size() && line[idx] != '#') {
        err = "unexpected trailing text after target";
        return false;
    }

    switch (rule.kind) {
    case LocalRule::Exact:
        if (HasTemplateRef(rule.target)) {
            err = "exact rule target must be a plain account name";
            return false;
        }
        if (!IsSafeUsername(rule.target)) {
            err = "unsafe target account name '" + rule.target + "'";
            return false;
        }
        return true;
    case LocalRule::Glob: {
        // Require a literal prefix that contains at least one complete
        // "/X=" attribute so a glob can never be "*anything*".
        size_t wc = rule.pattern.find_first_of("*?(");
        std::string prefix = rule.pattern.substr(0, wc);
        if (prefix.empty() || prefix[0] != '/' || prefix.find('=') == std::string::npos) {
            err = "glob must start with a literal DN prefix such as \"/C=KR/O=...\"";
            return false;
        }
        try {
            rule.re = std::regex(GlobToRegex(rule.pattern), std::regex::ECMAScript);
        } catch (const std::regex_error &e) {
            err = std::string("invalid glob: ") + e.what();
            return false;
        }
        break;
    }
    case LocalRule::Regex:
        try {
            rule.re = std::regex("^(?:" + rule.pattern + ")$", std::regex::ECMAScript);
        } catch (const std::regex_error &e) {
            err = std::string("invalid regex: ") + e.what();
            return false;
        }
        break;
    }
    if (!HasTemplateRef(rule.target) && !IsSafeUsername(rule.target)) {
        err = "unsafe target account name '" + rule.target + "'";
        return false;
    }
    // Validate the template syntax and that every referenced group exists.
    size_t maxGroup = 0;
    for (size_t i = 0; i < rule.target.size(); i++) {
        if (rule.target[i] != '$') continue;
        if (i + 1 == rule.target.size()) {
            err = "dangling '$' in target template";
            return false;
        }
        char n = rule.target[i + 1];
        size_t group = 0;
        if (n == '$') {
            i++;
            continue;
        } else if (isdigit(static_cast<unsigned char>(n))) {
            group = n - '0';
            i++;
        } else if (n == '{') {
            size_t close = rule.target.find('}', i + 2);
            if (close == std::string::npos || close == i + 2 || close - i > 6) {
                err = "malformed ${n} in target template";
                return false;
            }
            for (size_t k = i + 2; k < close; k++) {
                if (!isdigit(static_cast<unsigned char>(rule.target[k]))) {
                    err = "malformed ${n} in target template";
                    return false;
                }
                group = group * 10 + (rule.target[k] - '0');
            }
            i = close;
        } else {
            err = "invalid '$' reference in target template";
            return false;
        }
        if (group == 0) {
            err = "$0 is not allowed in target template (it would be the whole DN)";
            return false;
        }
        if (group > maxGroup) maxGroup = group;
    }
    if (maxGroup > rule.re.mark_count()) {
        err = "target template references $" + std::to_string(maxGroup) +
              " but the pattern has only " + std::to_string(rule.re.mark_count()) + " capture group(s)";
        return false;
    }
    return true;
}

bool ExpandTemplate(const std::string &tmpl, const std::smatch &m, std::string &out)
{
    out.clear();
    for (size_t i = 0; i < tmpl.size(); i++) {
        char c = tmpl[i];
        if (c != '$') {
            out += c;
            continue;
        }
        if (i + 1 == tmpl.size()) return false;
        char n = tmpl[i + 1];
        size_t group;
        if (n == '$') {
            out += '$';
            i++;
            continue;
        } else if (isdigit(static_cast<unsigned char>(n))) {
            group = n - '0';
            i++;
        } else if (n == '{') {
            size_t close = tmpl.find('}', i + 2);
            if (close == std::string::npos || close == i + 2) return false;
            group = 0;
            for (size_t k = i + 2; k < close; k++) {
                if (!isdigit(static_cast<unsigned char>(tmpl[k]))) return false;
                group = group * 10 + (tmpl[k] - '0');
                if (group > 1000) return false;
            }
            i = close;
        } else {
            return false;
        }
        if (group == 0 || m.empty() || group >= m.size() || !m[group].matched) return false;
        out += m[group].str();
    }
    return true;
}

bool ParseVomsLine(const std::string &line, std::vector<std::string> &entry,
                   std::string &target)
{
    bool began_entry = false;
    bool finish_entry = false;
    bool began_target = false;
    std::string element;
    element.reserve(16);
    for (size_t idx = 0; idx < line.size(); idx++) {
        auto txt = line[idx];
        if (!began_entry && !finish_entry) {
            if (txt == '#') {return false;}
            else if (txt == '"') {began_entry = true;}
            else if (!isspace(static_cast<unsigned char>(txt))) {return false;}
            continue;
        } else if (began_entry && !finish_entry) {
            if (txt == '\\') {
                if (idx + 1 == line.size()) {return false;}
                idx++;
                auto escaped_char = line[idx];
                switch (escaped_char) {
                case '\'': element += "'";  break;
                case '\"': element += "\""; break;
                case '/':  element += "/";  break;
                case 'f':  element += "\f"; break;
                case 'n':  element += "\n"; break;
                case 'r':  element += "\r"; break;
                case 't':  element += "\t"; break;
                default:
                    return false;
                };
            } else if (txt == '"') {
                if (!element.empty()) entry.push_back(element);
                finish_entry = true;
            } else if (txt == '/') {
                if (!element.empty()) entry.push_back(element);
                element.clear();
            } else if (isprint(static_cast<unsigned char>(txt))) {
                element += txt;
            } else {
                return false;
            }
        } else if (!began_target) {
            if (isspace(static_cast<unsigned char>(txt))) {continue;}
            began_target = true;
        }
        if (began_target) {
            if (isprint(static_cast<unsigned char>(txt)) && !isspace(static_cast<unsigned char>(txt))) {
                target += txt;
            } else if (isspace(static_cast<unsigned char>(txt))) {
                // Only whitespace or a comment may follow the target.
                for (idx++; idx < line.size(); idx++) {
                    if (line[idx] == '#') return true;
                    if (!isspace(static_cast<unsigned char>(line[idx]))) return false;
                }
                return true;
            } else {
                return false;
            }
        }
    }
    return true;
}

bool GlobStarMatch(const std::string &pattern, const std::string &str)
{
    // Port of XrdOucString::matches(s, '*') with `this` = str, s = pattern.
    const char wch = '*';
    const char *s = pattern.c_str();
    const int len = static_cast<int>(str.size());
    const int ls = static_cast<int>(pattern.size());
    if (ls == 0) return false;

    if (!strchr(s, wch)) return str == pattern;
    if (ls == 1) return true;

    int rc = 1;
    int cs = 0;
    int tb = 0;
    const char *ps = strchr(s + tb, wch);
    bool next = true;
    while (next) {
        int te = ps ? static_cast<int>(ps - s) : ls;
        int ts = te - tb;
        if (ts) {
            bool found = false;
            while (cs < len) {
                if (!strncmp(str.c_str() + cs, s + tb, ts)) {
                    cs += ts;
                    found = true;
                    break;
                }
                cs++;
            }
            if (!found) {
                rc = 0;
                break;
            }
        }
        tb = te + 1;
        ps = (tb < ls) ? strchr(s + tb, wch) : nullptr;
        next = (ps || (tb < ls));
    }
    if (s[ls - 1] != wch && cs < len) rc = 0;

    int nm = 0;
    if (rc > 0) {
        nm = ls;
        for (int n = ls; n--; ) {
            if (s[n] == wch) nm--;
        }
    }
    return nm != 0;
}

bool VomsCompare(const VomsRule &rule, const std::vector<std::string> &fqan)
{
    if (rule.path.empty()) return false;

    // A more specific mapfile entry cannot match a generic FQAN
    if (fqan.size() < rule.path.size()) return false;

    for (size_t idx = 0; idx < rule.path.size(); idx++) {
        if (!GlobStarMatch(rule.path[idx], fqan[idx])) return false;
    }
    if (fqan.size() == rule.path.size()) return true;
    if (rule.path.back() == "*") return true;
    return false;
}

std::vector<std::string> SplitFqan(const std::string &fqan)
{
    std::vector<std::string> path;
    size_t start = 0;
    while (start <= fqan.size()) {
        size_t slash = fqan.find('/', start);
        if (slash == std::string::npos) slash = fqan.size();
        if (slash > start) path.emplace_back(fqan.substr(start, slash - start));
        start = slash + 1;
    }
    return path;
}

bool IsSafeUsername(const std::string &name)
{
    if (name.empty() || name[0] == '-') return false;
    for (unsigned char c : name) {
        if (!isalnum(c) && c != '_' && c != '.' && c != '@' && c != '-') return false;
    }
    return true;
}

} // namespace X509Map
