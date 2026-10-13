// Copyright 2026 KISTI-GSDC
// SPDX-License-Identifier: Apache-2.0
#include "X509Mapper.hh"

#include <sys/stat.h>
#include <pwd.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

#include "XrdSec/XrdSecEntity.hh"

namespace X509Map {

const char *X509MapResult::SourceName(Source s)
{
    switch (s) {
    case Gridmap: return "gridmap";
    case Local:   return "local";
    case Voms:    return "voms";
    default:      return "none";
    }
}

namespace {

// getpwnam_r with a growing buffer (sssd/LDAP entries can exceed the
// sysconf hint). Returns 0, ENOENT, or the lookup errno.
int DefaultLookup(const std::string &user, uid_t &uid, gid_t &gid)
{
    struct passwd pwd, *result = nullptr;
    long buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (buflen < 0) buflen = 16384;
    std::vector<char> buf(buflen);
    int rc;
    do {
        rc = getpwnam_r(user.c_str(), &pwd, buf.data(), buf.size(), &result);
        if (result == nullptr && rc == ERANGE) {
            buf.resize(buf.size() * 2);
            continue;
        }
        break;
    } while (true);
    if (result == nullptr) return rc ? rc : ENOENT;
    uid = pwd.pw_uid;
    gid = pwd.pw_gid;
    return 0;
}

bool ParseNumber(const std::string &key, const std::string &val, long lo, long hi,
                 long &out, std::string &err)
{
    if (val.empty()) {
        err = key + "= requires a value";
        return false;
    }
    char *end = nullptr;
    errno = 0;
    long v = strtol(val.c_str(), &end, 10);
    if (errno || !end || *end || v < lo || v > hi) {
        err = "invalid value for " + key + "=" + val + " (allowed " + std::to_string(lo) +
              ".." + std::to_string(hi) + ")";
        return false;
    }
    out = v;
    return true;
}

std::string JoinFqans(const std::vector<std::string> &fqans)
{
    std::string s;
    for (const auto &f : fqans) {
        if (!s.empty()) s += ',';
        s += f;
    }
    return s.empty() ? "<none>" : s;
}

// Bring an FQAN into the "/group/Role=r/Capability=c" form used by
// voms-mapfile rules, adding Role=NULL / Capability=NULL when missing.
std::string NormaliseFqan(std::string fqan)
{
    for (auto &c : fqan) {
        if (c == '\t') c = ' ';
    }
    auto path = SplitFqan(fqan);
    if (path.empty()) return "";
    bool hasRole = false, hasCap = false;
    for (const auto &p : path) {
        if (p.compare(0, 5, "Role=") == 0) hasRole = true;
        if (p.compare(0, 11, "Capability=") == 0) hasCap = true;
    }
    if (!hasRole) path.emplace_back("Role=NULL");
    if (!hasCap) path.emplace_back("Capability=NULL");
    std::string out;
    for (const auto &p : path) out += "/" + p;
    return out;
}

std::vector<std::string> Tokenize(const char *s, char sep)
{
    std::vector<std::string> out;
    if (!s) return out;
    std::string cur;
    for (const char *p = s; ; p++) {
        if (*p == sep || *p == '\0') {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
            if (*p == '\0') break;
        } else {
            cur += *p;
        }
    }
    return out;
}

} // namespace

bool X509Mapper::FileStamp::operator==(const FileStamp &o) const
{
    return dev == o.dev && ino == o.ino && size == o.size &&
           mtime.tv_sec == o.mtime.tv_sec && mtime.tv_nsec == o.mtime.tv_nsec &&
           ctime.tv_sec == o.ctime.tv_sec && ctime.tv_nsec == o.ctime.tv_nsec;
}

X509Mapper::X509Mapper(Logger &log) : m_log(log), m_lookup(DefaultLookup) {}

// Unknown options are errors rather than warnings: a mistyped option would
// otherwise silently fall back to a default (e.g. minuid=500).
bool X509Mapper::Configure(const char *parms, std::string &err)
{
    X509MapConfig cfg;
    std::istringstream in(parms ? parms : "");
    std::string tok;
    while (in >> tok) {
        if (tok == "debug") {
            cfg.debug = true;
            continue;
        }
        auto eq = tok.find('=');
        if (eq == std::string::npos) {
            err = "unknown option '" + tok + "'";
            return false;
        }
        std::string key = tok.substr(0, eq), val = tok.substr(eq + 1);
        long n;
        if (key == "localmap") {
            cfg.localmap = val;
        } else if (key == "vomsmap") {
            cfg.vomsmap = val;
        } else if (key == "minuid") {
            if (!ParseNumber(key, val, 0, 0x7fffffff, n, err)) return false;
            cfg.minuid = static_cast<uid_t>(n);
        } else if (key == "mingid") {
            if (!ParseNumber(key, val, 0, 0x7fffffff, n, err)) return false;
            cfg.mingid = static_cast<gid_t>(n);
        } else if (key == "cacheto") {
            if (!ParseNumber(key, val, 0, 86400, n, err)) return false;
            cfg.cacheto = static_cast<int>(n);
        } else if (key == "negcacheto") {
            if (!ParseNumber(key, val, 0, 86400, n, err)) return false;
            cfg.negcacheto = static_cast<int>(n);
        } else if (key == "reloadsec") {
            if (!ParseNumber(key, val, 0, 86400, n, err)) return false;
            cfg.reloadsec = static_cast<int>(n);
        } else if (key == "debug") {
            if (val == "1" || val == "yes" || val == "true") cfg.debug = true;
            else if (val == "0" || val == "no" || val == "false") cfg.debug = false;
            else {
                err = "invalid value for debug=" + val;
                return false;
            }
        } else {
            err = "unknown option '" + key + "'";
            return false;
        }
        if ((key == "localmap" || key == "vomsmap") && (val.empty() || val[0] != '/')) {
            err = key + "= must be an absolute path";
            return false;
        }
    }
    return Configure(cfg, err);
}

bool X509Mapper::Configure(const X509MapConfig &cfg, std::string &err)
{
    err.clear();
    if (cfg.localmap.empty() && cfg.vomsmap.empty()) {
        err = "at least one of localmap= or vomsmap= must be given";
        return false;
    }
    m_cfg = cfg;

    auto rs = std::make_shared<RuleSet>();
    FileStamp ls, vs;
    if (!m_cfg.localmap.empty()) {
        if (!Stamp(m_cfg.localmap, ls) || !LoadLocal(m_cfg.localmap, rs->local, err)) {
            if (err.empty()) err = "cannot stat local map " + m_cfg.localmap + ": " + strerror(errno);
            return false;
        }
    }
    if (!m_cfg.vomsmap.empty()) {
        if (!Stamp(m_cfg.vomsmap, vs) || !LoadVoms(m_cfg.vomsmap, rs->voms, err)) {
            if (err.empty()) err = "cannot stat VOMS map " + m_cfg.vomsmap + ": " + strerror(errno);
            return false;
        }
    }
    rs->generation = 1;
    {
        std::lock_guard<std::mutex> lk(m_reloadMtx);
        m_localStamp = ls;
        m_vomsStamp  = vs;
        m_lastCheck  = Now();
    }
    {
        std::lock_guard<std::mutex> lk(m_rulesMtx);
        m_rules = rs;
    }
    Log(Info, "loaded " + std::to_string(rs->local.size()) + " local / " +
              std::to_string(rs->voms.size()) + " voms rules (generation 1)", "Config");
    return true;
}

bool X509Mapper::Stamp(const std::string &path, FileStamp &st)
{
    struct stat sb;
    if (stat(path.c_str(), &sb) != 0) return false;
    st.dev   = sb.st_dev;
    st.ino   = sb.st_ino;
    st.size  = sb.st_size;
    st.mtime = sb.st_mtim;
    st.ctime = sb.st_ctim;
    return true;
}

bool X509Mapper::LoadLocal(const std::string &path, std::vector<LocalRule> &rules, std::string &err)
{
    std::ifstream in(path);
    if (!in.is_open()) {
        err = "cannot open local map " + path + ": " + strerror(errno);
        return false;
    }
    std::string line, perr;
    int lineno = 0;
    while (std::getline(in, line)) {
        lineno++;
        LocalRule rule;
        if (ParseLocalLine(line, rule, perr)) {
            rule.lineno = lineno;
            rules.push_back(std::move(rule));
        } else if (!perr.empty()) {
            Log(Warning, path + ":" + std::to_string(lineno) + ": " + perr + "; line ignored");
        }
    }
    if (in.bad()) {
        err = "error reading local map " + path;
        return false;
    }
    return true;
}

bool X509Mapper::LoadVoms(const std::string &path, std::vector<VomsRule> &rules, std::string &err)
{
    std::ifstream in(path);
    if (!in.is_open()) {
        err = "cannot open VOMS map " + path + ": " + strerror(errno);
        return false;
    }
    std::string line;
    int lineno = 0;
    while (std::getline(in, line)) {
        lineno++;
        size_t first = line.find_first_not_of(" \t\r\n\f\v");
        if (first == std::string::npos || line[first] == '#') continue;
        VomsRule rule;
        if (!ParseVomsLine(line, rule.path, rule.target) || rule.path.empty() ||
            rule.target.empty()) {
            Log(Warning, path + ":" + std::to_string(lineno) + ": malformed VOMS map line; ignored");
            continue;
        }
        if (!IsSafeUsername(rule.target)) {
            Log(Warning, path + ":" + std::to_string(lineno) + ": unsafe target account '" +
                         rule.target + "'; line ignored");
            continue;
        }
        rule.lineno = lineno;
        rules.push_back(std::move(rule));
    }
    if (in.bad()) {
        err = "error reading VOMS map " + path;
        return false;
    }
    return true;
}

std::shared_ptr<const RuleSet> X509Mapper::Rules()
{
    std::lock_guard<std::mutex> lk(m_rulesMtx);
    return m_rules;
}

uint64_t X509Mapper::Generation()
{
    auto rs = Rules();
    return rs ? rs->generation : 0;
}

size_t X509Mapper::LocalRuleCount()
{
    auto rs = Rules();
    return rs ? rs->local.size() : 0;
}

size_t X509Mapper::VomsRuleCount()
{
    auto rs = Rules();
    return rs ? rs->voms.size() : 0;
}

// Called at the start of every Map(). At most one thread checks the files
// (try_lock); the others keep using the current rules. A file that changed
// is parsed into a new RuleSet that is published atomically with a new
// generation, which also invalidates the result cache. On any error the
// previous rules stay active and the check is retried after reloadsec.
void X509Mapper::MaybeReload()
{
    if (m_cfg.reloadsec <= 0) return;
    std::unique_lock<std::mutex> lk(m_reloadMtx, std::try_to_lock);
    if (!lk.owns_lock()) return;   // another thread is checking; use current rules
    time_t now = Now();
    if (now - m_lastCheck < m_cfg.reloadsec) return;
    m_lastCheck = now;

    FileStamp ls, vs;
    bool localChanged = false, vomsChanged = false;
    if (!m_cfg.localmap.empty()) {
        if (!Stamp(m_cfg.localmap, ls)) {
            Log(Error, "cannot stat local map " + m_cfg.localmap + ": " + strerror(errno) +
                       "; keeping previous rules");
            return;
        }
        localChanged = !(ls == m_localStamp);
    }
    if (!m_cfg.vomsmap.empty()) {
        if (!Stamp(m_cfg.vomsmap, vs)) {
            Log(Error, "cannot stat VOMS map " + m_cfg.vomsmap + ": " + strerror(errno) +
                       "; keeping previous rules");
            return;
        }
        vomsChanged = !(vs == m_vomsStamp);
    }
    if (!localChanged && !vomsChanged) return;

    auto old = Rules();
    auto rs = std::make_shared<RuleSet>();
    std::string err;
    if (localChanged) {
        if (!LoadLocal(m_cfg.localmap, rs->local, err)) {
            Log(Error, err + "; keeping previous rules");
            return;
        }
    } else if (old) {
        rs->local = old->local;
    }
    if (vomsChanged) {
        if (!LoadVoms(m_cfg.vomsmap, rs->voms, err)) {
            Log(Error, err + "; keeping previous rules");
            return;
        }
    } else if (old) {
        rs->voms = old->voms;
    }
    rs->generation = (old ? old->generation : 0) + 1;
    m_localStamp = ls;
    m_vomsStamp  = vs;
    {
        std::lock_guard<std::mutex> rlk(m_rulesMtx);
        m_rules = rs;
    }
    std::string what = localChanged && vomsChanged ? "local and VOMS maps"
                     : localChanged ? "local map" : "VOMS map";
    Log(Info, "reloaded " + what + " (generation " + std::to_string(rs->generation) + "): " +
              std::to_string(rs->local.size()) + " local / " + std::to_string(rs->voms.size()) +
              " voms rules", "Reload");
}

// Gatekeeper for every candidate account (gridmap, local and VOMS rules):
// rejects unsafe names (no path or option injection into multiuser), missing
// accounts and system accounts below minuid/mingid. `why` explains a
// rejection for the debug/deny log.
bool X509Mapper::ValidateAccount(const std::string &user, std::string &why)
{
    if (!IsSafeUsername(user)) {
        why = "unsafe account name '" + user + "'";
        return false;
    }
    time_t now = Now();
    PwEntry pe{};
    bool cached = false;
    {
        std::lock_guard<std::mutex> lk(m_pwMtx);
        auto it = m_pwcache.find(user);
        if (it != m_pwcache.end() && it->second.expires > now) {
            pe = it->second;
            cached = true;
        }
    }
    if (!cached) {
        pe.uid = 0;
        pe.gid = 0;
        pe.rc  = m_lookup(user, pe.uid, pe.gid);
        int ttl = pe.rc == 0 ? m_cfg.cacheto : m_cfg.negcacheto;
        // Transient lookup errors (sssd/LDAP down) are not cached.
        if (ttl > 0 && (pe.rc == 0 || pe.rc == ENOENT)) {
            pe.expires = now + ttl;
            std::lock_guard<std::mutex> lk(m_pwMtx);
            if (m_pwcache.size() >= kMaxCache) m_pwcache.clear();
            m_pwcache[user] = pe;
        }
    }
    if (pe.rc == ENOENT) {
        why = "account '" + user + "' does not exist";
        return false;
    }
    if (pe.rc != 0) {
        why = "lookup of account '" + user + "' failed: " + strerror(pe.rc);
        return false;
    }
    if (pe.uid < m_cfg.minuid) {
        why = "account '" + user + "' uid " + std::to_string(pe.uid) + " < minuid " +
              std::to_string(m_cfg.minuid);
        return false;
    }
    if (pe.gid < m_cfg.mingid) {
        why = "account '" + user + "' gid " + std::to_string(pe.gid) + " < mingid " +
              std::to_string(m_cfg.mingid);
        return false;
    }
    return true;
}

// First rule (in file order) that matches the DN and yields a valid account.
bool X509Mapper::MatchLocal(const RuleSet &rs, const std::string &dn, X509MapResult &res)
{
    for (const auto &rule : rs.local) {
        std::string user;
        if (rule.kind == LocalRule::Exact) {
            if (dn != rule.pattern) continue;
            user = rule.target;
        } else {
            std::smatch m;
            if (!std::regex_match(dn, m, rule.re)) continue;
            if (!ExpandTemplate(rule.target, m, user)) {
                if (m_log.Enabled(Debug))
                    Log(Debug, "local rule line " + std::to_string(rule.lineno) +
                               " matched but template expansion failed");
                continue;
            }
        }
        std::string why;
        if (!ValidateAccount(user, why)) {
            if (m_log.Enabled(Debug))
                Log(Debug, "local rule line " + std::to_string(rule.lineno) + " matched dn=" + dn +
                           " but " + why + "; trying next rule");
            continue;
        }
        res.ok     = true;
        res.user   = user;
        res.source = X509MapResult::Local;
        res.reason = "local map line " + std::to_string(rule.lineno);
        return true;
    }
    return false;
}

// Same precedence as XrdVomsMapfile: FQANs are tried in VOMS order and, for
// each FQAN, rules in file order, so the primary FQAN wins over a more
// specific rule for a secondary FQAN.
bool X509Mapper::MatchVoms(const RuleSet &rs, const std::vector<std::string> &fqans, X509MapResult &res)
{
    for (const auto &fqan : fqans) {
        auto path = SplitFqan(fqan);
        if (path.empty()) continue;
        for (const auto &rule : rs.voms) {
            if (!VomsCompare(rule, path)) continue;
            std::string why;
            if (!ValidateAccount(rule.target, why)) {
                if (m_log.Enabled(Debug))
                    Log(Debug, "VOMS rule line " + std::to_string(rule.lineno) + " matched fqan=" +
                               fqan + " but " + why + "; trying next rule");
                continue;
            }
            res.ok     = true;
            res.user   = rule.target;
            res.source = X509MapResult::Voms;
            res.reason = "VOMS map line " + std::to_string(rule.lineno) + " fqan " + fqan;
            return true;
        }
    }
    return false;
}

X509MapResult X509Mapper::Map(const std::string &dn, const std::vector<std::string> &fqans,
                           const std::string &gridmap_name)
{
    MaybeReload();
    auto rs = Rules();
    X509MapResult res;
    if (!rs) {
        res.reason = "mapper not configured";
        return res;
    }

    // Cache key: everything the result depends on. The rules generation makes
    // entries from before a reload unreachable. \x1f cannot appear in a DN.
    std::string key = std::to_string(rs->generation);
    key += '\x1f'; key += dn;
    key += '\x1f'; key += gridmap_name;
    for (const auto &f : fqans) {
        key += '\x1f';
        key += f;
    }

    time_t now = Now();
    {
        std::lock_guard<std::mutex> lk(m_cacheMtx);
        if (m_cacheGen != rs->generation) {
            m_cache.clear();
            m_cacheGen = rs->generation;
        }
        auto it = m_cache.find(key);
        if (it != m_cache.end()) {
            if (it->second.expires > now) return it->second.result;
            m_cache.erase(it);
        }
    }

    // 1. gridmap account (an invalid one is logged and ignored).
    std::string gridmapWhy;
    if (!gridmap_name.empty()) {
        if (ValidateAccount(gridmap_name, gridmapWhy)) {
            res.ok     = true;
            res.user   = gridmap_name;
            res.source = X509MapResult::Gridmap;
            res.reason = "gridmap";
        } else {
            Log(Warning, "ignoring gridmap mapping of dn=" + (dn.empty() ? "<unknown>" : dn) +
                         ": " + gridmapWhy);
        }
    }
    // 2. local DN map, 3. VOMS map, 4. deny.
    if (!res.ok) {
        if (dn.empty()) {
            res.reason = "no subject DN (need -gmapopt:10 or -moninfo)";
        } else if (MatchLocal(*rs, dn, res)) {
        } else if (fqans.empty()) {
            res.reason = "DN not local and no VOMS attributes";
        } else if (MatchVoms(*rs, fqans, res)) {
        } else {
            res.reason = "DN not local and no VOMS mapping";
        }
        if (!res.ok && !gridmapWhy.empty()) res.reason += " (gridmap: " + gridmapWhy + ")";
    }

    // One Info line per cache miss: the audit trail of who became whom.
    if (res.ok) {
        Log(Info, "map dn=" + (dn.empty() ? "<unknown>" : dn) + " fqan=" + JoinFqans(fqans) +
                  " -> " + res.user + " (" + X509MapResult::SourceName(res.source) + ", " +
                  res.reason + ")");
    } else {
        Log(Info, "map dn=" + (dn.empty() ? "<unknown>" : dn) + " fqan=" + JoinFqans(fqans) +
                  " -> DENY (" + res.reason + ")");
    }

    // Denials are cached for a shorter time so a newly created account or
    // map line takes effect quickly. When full, drop expired entries first,
    // then everything (simple bound on memory, no LRU needed).
    int ttl = res.ok ? m_cfg.cacheto : m_cfg.negcacheto;
    if (ttl > 0) {
        std::lock_guard<std::mutex> lk(m_cacheMtx);
        if (m_cacheGen == rs->generation) {
            if (m_cache.size() >= kMaxCache) {
                for (auto it = m_cache.begin(); it != m_cache.end(); ) {
                    if (it->second.expires <= now) it = m_cache.erase(it);
                    else ++it;
                }
                if (m_cache.size() >= kMaxCache) m_cache.clear();
            }
            m_cache[key] = CacheEntry{res, now + ttl};
        }
    }
    return res;
}

// gsi puts the DN in name with -gmapopt:10/11 (when not gridmap-mapped)
// and in moninfo with -moninfo; XrdHttp always puts it in moninfo. A value
// not starting with '/' (subject hash, account name) is not a DN.
std::string X509Mapper::ExtractDN(const XrdSecEntity &e)
{
    if (e.moninfo && e.moninfo[0] == '/') return e.moninfo;
    if (e.name && e.name[0] == '/') return e.name;
    return "";
}

std::vector<std::string> X509Mapper::ExtractFqans(const XrdSecEntity &e)
{
    return ExtractFqans(e.endorsements, e.vorg, e.grps, e.role);
}

// endorsements holds every FQAN when libXrdSecgsiVOMS / libXrdVoms run with
// the default grpopt=useall; with usefirst only the first one is there.
std::vector<std::string> X509Mapper::ExtractFqans(const char *endorsements, const char *vorg,
                                                  const char *grps, const char *role)
{
    std::vector<std::string> out;
    if (endorsements && endorsements[0]) {
        for (auto &f : Tokenize(endorsements, ',')) {
            size_t b = f.find_first_not_of(" ");
            size_t e = f.find_last_not_of(" ");
            if (b == std::string::npos) continue;
            auto n = NormaliseFqan(f.substr(b, e - b + 1));
            if (!n.empty()) out.push_back(n);
        }
        if (!out.empty()) return out;
    }

    // Tuple fallback, same zip as XrdVomsMapfile::Apply.
    auto vos   = Tokenize(vorg, ' ');
    auto groups = Tokenize(grps, ' ');
    auto roles = Tokenize(role, ' ');
    for (size_t i = 0; i < vos.size() && i < groups.size(); i++) {
        auto path = SplitFqan(groups[i]);
        if (path.empty()) continue;
        // The root group must be the VO name; enforce it as XrdVomsMapfile does.
        std::string vo = vos[i];
        for (auto &c : vo) if (c == '\t') c = ' ';
        std::string g0 = path[0];
        for (auto &c : g0) if (c == '\t') c = ' ';
        if (g0 != vo) continue;
        std::string r = (i < roles.size() && !roles[i].empty()) ? roles[i] : "NULL";
        auto n = NormaliseFqan(groups[i] + "/Role=" + r + "/Capability=NULL");
        if (!n.empty()) out.push_back(n);
    }
    return out;
}

} // namespace X509Map
