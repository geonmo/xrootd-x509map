// Copyright 2026 KISTI-GSDC
// SPDX-License-Identifier: Apache-2.0
#ifndef X509MAP_MAPPER_HH
#define X509MAP_MAPPER_HH

#include <sys/types.h>

#include <cstdint>
#include <ctime>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "X509MapLog.hh"
#include "X509MapRules.hh"

class XrdSecEntity;

namespace X509Map {

// Options of both plugins ("key=value" words after the library path).
// Both plugins must be given the same values.
struct X509MapConfig {
    std::string localmap;               // localmap=  DN rules (exact/glob/regex), absolute path
    std::string vomsmap;                // vomsmap=   voms-mapfile syntax, absolute path
    uid_t       minuid     = 500;       // mapped accounts below these are rejected
    gid_t       mingid     = 500;       //   (keep equal to multiuser.minuid/mingid)
    int         cacheto    = 600;   // positive mapping / passwd cache TTL (s), 0 = off
    int         negcacheto = 60;    // negative mapping / passwd cache TTL (s), 0 = off
    int         reloadsec  = 30;    // map file change check interval (s), 0 = never
    bool        debug      = false;     // "debug": log every rule decision
};

// Outcome of one mapping. `source` tells which stage produced the account.
struct X509MapResult {
    enum Source { None, Gridmap, Local, Voms };

    bool        ok = false;
    std::string user;
    std::string reason;   // deny reason, or the matching rule on success
    Source      source = None;

    static const char *SourceName(Source s);
};

// The mapping core shared by both plugins (each plugin owns one instance).
// It knows nothing about XRootD requests: it maps (DN, FQANs, gridmap
// account) to an account name, in this order:
//   1. gridmap account set by gsi/XrdHttp, if it passes ValidateAccount
//   2. local DN map, first matching rule whose account is valid
//   3. VOMS map, FQANs in VOMS order (primary first), first valid match
//   4. deny, with a reason for the log
// "Valid" means a safe name that exists in passwd with uid/gid >= minuid/
// mingid; a rule pointing at an invalid account is skipped, not fatal.
//
// Map files are re-read lazily (at most every reloadsec seconds, when their
// stat stamp changes) without blocking callers; a broken new file keeps the
// previous rules. Results are cached per (rules generation, DN, gridmap,
// FQANs) for cacheto (success) or negcacheto (deny) seconds, and passwd
// lookups are cached the same way. All public methods are thread safe.
class X509Mapper {
public:
    // Returns 0 and fills uid/gid if the account exists, ENOENT if it does
    // not, or another errno value on lookup failure.
    using AccountLookup = std::function<int(const std::string &, uid_t &, gid_t &)>;
    using Clock         = std::function<time_t()>;

    explicit X509Mapper(Logger &log);

    // Parse "key=value key=value debug" and load the map files.
    bool Configure(const char *parms, std::string &err);
    // Load the map files using an already-filled configuration.
    bool Configure(const X509MapConfig &cfg, std::string &err);

    // Map one identity. `dn` may be empty (then only the gridmap account can
    // match), `fqans` in VOMS order, `gridmap_name` empty if gsi/XrdHttp did
    // not map the DN through a grid-mapfile.
    X509MapResult Map(const std::string &dn, const std::vector<std::string> &fqans,
                   const std::string &gridmap_name);

    const X509MapConfig &Config() const { return m_cfg; }
    // Incremented on every successful reload; part of the cache key.
    uint64_t Generation();
    size_t   LocalRuleCount();
    size_t   VomsRuleCount();

    // Subject DN: moninfo if it is a DN, else name if it is a DN, else "".
    static std::string ExtractDN(const XrdSecEntity &e);
    // FQANs in VOMS order: endorsements (comma separated) if present, else
    // the zipped vorg/grps/role tuples. Each FQAN is normalised to
    // "/<group>/Role=<r>/Capability=<c>".
    static std::vector<std::string> ExtractFqans(const XrdSecEntity &e);
    static std::vector<std::string> ExtractFqans(const char *endorsements, const char *vorg,
                                                 const char *grps, const char *role);

    // Test hooks (the plugins never call these).
    void SetAccountLookup(AccountLookup fn) { m_lookup = std::move(fn); }
    void SetClock(Clock fn) { m_clock = std::move(fn); }
    void SetReloadInterval(int sec) { m_cfg.reloadsec = sec; }
    void SetCacheTTL(int pos, int neg) { m_cfg.cacheto = pos; m_cfg.negcacheto = neg; }

private:
    struct FileStamp {
        dev_t  dev = 0;
        ino_t  ino = 0;
        off_t  size = 0;
        struct timespec mtime{};
        struct timespec ctime{};
        bool operator==(const FileStamp &o) const;
    };
    struct CacheEntry {
        X509MapResult result;
        time_t     expires;
    };
    struct PwEntry {
        int    rc;
        uid_t  uid;
        gid_t  gid;
        time_t expires;
    };

    bool LoadLocal(const std::string &path, std::vector<LocalRule> &rules, std::string &err);
    bool LoadVoms(const std::string &path, std::vector<VomsRule> &rules, std::string &err);
    static bool Stamp(const std::string &path, FileStamp &st);

    std::shared_ptr<const RuleSet> Rules();
    void MaybeReload();

    bool ValidateAccount(const std::string &user, std::string &why);
    bool MatchLocal(const RuleSet &rs, const std::string &dn, X509MapResult &res);
    bool MatchVoms(const RuleSet &rs, const std::vector<std::string> &fqans, X509MapResult &res);

    time_t Now() const { return m_clock ? m_clock() : time(nullptr); }
    void Log(int mask, const std::string &msg, const char *ep = "Map") { m_log.Log(mask, ep, msg); }

    Logger         &m_log;
    X509MapConfig      m_cfg;
    AccountLookup   m_lookup;
    Clock           m_clock;

    std::mutex                      m_rulesMtx;   // guards m_rules
    std::shared_ptr<const RuleSet>  m_rules;
    std::mutex                      m_reloadMtx;  // guards the fields below
    time_t                          m_lastCheck = 0;
    FileStamp                       m_localStamp, m_vomsStamp;

    std::mutex                                  m_cacheMtx;
    std::unordered_map<std::string, CacheEntry> m_cache;
    uint64_t                                    m_cacheGen = 0;
    std::mutex                                  m_pwMtx;
    std::unordered_map<std::string, PwEntry>    m_pwcache;

    static const size_t kMaxCache = 10000;
};

} // namespace X509Map

#endif
