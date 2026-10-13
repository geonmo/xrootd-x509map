// Copyright 2026 KISTI-GSDC
// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>

#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "X509Mapper.hh"
#include "X509MapRules.hh"
#include "XrdSec/XrdSecEntity.hh"

using namespace X509Map;

namespace {

class CollectLogger : public Logger {
public:
    void Log(int mask, const char *ep, const std::string &msg) override
    {
        if (mask & m_mask) lines.push_back(std::string(ep) + ": " + msg);
    }
    int Mask() const override { return m_mask; }
    bool Contains(const std::string &s) const
    {
        for (const auto &l : lines)
            if (l.find(s) != std::string::npos) return true;
        return false;
    }
    std::vector<std::string> lines;
    int m_mask = All;
};

const char *kLocalMap =
    "# site local users\n"
    "\"/DC=org/DC=example/OU=Site/CN=Alice Kim\" alice   # exact\n"
    "glob \"/DC=org/DC=example/OU=Site/CN=(*)\" $1\n"
    "regex \"/DC=org/DC=example/OU=Site/CN=Robot: ([a-z0-9]+)-.*\" $1\n"
    "this line is broken\n";

const char *kVomsMap =
    "\"/cms/Role=production/Capability=NULL\" cmsprod\n"
    "\"/cms/Role=pilot/Capability=NULL\"      cmspilot\n"
    "\"/cms/*\"                                cms\n"
    "\"/alice/*\"                              alice\n";

class MapperTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        char tmpl[] = "/tmp/x509map-test-XXXXXX";
        ASSERT_NE(mkdtemp(tmpl), nullptr);
        m_dir = tmpl;
        m_local = m_dir + "/local.map";
        m_voms  = m_dir + "/voms.map";
        Write(m_local, kLocalMap);
        Write(m_voms, kVomsMap);

        m_accounts = {{"alice", {1001, 1001}}, {"cmsprod", {2001, 2000}},
                      {"cms", {2000, 2000}},     {"alice", {3000, 3000}},
                      {"root", {0, 0}},          {"bot42", {4242, 4242}},
                      {"sysacct", {1001, 10}}};
    }
    void TearDown() override
    {
        unlink(m_local.c_str());
        unlink(m_voms.c_str());
        rmdir(m_dir.c_str());
    }

    static void Write(const std::string &path, const std::string &content)
    {
        std::string tmp = path + ".tmp";
        std::ofstream out(tmp);
        out << content;
        out.close();
        ASSERT_EQ(rename(tmp.c_str(), path.c_str()), 0);
    }

    void Setup(X509Mapper &m, const std::string &extra = "")
    {
        m.SetAccountLookup([this](const std::string &u, uid_t &uid, gid_t &gid) {
            m_lookups++;
            auto it = m_accounts.find(u);
            if (it == m_accounts.end()) return ENOENT;
            uid = it->second.first;
            gid = it->second.second;
            return 0;
        });
        m.SetClock([this]() { return m_now; });
        std::string parms = "localmap=" + m_local + " vomsmap=" + m_voms + " minuid=1000 mingid=1000 " + extra;
        std::string err;
        ASSERT_TRUE(m.Configure(parms.c_str(), err)) << err;
    }

    std::string m_dir, m_local, m_voms;
    std::map<std::string, std::pair<uid_t, gid_t>> m_accounts;
    time_t m_now = 1000000;
    int m_lookups = 0;
    CollectLogger m_log;
};

const std::string kAlice = "/DC=org/DC=example/OU=Site/CN=Alice Kim";
const std::string kCern   = "/DC=ch/DC=cern/OU=Users/CN=jdoe";
const std::vector<std::string> kNoFqan;

} // namespace

TEST_F(MapperTest, ConfigureCountsRulesAndSkipsBrokenLines)
{
    X509Mapper m(m_log);
    Setup(m);
    EXPECT_EQ(m.LocalRuleCount(), 3u);
    EXPECT_EQ(m.VomsRuleCount(), 4u);
    EXPECT_EQ(m.Generation(), 1u);
    EXPECT_TRUE(m_log.Contains("local.map:5"));
}

TEST_F(MapperTest, ConfigureErrors)
{
    std::string err;
    {
        X509Mapper m(m_log);
        EXPECT_FALSE(m.Configure("minuid=1000", err));
        EXPECT_NE(err.find("localmap"), std::string::npos);
    }
    {
        X509Mapper m(m_log);
        EXPECT_FALSE(m.Configure("localmap=/nonexistent/x509map.map", err));
        EXPECT_NE(err.find("/nonexistent/x509map.map"), std::string::npos);
    }
    {
        X509Mapper m(m_log);
        EXPECT_FALSE(m.Configure(("localmap=" + m_local + " bogus=1").c_str(), err));
    }
    {
        X509Mapper m(m_log);
        EXPECT_FALSE(m.Configure(("localmap=" + m_local + " minuid=abc").c_str(), err));
    }
    {
        X509Mapper m(m_log);
        EXPECT_FALSE(m.Configure("localmap=relative.map", err));
    }
}

TEST_F(MapperTest, ExactDn)
{
    X509Mapper m(m_log);
    Setup(m);
    auto r = m.Map(kAlice, kNoFqan, "");
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.user, "alice");
    EXPECT_EQ(r.source, X509MapResult::Local);
}

TEST_F(MapperTest, GlobCaptureAndUnsafeFallThrough)
{
    X509Mapper m(m_log);
    Setup(m);
    auto r = m.Map("/DC=org/DC=example/OU=Site/CN=alice", kNoFqan, "");
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.user, "alice");

    // "Jane Doe" contains a space: glob expansion is unsafe, falls through to VOMS.
    r = m.Map("/DC=org/DC=example/OU=Site/CN=Jane Doe", {"/cms/Role=NULL/Capability=NULL"}, "");
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.user, "cms");
    EXPECT_EQ(r.source, X509MapResult::Voms);

    // Glob expands to a non-existent account: falls through, no VOMS -> deny.
    r = m.Map("/DC=org/DC=example/OU=Site/CN=nobodyhere", kNoFqan, "");
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.reason, "DN not local and no VOMS attributes");
}

TEST_F(MapperTest, RegexCapture)
{
    X509Mapper m(m_log);
    Setup(m);
    auto r = m.Map("/DC=org/DC=example/OU=Site/CN=Robot: bot42-cron", kNoFqan, "");
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.user, "bot42");
    EXPECT_EQ(r.source, X509MapResult::Local);
}

TEST_F(MapperTest, LocalBeatsVoms)
{
    X509Mapper m(m_log);
    Setup(m);
    auto r = m.Map(kAlice, {"/cms/Role=production/Capability=NULL"}, "");
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.user, "alice");
    EXPECT_EQ(r.source, X509MapResult::Local);
}

TEST_F(MapperTest, VomsRoleBeforeWildcard)
{
    X509Mapper m(m_log);
    Setup(m);
    auto r = m.Map(kCern, {"/cms/Role=production/Capability=NULL"}, "");
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.user, "cmsprod");

    r = m.Map(kCern, {"/cms/Role=NULL/Capability=NULL"}, "");
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.user, "cms");

    r = m.Map(kCern, {"/cms/uscms/Role=NULL/Capability=NULL"}, "");
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.user, "cms");

    // Primary FQAN is tried first.
    r = m.Map(kCern, {"/alice/Role=NULL/Capability=NULL", "/cms/Role=production/Capability=NULL"}, "");
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.user, "alice");
}

TEST_F(MapperTest, VomsTargetInvalidFallsToNextRule)
{
    Write(m_voms, "\"/cms/Role=pilot/Capability=NULL\" cmspilot\n\"/cms/*\" cms\n");
    X509Mapper m(m_log);
    Setup(m);
    // cmspilot account does not exist -> next matching rule.
    auto r = m.Map(kCern, {"/cms/Role=pilot/Capability=NULL"}, "");
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.user, "cms");
}

TEST_F(MapperTest, SpecificEntryDoesNotMatchGenericFqan)
{
    Write(m_voms, "\"/cms/uscms/Role=NULL/Capability=NULL\" cms\n");
    X509Mapper m(m_log);
    Setup(m);
    auto r = m.Map(kCern, {"/cms/Role=NULL/Capability=NULL"}, "");
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.reason, "DN not local and no VOMS mapping");

    VomsRule rule;
    rule.path = SplitFqan("/cms/uscms/Role=NULL/Capability=NULL");
    EXPECT_FALSE(VomsCompare(rule, SplitFqan("/cms/Role=NULL")));
    EXPECT_TRUE(VomsCompare(rule, SplitFqan("/cms/uscms/Role=NULL/Capability=NULL")));
    rule.path = SplitFqan("/cms/uscms");
    EXPECT_FALSE(VomsCompare(rule, SplitFqan("/cms/uscms/Role=NULL/Capability=NULL")));
}

TEST_F(MapperTest, NonLocalNoVomsDenied)
{
    X509Mapper m(m_log);
    Setup(m);
    auto r = m.Map(kCern, kNoFqan, "");
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.reason, "DN not local and no VOMS attributes");
    EXPECT_TRUE(m_log.Contains("-> DENY"));

    r = m.Map("", {"/cms/Role=NULL/Capability=NULL"}, "");
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.reason.find("no subject DN"), std::string::npos);
}

TEST_F(MapperTest, RootAndTraversalTargetsDenied)
{
    Write(m_local,
          "\"/DC=org/DC=example/OU=Site/CN=admin\" root\n"
          "glob \"/DC=org/DC=example/OU=Site/OU=(*)\" $1\n"
          "\"/DC=org/DC=example/OU=Site/CN=sys\" sysacct\n");
    X509Mapper m(m_log);
    Setup(m);
    auto r = m.Map("/DC=org/DC=example/OU=Site/CN=admin", kNoFqan, "");
    EXPECT_FALSE(r.ok);
    r = m.Map("/DC=org/DC=example/OU=Site/OU=../etc", kNoFqan, "");
    EXPECT_FALSE(r.ok);
    r = m.Map("/DC=org/DC=example/OU=Site/CN=sys", kNoFqan, "");
    EXPECT_FALSE(r.ok);  // gid 10 < mingid
    r = m.Map("/DC=org/DC=example/OU=Site/OU=-rf", kNoFqan, "");
    EXPECT_FALSE(r.ok);
}

TEST_F(MapperTest, GridmapNameRespected)
{
    X509Mapper m(m_log);
    Setup(m);
    auto r = m.Map(kCern, kNoFqan, "alice");
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.user, "alice");
    EXPECT_EQ(r.source, X509MapResult::Gridmap);

    // Gridmap without a DN (no -moninfo) still works.
    r = m.Map("", kNoFqan, "alice");
    EXPECT_TRUE(r.ok);

    // Invalid gridmap target falls through to the rules.
    r = m.Map(kCern, {"/cms/Role=NULL/Capability=NULL"}, "root");
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.user, "cms");
    r = m.Map(kCern, kNoFqan, "root");
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.reason.find("gridmap"), std::string::npos);
}

TEST(ExtractTest, FqansFromEndorsements)
{
    auto f = X509Mapper::ExtractFqans("/cms/Role=production/Capability=NULL,/cms/Role=NULL/Capability=NULL",
                                      "cms cms", "/cms /cms", "production NULL");
    ASSERT_EQ(f.size(), 2u);
    EXPECT_EQ(f[0], "/cms/Role=production/Capability=NULL");
    EXPECT_EQ(f[1], "/cms/Role=NULL/Capability=NULL");

    // Missing Role / Capability are normalised; tabs become spaces.
    f = X509Mapper::ExtractFqans("/cms/my\tgroup", nullptr, nullptr, nullptr);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0], "/cms/my group/Role=NULL/Capability=NULL");
}

TEST(ExtractTest, FqansFromTuples)
{
    auto f = X509Mapper::ExtractFqans(nullptr, "cms cms", "/cms/uscms /cms", "NULL production");
    ASSERT_EQ(f.size(), 2u);
    EXPECT_EQ(f[0], "/cms/uscms/Role=NULL/Capability=NULL");
    EXPECT_EQ(f[1], "/cms/Role=production/Capability=NULL");

    // No role at all -> NULL; group whose root differs from the VO is skipped.
    f = X509Mapper::ExtractFqans("", "cms atlas", "/cms /cms", nullptr);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0], "/cms/Role=NULL/Capability=NULL");

    EXPECT_TRUE(X509Mapper::ExtractFqans(nullptr, nullptr, nullptr, nullptr).empty());
}

TEST(ExtractTest, EntityHelpers)
{
    XrdSecEntity e("gsi");
    char dnName[] = "/DC=ch/CN=from-name";
    char dnMon[]  = "/DC=ch/CN=from-moninfo";
    char hash[]   = "a1b2c3d4.0";
    e.name = hash;
    EXPECT_EQ(X509Mapper::ExtractDN(e), "");
    e.name = dnName;
    EXPECT_EQ(X509Mapper::ExtractDN(e), dnName);
    e.moninfo = dnMon;
    EXPECT_EQ(X509Mapper::ExtractDN(e), dnMon);

    char endor[] = "/cms/Role=NULL/Capability=NULL";
    e.endorsements = endor;
    auto f = X509Mapper::ExtractFqans(e);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0], endor);

    // Do not let ~XrdSecEntity free stack buffers.
    e.name = e.moninfo = e.endorsements = nullptr;
}

TEST_F(MapperTest, ReloadOnChangeInvalidatesCache)
{
    X509Mapper m(m_log);
    Setup(m, "reloadsec=30");
    const std::string dn = "/C=KR/O=OTHER/CN=newuser";
    EXPECT_FALSE(m.Map(dn, kNoFqan, "").ok);

    Write(m_local, std::string(kLocalMap) + "\"" + dn + "\" alice\n");
    // Not yet: inside the reload interval the negative cache answers.
    m_now += 10;
    EXPECT_FALSE(m.Map(dn, kNoFqan, "").ok);
    EXPECT_EQ(m.Generation(), 1u);

    m_now += 30;
    auto r = m.Map(dn, kNoFqan, "");
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.user, "alice");
    EXPECT_EQ(m.Generation(), 2u);
    EXPECT_TRUE(m_log.Contains("reloaded local map (generation 2)"));

    // Unchanged files do not bump the generation.
    m_now += 60;
    m.Map(dn, kNoFqan, "");
    EXPECT_EQ(m.Generation(), 2u);
}

TEST_F(MapperTest, ReloadFailureKeepsRules)
{
    X509Mapper m(m_log);
    Setup(m, "reloadsec=1");
    unlink(m_local.c_str());
    m_now += 5;
    auto r = m.Map(kAlice, kNoFqan, "");
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(m.Generation(), 1u);
    EXPECT_TRUE(m_log.Contains("keeping previous rules"));
}

TEST_F(MapperTest, CacheAndNegativeTtl)
{
    X509Mapper m(m_log);
    Setup(m, "cacheto=600 negcacheto=60 reloadsec=0");
    const std::string dn = "/DC=org/DC=example/OU=Site/CN=newbie";
    EXPECT_FALSE(m.Map(dn, kNoFqan, "").ok);

    // Account appears; negative entries still answer until they expire.
    m_accounts["newbie"] = {5000, 5000};
    m_now += 30;
    EXPECT_FALSE(m.Map(dn, kNoFqan, "").ok);
    m_now += 31;
    auto r = m.Map(dn, kNoFqan, "");
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.user, "newbie");

    // Positive hits are served from cache without a passwd lookup.
    int before = m_lookups;
    for (int i = 0; i < 5; i++) EXPECT_TRUE(m.Map(dn, kNoFqan, "").ok);
    EXPECT_EQ(m_lookups, before);
}

TEST(RulesTest, VomsLineEscapes)
{
    std::vector<std::string> path;
    std::string target;
    EXPECT_TRUE(ParseVomsLine("\"/cms/Role=a\\\"b/Capability=NULL\" cms", path, target));
    ASSERT_EQ(path.size(), 3u);
    EXPECT_EQ(path[1], "Role=a\"b");
    EXPECT_EQ(target, "cms");

    path.clear(); target.clear();
    EXPECT_TRUE(ParseVomsLine("\"/cms/x\\/y\" cms  # comment", path, target));
    ASSERT_EQ(path.size(), 2u);
    EXPECT_EQ(path[1], "x/y");
    EXPECT_EQ(target, "cms");

    path.clear(); target.clear();
    EXPECT_TRUE(ParseVomsLine("\"/cms/#notacomment\" cms", path, target));
    EXPECT_EQ(path[1], "#notacomment");

    path.clear(); target.clear();
    EXPECT_FALSE(ParseVomsLine("# \"/cms\" cms", path, target));
    path.clear(); target.clear();
    EXPECT_FALSE(ParseVomsLine("\"/cms\\q\" cms", path, target));
    path.clear(); target.clear();
    EXPECT_FALSE(ParseVomsLine("\"/cms\" cms extra", path, target));
}

TEST(RulesTest, LocalLineParsing)
{
    LocalRule rule;
    std::string err;
    EXPECT_FALSE(ParseLocalLine("   # comment", rule, err));
    EXPECT_TRUE(err.empty());
    EXPECT_FALSE(ParseLocalLine("", rule, err));
    EXPECT_TRUE(err.empty());

    EXPECT_TRUE(ParseLocalLine("\"/C=KR/CN=A \\\"B\\\"\" usera", rule, err)) << err;
    EXPECT_EQ(rule.pattern, "/C=KR/CN=A \"B\"");
    EXPECT_EQ(rule.kind, LocalRule::Exact);

    EXPECT_TRUE(ParseLocalLine("regex \"/C=KR/CN=x\\.(\\d+)\" u$1", rule, err)) << err;
    std::smatch m;
    std::string dn = "/C=KR/CN=x.42", out;
    ASSERT_TRUE(std::regex_match(dn, m, rule.re));
    ASSERT_TRUE(ExpandTemplate(rule.target, m, out));
    EXPECT_EQ(out, "u42");
    dn = "/C=KR/CN=xy42";
    EXPECT_FALSE(std::regex_match(dn, m, rule.re));
    dn = "prefix/C=KR/CN=x.42";
    EXPECT_FALSE(std::regex_match(dn, m, rule.re));  // anchored

    // Glob metacharacters are escaped.
    EXPECT_TRUE(ParseLocalLine("glob \"/C=KR/CN=a.b (*)\" ${1}", rule, err)) << err;
    dn = "/C=KR/CN=a.b x";
    EXPECT_TRUE(std::regex_match(dn, m, rule.re));
    dn = "/C=KR/CN=aXb x";
    EXPECT_FALSE(std::regex_match(dn, m, rule.re));

    // Rejections.
    EXPECT_FALSE(ParseLocalLine("glob \"*\" $1", rule, err));
    EXPECT_FALSE(err.empty());
    EXPECT_FALSE(ParseLocalLine("glob \"/C=KR/CN=(*)\" $2", rule, err));
    EXPECT_FALSE(ParseLocalLine("regex \"/C=KR/CN=(\" $1", rule, err));
    EXPECT_FALSE(ParseLocalLine("\"/C=KR/CN=x\" $1", rule, err));
    EXPECT_FALSE(ParseLocalLine("\"/C=KR/CN=x\" ../etc", rule, err));
    EXPECT_FALSE(ParseLocalLine("\"/C=KR/CN=x\"", rule, err));
    EXPECT_FALSE(ParseLocalLine("\"/C=KR/CN=x\" a b", rule, err));
    EXPECT_FALSE(ParseLocalLine("wildcard \"/C=KR\" a", rule, err));
    EXPECT_FALSE(ParseLocalLine("glob \"/C=KR/CN=(*)\" $0", rule, err));
}

TEST(RulesTest, GlobStarMatchMatchesXrdOucString)
{
    EXPECT_TRUE(GlobStarMatch("*", "anything"));
    EXPECT_TRUE(GlobStarMatch("Role=*", "Role=production"));
    EXPECT_FALSE(GlobStarMatch("Role=*", "Capability=NULL"));
    EXPECT_TRUE(GlobStarMatch("cms", "cms"));
    EXPECT_FALSE(GlobStarMatch("cms", "cmsx"));
    EXPECT_TRUE(GlobStarMatch("*prod*", "Role=production"));
    EXPECT_FALSE(GlobStarMatch("a*c", "abd"));
}

TEST(RulesTest, SafeUsernames)
{
    EXPECT_TRUE(IsSafeUsername("alice"));
    EXPECT_TRUE(IsSafeUsername("cms.prod_01@x-y"));
    EXPECT_FALSE(IsSafeUsername(""));
    EXPECT_FALSE(IsSafeUsername("-rf"));
    EXPECT_FALSE(IsSafeUsername("../etc"));
    EXPECT_FALSE(IsSafeUsername("a b"));
    EXPECT_FALSE(IsSafeUsername("a/b"));
}

TEST(SampleConfigs, ParseWithoutWarnings)
{
    CollectLogger log;
    X509Mapper m(log);
    std::string err;
    std::string parms = std::string("localmap=") + X509MAP_CONFIG_DIR + "/x509map-local.map vomsmap=" +
                        X509MAP_CONFIG_DIR + "/x509map-voms.map";
    ASSERT_TRUE(m.Configure(parms.c_str(), err)) << err;
    for (const auto &l : log.lines) EXPECT_EQ(l.find("ignored"), std::string::npos) << l;
    EXPECT_EQ(m.VomsRuleCount(), 4u);

    // Every commented-out example in the local map must be a valid rule.
    std::ifstream in(std::string(X509MAP_CONFIG_DIR) + "/x509map-local.map");
    std::string line;
    int examples = 0;
    while (std::getline(in, line)) {
        if (line.size() < 2 || line[0] != '#' || (line[1] != '"' && line.compare(1, 4, "glob") &&
                                                  line.compare(1, 5, "regex")))
            continue;
        LocalRule rule;
        std::string perr;
        EXPECT_TRUE(ParseLocalLine(line.substr(1), rule, perr)) << line << ": " << perr;
        examples++;
    }
    EXPECT_GE(examples, 5);
}
