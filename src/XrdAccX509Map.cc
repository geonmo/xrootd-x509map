// Copyright 2026 KISTI-GSDC
// SPDX-License-Identifier: Apache-2.0
//
// libXrdAccX509Map: "ofs.authlib ++" wrapper (xroot and HTTPS).
//
//   ofs.authlib ++ /usr/lib64/libXrdAccX509Map.so localmap=... vomsmap=...
//   ofs.authlib ++ libXrdMacaroons.so
//   ofs.authlib ++ libXrdAccSciTokens.so config=...
//
// XrdOfs calls XrdAccAuthorize::Access() before every file system operation.
// Each "++" line wraps the authorizer built by the lines before it, so the
// LAST line is the outermost and is called FIRST. With the stack above the
// call order is SciTokens -> Macaroons -> X509Map -> authdb: requests with a
// valid token or macaroon are decided before this plugin, and an invalid
// token falls through to the client's X509 identity.
//
// This wrapper is the enforcement point of the package. For X509 entities
// (prot "gsi", or "https" with a client certificate) it maps the DN/FQANs
// to a local or pool account, publishes it as request.name for
// xrootd-multiuser and the authdb, and then delegates to the wrapped
// authorizer (normally the authdb), which still decides the path
// privileges. If no rule matches it returns XrdAccPriv_None without
// consulting the chain. All other entities (ztn tokens, unix, sss,
// anonymous HTTPS, SciTokens mapping-only entities with prot "") are passed
// to the chain untouched.
//
// XRootD 5.9 has no Access() variant that returns an error text, so the
// deny reason is only written to the server log ("x509mapacc_Access:
// denying ... x509map: <reason>"); the client sees a plain permission
// denied (xroot) or 403 (HTTP).

#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

#include "XrdAcc/XrdAccAuthorize.hh"
#include "XrdOuc/XrdOucEnv.hh"
#include "XrdSec/XrdSecEntity.hh"
#include "XrdSec/XrdSecEntityAttr.hh"
#include "XrdSys/XrdSysError.hh"
#include "XrdSys/XrdSysLogger.hh"
#include "XrdVersion.hh"

#include "X509Mapper.hh"
#include "X509MapXrdLog.hh"

using namespace X509Map;

namespace {

class X509MapAccWrapper : public XrdAccAuthorize {
public:
    // `chain` is the authorizer this one wraps (the authdb or a previous
    // "++" plugin). It is owned by XrdOfs, not deleted here.
    X509MapAccWrapper(XrdSysLogger *lp, XrdAccAuthorize *chain)
        : m_eroute(lp, "x509mapacc_"), m_logger(m_eroute), m_mapper(m_logger), m_chain(chain) {}

    // Parse the directive parameters and load the map files. Returning false
    // makes XRootD refuse to start.
    bool Configure(const char *parms)
    {
        m_eroute.setMsgMask(DefaultMask(false));
        std::string err;
        if (!m_mapper.Configure(parms, err)) {
            m_eroute.Emsg("Config", "configuration failed:", err.c_str());
            return false;
        }
        m_eroute.setMsgMask(DefaultMask(m_mapper.Config().debug));
        return true;
    }

    // True if `E` is owned by an XrdHttp connection, which serves one request
    // at a time, so its name may be replaced in place. xroot entities can be
    // shared by parallel streams and are only renamed by the entitylib pin.
    //
    // XrdHttp reports prot "https" for a plain certificate but "gsi" when
    // http.secxtractor found VOMS attributes, so "gsi" alone does not tell
    // the protocols apart. The entitylib pin marks every xroot gsi entity
    // with kPinAttr and sets kPinEnv at start-up; an unmarked gsi entity in
    // a process with the pin configured must therefore come from XrdHttp.
    // Without the pin, VOMS HTTPS entities are not renamed (safe default).
    static bool IsHttpEntity(const XrdSecEntity *E, bool https)
    {
        if (https) return true;   // "https" is only ever set by XrdHttp
        std::string v;
        if (E->eaAPI->Get(kPinAttr, v)) return false;
        const char *pin = getenv(kPinEnv);
        return pin && !strcmp(pin, "1");
    }

    XrdAccPrivs Access(const XrdSecEntity *E, const char *path, const Access_Operation oper,
                       XrdOucEnv *env) override
    {
        // Not an X509 identity: nothing to map, let the chain decide.
        if (!E || !E->eaAPI) return m_chain->Access(E, path, oper, env);
        bool https = !strcmp(E->prot, "https");
        if (strcmp(E->prot, "gsi") != 0 && !https) return m_chain->Access(E, path, oper, env);

        // DN as saved by the entitylib pin (xroot), else from moninfo/name
        // (HTTPS always puts the DN in moninfo).
        std::string dn;
        if (!E->eaAPI->Get("x509map.dn", dn) || dn.empty()) dn = X509Mapper::ExtractDN(*E);
        // HTTPS without a client certificate (token-only clients, macaroon
        // TPC): there is no X509 identity to map, so the authdb decides.
        if (dn.empty() && https) return m_chain->Access(E, path, oper, env);

        // The entitylib pin records the gsi gridmap result before it
        // overwrites name; otherwise take it from the entity directly
        // (http.gridmap, or xroot without the pin).
        std::string gridmap, gm;
        if (E->eaAPI->Get("x509map.gridmap", gm)) gridmap = gm;
        else if (E->eaAPI->Get("gridmap.name", gm) && gm == "1" && E->name) gridmap = E->name;

        // Recomputed on every call (cache hit) because XrdOfs::rename resets
        // request.name between its two authorization checks.
        X509MapResult r = m_mapper.Map(dn, X509Mapper::ExtractFqans(*E), gridmap);
        if (!r.ok) {
            // Deny without consulting the chain: an unmapped X509 client must
            // never reach multiuser, which would run it as the daemon uid.
            std::string msg = std::string("denying ") + (E->tident ? E->tident : "?") +
                              " path=" + (path ? path : "") + ": x509map: " + r.reason;
            m_eroute.Log(Info, "Access", msg.c_str());
            return XrdAccPriv_None;
        }
        // request.name is read first by xrootd-multiuser (setfsuid) and by the
        // authdb "u" rules; same attribute XrdSciTokens uses.
        E->eaAPI->Add("request.name", r.user, true);
        E->eaAPI->Add("x509map.user", r.user, true);
        // XrdMacaroons embeds SecEntity.name in issued macaroons, so an HTTP
        // client must carry the mapped account there, not the subject hash.
        // Access() gets a const entity; XrdHttp owns it and does not share
        // it between requests, so replacing name is safe for HTTP only.
        if (IsHttpEntity(E, https) && (!E->name || r.user != E->name)) {
            XrdSecEntity *W = const_cast<XrdSecEntity *>(E);
            free(W->name);
            W->name = strdup(r.user.c_str());
        }
        // The mapping only chooses the account; the wrapped authorizer still
        // decides which privileges that account has on `path`.
        return m_chain->Access(E, path, oper, env);
    }

    // Auditing and privilege tests are not affected by the mapping.
    int Audit(const int accok, const XrdSecEntity *E, const char *path, const Access_Operation oper,
              XrdOucEnv *env) override
    {
        return m_chain->Audit(accok, E, path, oper, env);
    }

    int Test(const XrdAccPrivs priv, const Access_Operation oper) override
    {
        return m_chain->Test(priv, oper);
    }

private:
    XrdSysError      m_eroute;   // log prefix "x509mapacc_"
    XrdLogger        m_logger;   // adapts m_eroute for the mapping core
    X509Mapper       m_mapper;   // own rules and caches (separate from the pin's)
    XrdAccAuthorize *m_chain;    // wrapped authorizer, not owned
};

} // namespace

// Entry point for "ofs.authlib ++ libXrdAccX509Map.so <parms>". XrdOfs passes
// the authorizer built so far in `accP` and uses the returned object in its
// place. Returning null aborts the server start-up.
extern "C" XrdAccAuthorize *XrdAccAuthorizeObjAdd(XrdSysLogger *lp, const char * /*cfn*/,
                                                  const char *parm, XrdOucEnv * /*envP*/,
                                                  XrdAccAuthorize *accP)
{
    if (!accP) {
        XrdSysError eroute(lp, "x509mapacc_");
        eroute.Emsg("Config", "libXrdAccX509Map must be stacked with 'ofs.authlib ++'");
        return nullptr;
    }
    std::unique_ptr<X509MapAccWrapper> acc(new X509MapAccWrapper(lp, accP));
    if (!acc->Configure(parm)) return nullptr;
    return acc.release();
}

XrdVERSIONINFO(XrdAccAuthorizeObjAdd, x509mapacc);

// Only reached when the library is configured without "++": fail with a
// clear message instead of the loader's "unable to find symbol". This
// plugin cannot work as a stand-alone authorizer because it has no path
// rules of its own.
extern "C" XrdAccAuthorize *XrdAccAuthorizeObject2(XrdSysLogger *lp, const char * /*cfn*/,
                                                   const char * /*parm*/, XrdOucEnv * /*envP*/)
{
    XrdSysError eroute(lp, "x509mapacc_");
    eroute.Emsg("Config", "libXrdAccX509Map must be stacked with 'ofs.authlib ++'");
    return nullptr;
}

XrdVERSIONINFO(XrdAccAuthorizeObject2, x509mapacc);
