// Copyright 2026 KISTI-GSDC
// SPDX-License-Identifier: Apache-2.0
//
// libXrdSecEntityX509Map: "sec.entitylib" plugin (xroot protocol only).
//
//   sec.entitylib /usr/lib64/libXrdSecEntityX509Map.so localmap=... vomsmap=...
//
// XrdSecServer calls XrdSecEntityPin::Process() once per xroot login, right
// after a security protocol (gsi, ztn, unix, ...) has authenticated the
// client and filled the XrdSecEntity. For gsi logins this plugin maps the
// X509 DN / VOMS FQANs to a local or pool account and rewrites the entity so
// that logs, monitoring, acc.audit and macaroon issuance show the account
// rather than the DN.
//
// What it does NOT do: it never rejects a login. A client that cannot be
// mapped may still send a valid SciToken with each request (authz CGI), so
// the decision belongs to libXrdAccX509Map ("ofs.authlib ++"), which runs on
// every request and is the only enforcement point. Always configure both
// plugins with identical options.
//
// Entity fields written for gsi logins:
//   moninfo          DN, if it was not already there (-moninfo)
//   x509map.dn       DN, kept even after name is overwritten
//   x509map.gridmap  account from the gsi gridmap ("" if none)
//   x509map.pin      "1"; tells the authlib this is an xroot entity
// and, only when the mapping succeeds:
//   name             mapped account (left alone for gridmap hits)
//   request.name     mapped account; read first by xrootd-multiuser/authdb
//   gridmap.name     "1"; makes multiuser accept users without VOMS
//   x509map.user     mapped account
//
// cmsd reads the same config file and also calls sec.entitylib, so the
// directive must be placed inside "if exec xrootd".

#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

#include "XrdOuc/XrdOucErrInfo.hh"
#include "XrdOuc/XrdOucPinObject.hh"
#include "XrdSec/XrdSecEntity.hh"
#include "XrdSec/XrdSecEntityAttr.hh"
#include "XrdSec/XrdSecEntityPin.hh"
#include "XrdSys/XrdSysError.hh"
#include "XrdVersion.hh"

#include "X509Mapper.hh"
#include "X509MapXrdLog.hh"

using namespace X509Map;

namespace {

// One instance per "sec.entitylib" line. Several entity pins may be stacked;
// `prev` is the pin loaded before this one (or null) and is always run first.
class X509MapEntityPin : public XrdSecEntityPin {
public:
    X509MapEntityPin(XrdSysLogger &lg, XrdSecEntityPin *prev)
        : m_eroute(&lg, "x509mappin_"), m_logger(m_eroute), m_mapper(m_logger), m_prev(prev) {}

    // Parse the directive parameters and load the map files. Returning false
    // makes XRootD refuse to start, so a typo or missing map is never silent.
    bool Configure(const char *parms)
    {
        m_eroute.setMsgMask(DefaultMask(false));
        std::string err;
        if (!m_mapper.Configure(parms, err)) {
            m_eroute.Emsg("Config", "configuration failed:", err.c_str());
            return false;
        }
        m_eroute.setMsgMask(DefaultMask(m_mapper.Config().debug));
        // Announce to libXrdAccX509Map (same process) that every xroot gsi
        // entity will carry kPinAttr; see X509MapAccWrapper::IsHttpEntity.
        setenv(kPinEnv, "1", 1);   // configuration is single threaded
        return true;
    }

    // Called once per login. Returning false would reject the login, which
    // this plugin only does when an earlier pin in the stack asked for it.
    bool Process(XrdSecEntity &e, XrdOucErrInfo &einfo) override
    {
        if (m_prev && !m_prev->Process(e, einfo)) return false;
        // Only X509 logins are mapped; ztn (tokens), unix, sss, krb5, ...
        // are left exactly as the protocol produced them.
        if (strcmp(e.prot, "gsi") != 0) return true;

        // With -gmapopt:1x/2 gsi may already have mapped the DN through the
        // grid-mapfile: it then puts the account in name and sets
        // gridmap.name=1. The mapper honours such an account first.
        std::string gm, gridmap;
        if (e.eaAPI->Get("gridmap.name", gm) && gm == "1" && e.name) gridmap = e.name;
        std::string dn = X509Mapper::ExtractDN(e);
        X509MapResult r = m_mapper.Map(dn, X509Mapper::ExtractFqans(e), gridmap);

        // Preserve the original identity for the authlib wrapper, which
        // re-evaluates the mapping on every request (served from its cache).
        // This must happen before name is overwritten below.
        if (!dn.empty()) {
            if (!e.moninfo || e.moninfo[0] != '/') {
                free(e.moninfo);
                e.moninfo = strdup(dn.c_str());
            }
            e.eaAPI->Add("x509map.dn", dn, true);
        }
        e.eaAPI->Add("x509map.gridmap", gridmap, true);
        e.eaAPI->Add(kPinAttr, "1", true);

        if (!r.ok) {
            // Leave the entity as gsi produced it (name = DN or gridmap
            // account). The authlib will deny the first request unless a
            // token decides it before.
            if (m_logger.Enabled(Debug))
                m_eroute.Log(Debug, "Process", e.tident, "unmapped at login, deferring to authlib:",
                             r.reason.c_str());
            return true;
        }
        // A gridmap hit already has the account in name.
        if (r.source != X509MapResult::Gridmap) {
            free(e.name);
            e.name = strdup(r.user.c_str());
        }
        // request.name is what xrootd-multiuser uses for setfsuid and what
        // the authdb uses for "u" rules (it takes precedence over name).
        e.eaAPI->Add("request.name", r.user, true);
        // Lets xrootd-multiuser treat a local user without VOMS as mapped
        // (otherwise a gsi entity with neither vorg nor gridmap.name is
        // handled as anonymous and runs as the daemon uid).
        e.eaAPI->Add("gridmap.name", "1", true);
        e.eaAPI->Add("x509map.user", r.user, true);
        return true;
    }

private:
    XrdSysError      m_eroute;   // log prefix "x509mappin_"
    XrdLogger        m_logger;   // adapts m_eroute for the mapping core
    X509Mapper       m_mapper;   // owns the rules, reload logic and caches
    XrdSecEntityPin *m_prev;     // previous pin in the stack, not owned
};

} // namespace

// Plugin factory. XrdSecServer looks up the object named "SecEntityPin" with
// dlsym and calls getInstance() once per sec.entitylib line, so the object
// must have external linkage (it cannot live in the anonymous namespace).
// Returning null aborts the server start-up.
class X509MapPinObject : public XrdOucPinObject<XrdSecEntityPin> {
public:
    XrdSecEntityPin *getInstance(const char *parms, XrdOucEnv &, XrdSysLogger &lg,
                                 XrdSecEntityPin *prev) override
    {
        std::unique_ptr<X509MapEntityPin> pin(new X509MapEntityPin(lg, prev));
        if (!pin->Configure(parms)) return nullptr;
        return pin.release();
    }
};

X509MapPinObject SecEntityPin;

// Records the XRootD version this plugin was built against; the loader
// refuses a plugin built for a different major version.
XrdVERSIONINFO(SecEntityPin, x509mappin);
