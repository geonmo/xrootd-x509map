// Copyright 2026 KISTI-GSDC
// SPDX-License-Identifier: Apache-2.0
#ifndef X509MAP_XRDLOG_HH
#define X509MAP_XRDLOG_HH

#include "X509MapLog.hh"
#include "XrdSys/XrdSysError.hh"

namespace X509Map {

// Logger backed by XrdSysError, used by both plugin adapters.
class XrdLogger : public Logger {
public:
    explicit XrdLogger(XrdSysError &e) : m_e(e) {}
    void Log(int mask, const char *epname, const std::string &msg) override
    {
        m_e.Log(mask, epname, msg.c_str());
    }
    int Mask() const override { return m_e.getMsgMask(); }

private:
    XrdSysError &m_e;
};

// Process environment variable the entitylib pin sets when it is configured,
// so the authlib wrapper knows that every xroot gsi entity carries the
// kPinAttr marker and an unmarked gsi entity must come from XrdHttp.
static const char *const kPinEnv  = "XRDX509MAP_ENTITYPIN";
static const char *const kPinAttr = "x509map.pin";

inline int DefaultMask(bool debug)
{
    return debug ? All : (Info | Warning | Error);
}

} // namespace X509Map

#endif
