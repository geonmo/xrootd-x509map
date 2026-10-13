// Copyright 2026 KISTI-GSDC
// SPDX-License-Identifier: Apache-2.0
#ifndef X509MAP_LOG_HH
#define X509MAP_LOG_HH

#include <string>

namespace X509Map {

// Log mask bits, same convention as XrdVomsMapfile / XrdSciTokens.
enum LogMask {
    Debug   = 0x01,
    Info    = 0x02,
    Warning = 0x04,
    Error   = 0x08,
    All     = 0xff
};

// Minimal logging interface so the mapping core does not link against
// XrdUtils. The plugin adapters wrap XrdSysError; the unit tests use a
// stdout/collecting logger.
class Logger {
public:
    virtual ~Logger() {}
    virtual void Log(int mask, const char *epname, const std::string &msg) = 0;
    virtual int  Mask() const = 0;

    bool Enabled(int mask) const { return (Mask() & mask) != 0; }
};

} // namespace X509Map

#endif
