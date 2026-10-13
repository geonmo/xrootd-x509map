# Locate the XRootD 5 development headers and XrdUtils.
#
# Set XROOTD_DIR (CMake or environment) to point at a non-default install.
# The header directories are searched before CMake's system paths so that a
# stray /usr/local install of another major version is not picked up.

FIND_PATH(XROOTD_INCLUDES XrdVersion.hh
  HINTS
  ${XROOTD_DIR}
  $ENV{XROOTD_DIR}
  /usr
  /opt/xrootd/
  PATH_SUFFIXES include/xrootd
  PATHS /opt/xrootd
  NO_CMAKE_SYSTEM_PATH
)

FIND_LIBRARY(XROOTD_UTILS_LIB XrdUtils
  HINTS
  ${XROOTD_DIR}
  $ENV{XROOTD_DIR}
  /usr
  /opt/xrootd/
  PATH_SUFFIXES lib64 lib
  NO_CMAKE_SYSTEM_PATH
)

# The entity post-processing plugin interface appeared in XRootD 5.0.
if(XROOTD_INCLUDES AND NOT EXISTS "${XROOTD_INCLUDES}/XrdSec/XrdSecEntityPin.hh")
  message(FATAL_ERROR "XrdSec/XrdSecEntityPin.hh not found in ${XROOTD_INCLUDES}; XRootD >= 5.4 server headers (xrootd-server-devel) are required")
endif()

if(XROOTD_INCLUDES)
  file(STRINGS "${XROOTD_INCLUDES}/XrdVersion.hh" _xrd_vnum REGEX "^#define XrdVNUMBER")
  string(REGEX REPLACE ".*XrdVNUMBER[ \t]+([0-9]+).*" "\\1" XROOTD_VNUMBER "${_xrd_vnum}")
  math(EXPR XROOTD_VERSION_MAJOR "${XROOTD_VNUMBER} / 10000")
  math(EXPR XROOTD_VERSION_MINOR "(${XROOTD_VNUMBER} / 100) % 100")
  math(EXPR XROOTD_VERSION_PATCH "${XROOTD_VNUMBER} % 100")
  set(XROOTD_VERSION "${XROOTD_VERSION_MAJOR}.${XROOTD_VERSION_MINOR}.${XROOTD_VERSION_PATCH}")
endif()

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Xrootd
  REQUIRED_VARS XROOTD_UTILS_LIB XROOTD_INCLUDES
  VERSION_VAR XROOTD_VERSION)
