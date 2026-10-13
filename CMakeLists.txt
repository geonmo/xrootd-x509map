cmake_minimum_required(VERSION 3.16)
project(xrootd-x509map VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

include(GNUInstallDirs)

option(BUILD_TESTS "Build the GoogleTest unit tests" OFF)

find_package(Xrootd REQUIRED)

# XRootD resolves "libXrdFoo.so" to "libXrdFoo-<plugin version>.so".
if(NOT XROOTD_PLUGIN_VERSION)
  set(XROOTD_PLUGIN_VERSION ${XROOTD_VERSION_MAJOR})
endif()
if(NOT XROOTD_PLUGIN_VERSION STREQUAL "5")
  message(FATAL_ERROR "XRootD 5.x headers required, found ${XROOTD_VERSION} in ${XROOTD_INCLUDES}. Set XROOTD_DIR.")
endif()
if(XROOTD_VERSION VERSION_LESS "5.4.0")
  message(FATAL_ERROR "XRootD >= 5.4 required (gridmap.name / request.name attributes), found ${XROOTD_VERSION}")
endif()
message(STATUS "XRootD ${XROOTD_VERSION}: ${XROOTD_INCLUDES}, ${XROOTD_UTILS_LIB}")

add_compile_options(-Wall -Wextra -Werror)
add_compile_definitions(_POSIX_C_SOURCE=200809L _DEFAULT_SOURCE)

# Mapping core, linked statically into both plugins.
add_library(X509MapCore OBJECT src/X509MapRules.cc src/X509Mapper.cc)
target_include_directories(X509MapCore PUBLIC ${PROJECT_SOURCE_DIR}/src ${XROOTD_INCLUDES})

function(x509map_plugin target source symfile)
  add_library(${target} MODULE ${source} $<TARGET_OBJECTS:X509MapCore>)
  target_include_directories(${target} PRIVATE ${PROJECT_SOURCE_DIR}/src ${XROOTD_INCLUDES})
  target_link_libraries(${target} PRIVATE ${XROOTD_UTILS_LIB})
  target_link_options(${target} PRIVATE
    -Wl,--no-undefined
    -Wl,--version-script=${PROJECT_SOURCE_DIR}/configs/${symfile})
  set_target_properties(${target} PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "${target}-${XROOTD_PLUGIN_VERSION}"
    SUFFIX ".so"
    LINK_DEPENDS ${PROJECT_SOURCE_DIR}/configs/${symfile})
  install(TARGETS ${target} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
endfunction()

x509map_plugin(XrdSecEntityX509Map src/XrdSecEntityX509Map.cc export-symbols-entity)
x509map_plugin(XrdAccX509Map       src/XrdAccX509Map.cc       export-symbols-acc)

set(X509MAP_SYSCONFDIR "/etc/xrootd" CACHE PATH "Install path for the sample map files")
install(FILES
  configs/x509map-local.map
  configs/x509map-voms.map
  configs/x509map-authdb
  DESTINATION ${X509MAP_SYSCONFDIR})
install(FILES configs/xrootd-multiuser-x509map.sample.cfg
  DESTINATION ${X509MAP_SYSCONFDIR}
  RENAME xrootd-multiuser-x509map.cfg)
install(FILES README.md README.ko.md DESTINATION ${CMAKE_INSTALL_DOCDIR})

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
