find_package(GTest REQUIRED)
include(GoogleTest)

add_executable(x509map-tests X509MapperTests.cc $<TARGET_OBJECTS:X509MapCore>)
target_include_directories(x509map-tests PRIVATE ${PROJECT_SOURCE_DIR}/src ${XROOTD_INCLUDES})
target_link_libraries(x509map-tests PRIVATE GTest::gtest GTest::gtest_main ${XROOTD_UTILS_LIB} pthread)

target_compile_definitions(x509map-tests PRIVATE X509MAP_CONFIG_DIR="${PROJECT_SOURCE_DIR}/configs")

gtest_discover_tests(x509map-tests)
