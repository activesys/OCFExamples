#
#   Copyright (C) 2021 WangBo All rights reserved.
#
#   Top CMakeLists for ipv6_server
#

##################################
# Set ipv6_server version informations
set(IPV6_SERVER_VERSION           0x010000)
set(IPV6_SERVER_VERSION_MAJOR     1)
set(IPV6_SERVER_VERSION_MINOR     0)
set(IPV6_SERVER_VERSION_PATCH     0)
set(IPV6_SERVER_VERSION_TEXT      "${IPV6_SERVER_VERSION_MAJOR}.${IPV6_SERVER_VERSION_MINOR}.${IPV6_SERVER_VERSION_PATCH}")
set(IPV6_SERVER_SOVERSION_TEXT    "${IPV6_SERVER_VERSION_MAJOR}.${IPV6_SERVER_VERSION_MINOR}")

##################################
# Set ipv6_server config
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/ipv6_server_config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/ipv6_server_config.h
)

##################################
# Set include directories for ipv6_server
include_directories(
    src
    ${CMAKE_CURRENT_BINARY_DIR}
    ${ASDEV_IOTIVITY_LITE_INCLUDE}
)

##################################
# Set sources for ipv6_server
set(IPV6_SERVER_SOURCES
    src/ipv6_server.c
)

##################################
# Build shared library
add_executable(ipv6_server ${IPV6_SERVER_SOURCES})
if(WIN32)
    target_link_libraries(ipv6_server ws2_32 Iphlpapi ${ASDEV_IOTIVITY_LITE_LIB})
else(WIN32)
    target_link_libraries(ipv6_server ${ASDEV_IOTIVITY_LITE_LIB})
endif(WIN32)

##################################
# Install library
if(WIN32)
    install(TARGETS ipv6_server           DESTINATION ${OCFEXAMPLES_INSTALL_BIN_PATH}/IPV6_SERVER)
else(WIN32)
    install(TARGETS ipv6_server           RUNTIME DESTINATION bin)
endif(WIN32)
install(FILES README.md         DESTINATION ${OCFEXAMPLES_INSTALL_README_PATH}     RENAME ipv6_server.README)
install(FILES ChangeLog         DESTINATION ${OCFEXAMPLES_INSTALL_CHANGELOG_PATH}  RENAME ipv6_server.ChangeLog)

