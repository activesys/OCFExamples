#
#   Copyright (C) 2021 WangBo All rights reserved.
#
#   Top CMakeLists for ipv6_get_client
#

##################################
# Set ipv6_get_client version informations
set(IPV6_GET_CLIENT_VERSION           0x010000)
set(IPV6_GET_CLIENT_VERSION_MAJOR     1)
set(IPV6_GET_CLIENT_VERSION_MINOR     0)
set(IPV6_GET_CLIENT_VERSION_PATCH     0)
set(IPV6_GET_CLIENT_VERSION_TEXT      "${IPV6_GET_CLIENT_VERSION_MAJOR}.${IPV6_GET_CLIENT_VERSION_MINOR}.${IPV6_GET_CLIENT_VERSION_PATCH}")
set(IPV6_GET_CLIENT_SOVERSION_TEXT    "${IPV6_GET_CLIENT_VERSION_MAJOR}.${IPV6_GET_CLIENT_VERSION_MINOR}")

##################################
# Set ipv6_get_client config
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/ipv6_get_client_config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/ipv6_get_client_config.h
)

##################################
# Set include directories for ipv6_get_client
include_directories(
    src
    ${CMAKE_CURRENT_BINARY_DIR}
    ${ASDEV_IOTIVITY_LITE_INCLUDE}
)

##################################
# Set sources for ipv6_get_client
set(IPV6_GET_CLIENT_SOURCES
    src/ipv6_get_client.c
)

##################################
# Build shared library
add_executable(ipv6_get_client ${IPV6_GET_CLIENT_SOURCES})
if(WIN32)
    target_link_libraries(ipv6_get_client ws2_32 Iphlpapi ${ASDEV_IOTIVITY_LITE_LIB})
else(WIN32)
    target_link_libraries(ipv6_get_client ${ASDEV_IOTIVITY_LITE_CLIENT_LIB})
endif(WIN32)

##################################
# Install library
if(WIN32)
    install(TARGETS ipv6_get_client           DESTINATION ${OCFEXAMPLES_INSTALL_BIN_PATH}/IPV6_GET_CLIENT)
else(WIN32)
    install(TARGETS ipv6_get_client           RUNTIME DESTINATION bin)
endif(WIN32)
install(FILES README.md         DESTINATION ${OCFEXAMPLES_INSTALL_README_PATH}     RENAME ipv6_get_client.README)
install(FILES ChangeLog         DESTINATION ${OCFEXAMPLES_INSTALL_CHANGELOG_PATH}  RENAME ipv6_get_client.ChangeLog)

