#
#   Copyright (C) 2021 WangBo All rights reserved.
#
#   Top CMakeLists for OCFExamples
#

##################################
cmake_minimum_required(VERSION 2.8)

##################################
# Set project name and version.
project(OCFExamples C)
set(PROJECT_VERSION_MAJOR 1)
set(PROJECT_VERSION_MINOR 0)
set(PROJECT_VERSION_PATCH 0)

##################################
# Check necessary headers and libraries for OCFExamples development
include(CheckIncludeFile)
include(CheckLibraryExists)

##################################
# Make rpm package
if(NOT WIN32)

exec_program(uname ARGS "-p" OUTPUT_VARIABLE ASDEV_ARCH)

IF(${CMAKE_SYSTEM_VERSION} MATCHES "el")
set(CPACK_GENERATOR "RPM")
ELSE()
set(CPACK_GENERATOR "DEB")
ENDIF()

set(CPACK_PACKAGE_NAME "ocfexamples")
set(CPACK_PACKAGE_RELEASE_NUMBER 4)
IF(${CMAKE_SYSTEM_VERSION} MATCHES "el6")
    set(CPACK_PACKAGE_RELEASE ${CPACK_PACKAGE_RELEASE_NUMBER}.el6)
ELSEIF(${CMAKE_SYSTEM_VERSION} MATCHES "el7")
    set(CPACK_PACKAGE_RELEASE ${CPACK_PACKAGE_RELEASE_NUMBER}.el7)
ELSE()
    set(CPACK_PACKAGE_RELEASE ${CPACK_PACKAGE_RELEASE_NUMBER})
ENDIF()

set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")
set(CPACK_OUTPUT_FILE_PREFIX "${CMAKE_CURRENT_BINARY_DIR}/installer")
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr/local")

IF(${CMAKE_SYSTEM_VERSION} MATCHES "el")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_RPM_PACKAGE_NAME ${CPACK_PACKAGE_NAME})
set(CPACK_RPM_PACKAGE_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})
set(CPACK_RPM_PACKAGE_RELEASE ${CPACK_PACKAGE_RELEASE})
set(CPACK_RPM_PACKAGE_VENDOR "WangBo")
set(CPACK_RPM_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION})
set(CPACK_RPM_PACKAGE_SUMMARY "OCF Example codes.")
set(CPACK_RPM_PACKAGE_LICENSE "MIT")
set(CPACK_RPM_PACKAGE_GROUP "Applications/Communications")
set(CPACK_RPM_PACKAGE_DESCRIPTION "OCF Example codes.")
ELSE()
execute_process(
    COMMAND dpkg --print-architecture
    OUTPUT_VARIABLE CPACK_DEBIAN_PACKAGE_ARCHITECTURE
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}")
set(CPACK_DEBIAN_PACKAGE_NAME ${CPACK_PACKAGE_NAME})
set(CPACK_DEBIAN_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE})
set(CPACK_DEBIAN_PACKAGE_SECTION "extra")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "activesys@sina.com")
set(CPACK_DEBIAN_PACKAGE_PROVIDES "WangBo")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "OCF Example codes.")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA ${CMAKE_CURRENT_SOURCE_DIR}/package/deb/preinst)
ENDIF()

include(CPack)
endif(NOT WIN32)

# Check C header files
CHECK_INCLUDE_FILE(stdio.h      HAVE_STDIO_H)
CHECK_INCLUDE_FILE(stdlib.h     HAVE_STDLIB_H)
CHECK_INCLUDE_FILE(stdint.h     HAVE_STDINT_H)
CHECK_INCLUDE_FILE(string.h     HAVE_STRING_H)
CHECK_INCLUDE_FILE(stdarg.h     HAVE_STDARG_H)
CHECK_INCLUDE_FILE(math.h       HAVE_MATH_H)
CHECK_INCLUDE_FILE(float.h      HAVE_FLOAT_H)
CHECK_INCLUDE_FILE(limits.h     HAVE_LIMITS_H)
CHECK_INCLUDE_FILE(ctype.h      HAVE_CTYPE_H)

if(NOT HAVE_STDIO_H)
    message (FATAL_ERROR "ERROR: CMake can't find the standard C header file \"stdio.h\".")
endif()
if(NOT HAVE_STDLIB_H)
    message (FATAL_ERROR "ERROR: CMake can't find the standard C header file \"stdlib.h\".")
endif()
if(NOT HAVE_STDINT_H)
    message (FATAL_ERROR "ERROR: CMake can't find the standard C header file \"stdint.h\".")
endif()
if(NOT HAVE_STRING_H)
    message (FATAL_ERROR "ERROR: CMake can't find the standard C header file \"string.h\".")
endif()
if(NOT HAVE_STDARG_H)
    message (FATAL_ERROR "ERROR: CMake can't find the standard C header file \"stdarg.h\".")
endif()
if(NOT HAVE_MATH_H)
    message (FATAL_ERROR "ERROR: CMake can't find the standard C header file \"math.h\".")
endif()
if(NOT HAVE_FLOAT_H)
    message (FATAL_ERROR "ERROR: CMake can't find the standard C header file \"float.h\".")
endif()
if(NOT HAVE_LIMITS_H)
    message (FATAL_ERROR "ERROR: CMake can't find the standard C header file \"limits.h\".")
endif()
if(NOT HAVE_CTYPE_H)
    message (FATAL_ERROR "ERROR: CMake can't find the standard C header file \"ctype.h\".")
endif()

# Check Header files of specified platform.
if(WIN32)
    CHECK_INCLUDE_FILE(windows.h    HAVE_WINDOWS_H)
    CHECK_INCLUDE_FILE(direct.h     HAVE_DIRECT_H)
    CHECK_INCLUDE_FILE(Winsock2.h   HAVE_WINSOCK2_H)

    if (NOT HAVE_WINDOWS_H)
        message (FATAL_ERROR "ERROR: CMake can't find the Windows API header file \"windows.h\".")
    endif()
    if (NOT HAVE_DIRECT_H)
        message (FATAL_ERROR "ERROR: CMake can't find the Windows API header file \"direct.h\".")
    endif()
    if (NOT HAVE_WINSOCK2_H)
        message (FATAL_ERROR "ERROR: CMake can't find the Windows API header file \"Winsock2.h\".")
    endif()
else(WIN32)
    CHECK_INCLUDE_FILE(sys/stat.h   HAVE_SYS_STAT_H)
    CHECK_INCLUDE_FILE(sys/time.h   HAVE_SYS_TIME_H)
    CHECK_INCLUDE_FILE(unistd.h     HAVE_UNISTD_H)

    if (NOT HAVE_SYS_STAT_H)
        message (FATAL_ERROR "ERROR: CMake can't find the POSIX API header file \"sys/stat.h\".")
    endif()
    if (NOT HAVE_SYS_TIME_H)
        message (FATAL_ERROR "ERROR: CMake can't find the POSIX API header file \"sys/time.h\".")
    endif()
    if (NOT HAVE_UNISTD_H)
        message (FATAL_ERROR "ERROR: CMake can't find the POSIX API header file \"unistd.h\".")
    endif()

    find_library(ASDEV_M_LIB m)
    if(NOT ASDEV_M_LIB)
        message (FATAL_ERROR "ERROR: CMake can't find the library \"m\".")
    endif()
endif(WIN32)

##################################
# Check iotivity-lite
if(WIN32)
    set(ASDEV_IOTIVITY_LITE_LIB_PATH           				${CMAKE_CURRENT_SOURCE_DIR}/iotivity-lite/lib)
    set(ASDEV_IOTIVITY_LITE_INCLUDE_PATH       				${CMAKE_CURRENT_SOURCE_DIR}/iotivity-lite/include)
    find_library(ASDEV_IOTIVITY_LITE_LIB iotivity-lite    	${ASDEV_IOTIVITY_LITE_LIB_PATH})
    find_file(ASDEV_IOTIVITY_LITE_H  oc_api.h               ${ASDEV_IOTIVITY_LITE_INCLUDE_PATH})
    set(ASDEV_IOTIVITY_LITE_INCLUDE            				${ASDEV_IOTIVITY_LITE_INCLUDE_PATH})
else(WIN32)
    find_library(ASDEV_IOTIVITY_LITE_LIB iotivity-lite-client-server)
    find_library(ASDEV_IOTIVITY_LITE_CLIENT_LIB iotivity-lite-client)
    find_library(ASDEV_IOTIVITY_LITE_SERVER_LIB iotivity-lite-server)
    find_file(ASDEV_IOTIVITY_LITE_H  oc_api.h               /usr/local/include/iotivity-lite)
    find_path(ASDEV_IOTIVITY_LITE_INCLUDE  oc_api.h         /usr/local/include/iotivity-lite)
endif(WIN32)


if(NOT ASDEV_IOTIVITY_LITE_LIB OR NOT ASDEV_IOTIVITY_LITE_H OR NOT ASDEV_IOTIVITY_LITE_INCLUDE)
    message (FATAL_ERROR "ERROR: CMake can't find the library \"IoTivity-Lite\".")
endif()

##################################
# Set Install Path
if(WIN32)
    set(OCFEXAMPLES_INSTALL_PATH           ${CMAKE_CURRENT_SOURCE_DIR}/installer/OCFExamples)
    set(OCFEXAMPLES_INSTALL_BIN_PATH       ${OCFEXAMPLES_INSTALL_PATH}/bin)
    set(OCFEXAMPLES_INSTALL_LIB_PATH       ${OCFEXAMPLES_INSTALL_PATH}/lib)
    set(OCFEXAMPLES_INSTALL_INCLUDE_PATH   ${OCFEXAMPLES_INSTALL_PATH}/include)
    set(OCFEXAMPLES_INSTALL_README_PATH    ${OCFEXAMPLES_INSTALL_PATH}/readme)
    set(OCFEXAMPLES_INSTALL_CHANGELOG_PATH ${OCFEXAMPLES_INSTALL_PATH}/changelog)
    set(OCFEXAMPLES_INSTALL_PROTOCOL_PATH  ${OCFEXAMPLES_INSTALL_PATH}/protocol)
    set(OCFEXAMPLES_INSTALL_RESOURCE_PATH  ${OCFEXAMPLES_INSTALL_PATH}/resource)
else(WIN32)
    set(OCFEXAMPLES_INSTALL_README_PATH    docs/OCFEXAMPLES/readme)
    set(OCFEXAMPLES_INSTALL_CHANGELOG_PATH docs/OCFEXAMPLES/changelog)
    set(OCFEXAMPLES_INSTALL_INCLUDE_PATH   include)
endif(WIN32)

##################################
# Build ipv6_get_client
add_subdirectory(ipv6_get_client)

# Build ipv6_server
add_subdirectory(ipv6_server)

# Build installer
# add_subdirectory(installer)

##################################
# Install ChangeLog
if(WIN32)
    install(FILES ChangeLog         DESTINATION ${OCFEXAMPLES_INSTALL_PATH} RENAME ChangeLog.log)
    install(FILES README.md         DESTINATION ${OCFEXAMPLES_INSTALL_PATH})
else(WIN32)
    install(FILES ChangeLog         DESTINATION ${OCFEXAMPLES_INSTALL_CHANGELOG_PATH})
    install(FILES README.md         DESTINATION ${OCFEXAMPLES_INSTALL_README_PATH})
endif(WIN32)
