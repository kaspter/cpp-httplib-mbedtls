cmake_minimum_required(VERSION 3.10)
project(https_mbedtls)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin")
set(OUTPUT_BIN_DIR bin CACHE PATH "output directory for executables")

MESSAGE(STATUS "operation system is ${CMAKE_SYSTEM}")

IF (CMAKE_SYSTEM_NAME MATCHES "Linux")
    MESSAGE(STATUS "current platform: Linux ")
ELSEIF (CMAKE_SYSTEM_NAME MATCHES "Windows")
    MESSAGE(STATUS "current platform: Windows")
ELSEIF (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
    MESSAGE(STATUS "current platform: FreeBSD")
ELSE ()
    MESSAGE(STATUS "other platform: ${CMAKE_SYSTEM_NAME}")
ENDIF (CMAKE_SYSTEM_NAME MATCHES "Linux")


option(USE_OPENSSL "enable https with OpenSSL" OFF)
option(USE_MBEDTLS "enable https whit MbedTLS" OFF)

if (USE_OPENSSL)
    find_package(OpenSSL)
    if (OPENSSL_FOUND)
        message (STATUS "OPENSSL found")
        message (STATUS "OpenSSL Include directories:" ${OPENSSL_INCLUDE_DIR})
        add_definitions(-DCPPHTTPLIB_HTTPS_SUPPORT)
        add_definitions(-DCPPHTTPLIB_USE_OPENSSL=1)
    endif()
endif()

if (USE_MBEDTLS)
    find_package(MbedTLS)
    if (MBEDTLS_FOUND)
        message (STATUS "mbedtls found")
        message (STATUS "mbedtls Include directories:" ${MBEDTLS_INCLUDE_DIR})
        add_definitions(-DCPPHTTPLIB_HTTPS_SUPPORT)
        add_definitions(-DCPPHTTPLIB_USE_MBEDTLS=1)
    endif()
endif()

if(WIN32)
    add_definitions(/wd4996)
    add_definitions(/W4)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd" CACHE STRING "" FORCE)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT" CACHE STRING "" FORCE)
    add_definitions(-DUNICODE -D_UNICODE)
else()
    if(NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
    endif(NOT CMAKE_BUILD_TYPE)
    add_definitions(-Wall)

    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("-std=c++11" COMPILER_SUPPORTS_CXX11)
    if(COMPILER_SUPPORTS_CXX11)
        if(CMAKE_COMPILER_IS_GNUCXX)
            set(CMAKE_CXX_FLAGS "-std=c++11 ${CMAKE_CXX_FLAGS}")
            message(STATUS "optional:-std=c++11")
        endif(CMAKE_COMPILER_IS_GNUCXX)
    else()
        message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use higher version C++ compiler.")
    endif()

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wl,--default-symver -Wl,--no-undefined,-z,relro,-z,now,-z,noexecstack -fstack-protector -Wno-format")
endif()

set(xhttptest_SRCS
    src/client.cc
)

if (USE_MBEDTLS)
    if (MBEDTLS_FOUND)
        list(APPEND xhttptest_SRCS src/mbedtls.cc)
    endif()
endif()

set(xhttptest_INCLUDES
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${MBEDTLS_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

add_executable(xhttptest ${xhttptest_SRCS})
target_include_directories(xhttptest PRIVATE ${xhttptest_INCLUDES})
target_link_libraries(xhttptest ${MBEDTLS_LIBRARIES} ${OPENSSL_LIBRARIES})
