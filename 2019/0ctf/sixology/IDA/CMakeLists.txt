cmake_minimum_required (VERSION 3.5)

project (0ctf2019 CXX)

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "Release")
endif()

# idasdk72
if(NOT IDA_SDK_DIR)
	message(FATAL_ERROR "IDA_SDK_DIR: Please specify the idasdk directory.")
endif()

include_directories(SYSTEM
	"${IDA_SDK_DIR}/include"
)

#message(${IDA_SDK_DIR} "gogogo")

if(MSVC)
    message("---- MSVC ----")
	add_definitions(-D__NT__)
	add_definitions(-D__X64__)
    add_definitions(-D__IDP__)
	set(IDASDK_LIBRARIES "${IDA_SDK_DIR}/lib/x64_win_vc_32/ida.lib")
    if(CMAKE_BUILD_TYPE MATCHES Release)
        add_definitions(-DRELEASE)
    endif()
elseif(APPLE)
    message("---- APPLE ----" ${CMAKE_BUILD_TYPE})
	add_definitions(-D__MAC__)
	set(IDASDK_LIBRARIES "${IDA_SDK_DIR}/lib/x64_mac_gcc_32/libida.dylib")
else()
    message("---- LINUX ----")
	add_definitions(-D__LINUX__)
	set(IDASDK_LIBRARIES "")
endif()

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
	add_definitions("/wd4244")
	add_definitions("/wd4267")
else()
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-format")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-parameter")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-sign-compare")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-variable")

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
endif()

set(SOURCES
	reg.cpp
    ins.hpp
	ins.cpp
	ana.cpp
	emu.cpp
	out.cpp
    0ctf.hpp
)

add_library(${CMAKE_PROJECT_NAME} SHARED ${SOURCES})

set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES PREFIX "")
set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES OUTPUT_NAME "${CMAKE_PROJECT_NAME}")
set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES CXX_VISIBILITY_PRESET hidden)

target_link_libraries(${CMAKE_PROJECT_NAME} ${IDASDK_LIBRARIES})

if(MSVC)
	install(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION "$ENV{APPDATA}/Hex-Rays/IDA Pro/plugins")
else()
	install(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION "~/.idapro/plugins")
endif()

