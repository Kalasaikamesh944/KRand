cmake_minimum_required(VERSION 3.10)
project(KRand VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find dependencies
find_package(CURL REQUIRED)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(/usr/local/include)  # CPR headers

# Source files
set(SOURCES src/KRand.cpp)
set(HEADERS include/KRand.h)

# Create static and shared libraries
add_library(KRand STATIC ${SOURCES})
add_library(KRandShared SHARED ${SOURCES})

# Link with required libraries (CPR, CURL, OpenSSL)
target_link_libraries(KRand ssl crypto pcap ${CURL_LIBRARIES} cpr)
target_link_libraries(KRandShared ssl crypto pcap ${CURL_LIBRARIES} cpr)

# Install headers and library
install(TARGETS KRand KRandShared
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)
install(FILES ${HEADERS} DESTINATION include/KRand)

# Test executable
add_executable(test_krand src/test.cpp)
target_link_libraries(test_krand KRand ${CURL_LIBRARIES} cpr)
