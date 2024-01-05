cmake_minimum_required(VERSION 3.22.1)

project(playintegrityfix)

find_package(cxx REQUIRED CONFIG)

link_libraries(cxx::cxx)

add_library(${CMAKE_PROJECT_NAME} SHARED module.cpp elf_util.cpp)

add_subdirectory(Dobby)

option(LSPLANT_BUILD_SHARED off)
add_subdirectory(LSPlant/lsplant/src/main/jni)
include_directories(LSPlant/lsplant/src/main/jni/include)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE log dobby_static lsplant_static)