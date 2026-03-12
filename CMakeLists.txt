cmake_minimum_required(VERSION 3.25)
project(fwsvc C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBPQ REQUIRED IMPORTED_TARGET libpq)

add_executable(fwsvc
  src/main.c
  src/db.c
  src/event.c
  src/fw.c
  src/listener.c
  src/net.c
  src/reload.c
  src/service.c
)

target_include_directories(fwsvc PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(fwsvc PRIVATE PkgConfig::LIBPQ)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_compile_definitions(fwsvc PRIVATE _GNU_SOURCE=1 LINUX_BUILD=1)

  target_compile_options(fwsvc PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wformat=2
    -Wnull-dereference
    -Wdouble-promotion
    $<$<CONFIG:Debug>:-O0;-g3;-fno-omit-frame-pointer>
    $<$<CONFIG:Release>:-O3;-DNDEBUG;-fomit-frame-pointer;-ffunction-sections;-fdata-sections>
    $<$<CONFIG:RelWithDebInfo>:-O2;-g;-fno-omit-frame-pointer>
  )

  target_link_options(fwsvc PRIVATE
    $<$<CONFIG:Release>:-Wl,--gc-sections>
  )
endif()

install(TARGETS fwsvc
  RUNTIME DESTINATION bin
)
