cmake_minimum_required(VERSION 3.22)
project(m365_bec_mcp VERSION 0.1.1 LANGUAGES C)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE MinSizeRel CACHE STRING "Build configuration" FORCE)
endif()
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options("$<$<CONFIG:MinSizeRel>:-ffunction-sections;-fdata-sections>")
    if(WIN32 OR CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_link_options("$<$<CONFIG:MinSizeRel>:-Wl,--gc-sections;-s>")
    endif()
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(ENGINE REQUIRED IMPORTED_TARGET glib-2.0 sqlite3 zlib expat libzip xlsxwriter)
pkg_check_modules(YYJSON QUIET IMPORTED_TARGET yyjson)
if(YYJSON_FOUND)
    set(JSON_LIBRARY PkgConfig::YYJSON)
else()
    include(FetchContent)
    if(POLICY CMP0135)
        cmake_policy(SET CMP0135 NEW)
    endif()
    FetchContent_Declare(yyjson
        URL https://codeload.github.com/ibireme/yyjson/tar.gz/refs/tags/0.10.0
        URL_HASH SHA256=0d901cb2c45c5586e3f3a4245e58c2252d6b24bf4b402723f6179523d389b165)
    FetchContent_MakeAvailable(yyjson)
    set(JSON_LIBRARY yyjson)
endif()
set(ANALYZER vendor/analyzer)
add_library(bec STATIC
    ${ANALYZER}/core/bql.c ${ANALYZER}/core/fields.c ${ANALYZER}/core/json.c
    ${ANALYZER}/core/stats.c ${ANALYZER}/core/store.c ${ANALYZER}/core/text.c
    ${ANALYZER}/io/csv_read.c ${ANALYZER}/io/xlsx_read.c
    ${ANALYZER}/io/import.c ${ANALYZER}/io/export.c)
target_include_directories(bec PUBLIC ${ANALYZER})
if(MINGW AND CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
    find_library(WORKBOOK_LIBRARY NAMES libxlsxwriter.a libxlsxwriter.dll.a
                 HINTS ${ENGINE_LIBRARY_DIRS} REQUIRED)
    set(engine_links ${ENGINE_STATIC_LDFLAGS})
    list(TRANSFORM engine_links REPLACE "^-lxlsxwriter$" "${WORKBOOK_LIBRARY}")
    target_include_directories(bec PUBLIC ${ENGINE_INCLUDE_DIRS} ${YYJSON_INCLUDE_DIRS})
    target_compile_options(bec PUBLIC ${ENGINE_STATIC_CFLAGS_OTHER})
    target_compile_definitions(bec PUBLIC GLIB_STATIC_COMPILATION XML_STATIC ZIP_STATIC)
    if(YYJSON_FOUND)
        set(JSON_LIBRARY ${YYJSON_STATIC_LDFLAGS})
    endif()
    target_link_libraries(bec PUBLIC -Wl,-Bstatic ${engine_links} ${JSON_LIBRARY}
                          iconv -Wl,-Bdynamic m)
else()
    target_link_libraries(bec PUBLIC PkgConfig::ENGINE ${JSON_LIBRARY} m)
endif()

add_executable(m365-bec-mcp src/main.c src/protocol.c src/tools.c src/runbook.c)
target_link_libraries(m365-bec-mcp PRIVATE bec)
target_compile_options(m365-bec-mcp PRIVATE -Wall -Wextra)
install(TARGETS m365-bec-mcp RUNTIME DESTINATION bin)
if(WIN32)
    get_filename_component(toolchain_bin "${CMAKE_C_COMPILER}" DIRECTORY)
    install(CODE "set(toolchain_bin [[${toolchain_bin}]])")
    install(CODE [[
        if(POLICY CMP0207)
            cmake_policy(SET CMP0207 NEW)
        endif()
        file(GET_RUNTIME_DEPENDENCIES
            EXECUTABLES "$<TARGET_FILE:m365-bec-mcp>"
            DIRECTORIES "${toolchain_bin}"
            RESOLVED_DEPENDENCIES_VAR libs
            PRE_EXCLUDE_REGEXES "api-ms-" "ext-ms-"
            POST_EXCLUDE_REGEXES "[Ww][Ii][Nn][Dd][Oo][Ww][Ss]/[Ss][Yy][Ss][Tt][Ee][Mm]32/")
        foreach(lib IN LISTS libs)
            file(TO_CMAKE_PATH "${lib}" normalized)
            cmake_path(IS_PREFIX toolchain_bin "${normalized}" NORMALIZE from_toolchain)
            if(from_toolchain)
                file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE FILE FILES "${lib}")
            endif()
        endforeach()
    ]])
endif()

include(CTest)
if(BUILD_TESTING)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_test(NAME mcp_stdio COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_stdio.py $<TARGET_FILE:m365-bec-mcp>)
endif()
