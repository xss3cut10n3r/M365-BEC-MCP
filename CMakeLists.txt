cmake_minimum_required(VERSION 3.22)
project(m365_bec_mcp VERSION 0.1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

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
target_link_libraries(bec PUBLIC PkgConfig::ENGINE ${JSON_LIBRARY} m)

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
