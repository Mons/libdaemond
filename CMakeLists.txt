include_directories(src)
add_library(libdaemond src/libdaemond.c)
add_executable(sample ex/sample.c)
target_link_libraries(sample libdaemond)
