include_directories(
        ${PROJECT_SOURCE_DIR}/src/include
        ${PROJECT_SOURCE_DIR}/lib
        ${PROJECT_SOURCE_DIR}/extension
)

add_library(test SHARED module_test.c module_isatap.c entry.c)