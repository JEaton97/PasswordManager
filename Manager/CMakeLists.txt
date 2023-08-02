cmake_minimum_required(VERSION 3.14)
set(PROJECT_NAME PasswordManager)
project(${PROJECT_NAME})

if (NOT DEFINED PROJECT_ROOT)
	set(PROJECT_ROOT ${CMAKE_CURRENT_LIST_DIR})
endif()

include_directories(
	${PROJECT_ROOT}/include
	${PROJECT_ROOT}/../Crypto/API
)

set(SRC_FILES "")
file(GLOB SRC_FILES src/*.cpp)

add_executable(
	${PROJECT_NAME}
	${SRC_FILES}
)

target_link_libraries(
	${PROJECT_NAME}
	Crypto
)