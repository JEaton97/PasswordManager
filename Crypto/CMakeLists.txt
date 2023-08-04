cmake_minimum_required(VERSION 3.14)
set(PROJECT_NAME Crypto)
project(${PROJECT_NAME})

if (NOT DEFINED PROJECT_ROOT)
	set(PROJECT_ROOT ${CMAKE_CURRENT_LIST_DIR})
endif()

option(ENABLE_CRYPTO_TESTS "Build crypto test applications." ON)

add_subdirectory(../_thirdParty/mbedtls-3.4.0 mbedtls EXCLUDE_FROM_ALL)
add_subdirectory(../_thirdParty/argon2-20190702 argon2 EXCLUDE_FROM_ALL)

include_directories(
	${PROJECT_ROOT}/API
	${PROJECT_ROOT}/include
	${PROJECT_ROOT}/../_thirdParty/mbedtls-3.4.0/include
	${PROJECT_ROOT}/../_thirdParty/argon2-20190702/include
)

set(SRC_FILES "")
file(GLOB SRC_FILES src/*.cpp)

add_library(
	${PROJECT_NAME} STATIC
	${SRC_FILES}
)

add_dependencies(
	${PROJECT_NAME}
	mbedcrypto
	argon2
)	

target_link_libraries(
	${PROJECT_NAME}
	mbedcrypto
	argon2
)

if (ENABLE_CRYPTO_TESTS)
	message(STATUS "Crypto Tests enabled")
	file(GLOB TEST_SOURCES ${PROJECT_ROOT}/tests/*.cpp)
	foreach(TEST_SOURCE ${TEST_SOURCES})
		get_filename_component( TEST_NAME ${TEST_SOURCE} NAME_WE)
		add_executable(${TEST_NAME} ${TEST_SOURCE})
		target_link_libraries(
			${TEST_NAME}
			${PROJECT_NAME}
		)
	endforeach()
endif()