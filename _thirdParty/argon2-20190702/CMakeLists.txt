cmake_minimum_required(VERSION 3.14)
set(PROJECT_NAME argon2)
project(${PROJECT_NAME})

include_directories(
	${CMAKE_CURRENT_LIST_DIR}/include
)

set(SRC_FILES "")
file(GLOB_RECURSE SRC_FILES ${CMAKE_CURRENT_LIST_DIR}/src/*.c)

foreach (SRC ${SRC_FILES})
	if (${SRC} MATCHES "bench.c" OR
		${SRC} MATCHES "test.c" OR
		${SRC} MATCHES "run.c")
		list(REMOVE_ITEM SRC_FILES ${SRC})
	endif()
endforeach()


add_library(
	${PROJECT_NAME} STATIC
	${SRC_FILES}
)

if (UNIX)
	set(THREADS_PREFER_PTHREAD_FLAG ON)
	find_package(Threads REQUIRED)
	target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads)
endif()