cmake_minimum_required(VERSION 2.8)


project(open_password_manager)
set(SOURCE_EXE main.c info.c daemon.c db.c term.c encrypt.c password.c)
#set(SOURCE_LIB foo.c)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g")

include_directories(includes)

#add_library(foo STATIC ${SOURCE_LIB})
find_package(OpenSSL REQUIRED)
if (NOT OPENSSL_FOUND)
	message(SEND_ERROR "Failed to find openssl")
	return()
else()
	include_directories(${OPENSSL_INCLUDE_DIR})
endif()

find_package(X11)
if (NOT X11_FOUND)
	message(WARNING "X11 devel package was not found. Password buffering will not work")
	add_definitions( -DNO_X11 )
else()
	if (NOT X11_Xmu_FOUND)
		# for old cmakes
		find_path(X11_Xmu_INCLUDE_PATH X11/Xmu/Xmu.h ${X11_INC_SEARCH_PATH})
		find_library(X11_Xmu_LIB Xmu ${X11_LIB_SEARCH_PATH})
		if (X11_Xmu_INCLUDE_PATH AND X11_Xmu_LIB)
			set(X11_OK "1")
			set(X11_INCLUDE_DIR ${X11_INCLUDE_DIR} ${X11_Xmu_INCLUDE_PATH})
			include_directories(${X11_INCLUDE_DIR})
			include_directories(${X11_Xmu_INCLUDE_PATH})
		else()
			message(WARNING "libXmu devel package was not found. Password buffering will not work")
			add_definitions( -DNO_X11 )
		endif()
	else()
		set(X11_OK "1")
		include_directories(${X11_INCLUDE_DIR})
		include_directories(${X11_Xmu_INCLUDE_PATH})
	endif()
endif()

set(PROGNAME "opm")

add_executable(${PROGNAME} ${SOURCE_EXE})

target_link_libraries(${PROGNAME} ${OPENSSL_LIBRARIES})
if (X11_OK)
	target_link_libraries(${PROGNAME} ${X11_LIBRARIES})
	target_link_libraries(${PROGNAME} ${X11_Xmu_LIB})
endif()


install(TARGETS ${PROGNAME} DESTINATION /usr/bin)
