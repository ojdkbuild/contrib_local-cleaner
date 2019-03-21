# Copyright 2019, akashche at redhat.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required ( VERSION 2.8.12 )

project ( local_cleaner C CXX )

set ( ${PROJECT_NAME}_ICON_PATH "${openjdk_INSTALLER_RESOURCES_PATH}/icon.ico" CACHE STRING "Path to icon file" )
set ( ${PROJECT_NAME}_EXE_VERSION "1,${openjdk_MAJOR_VERSION},${openjdk_UPDATE}${openjdk_RPMBUILD},${openjdk_BUILD}" CACHE STRING "EXE version field" )
set ( ${PROJECT_NAME}_FILE_VERSION "1.${openjdk_MAJOR_VERSION}.0.${openjdk_UPDATE}.${openjdk_RPMBUILD}" CACHE STRING "File version field" )
set ( ${PROJECT_NAME}_COMPANY_NAME_LABEL "${openjdk_VENDOR}" CACHE STRING "Company name version field" )
set ( ${PROJECT_NAME}_FILE_DESCRIPTION_JAVAWS "${openjdk_VENDOR_SHORT} Local Cleaner" CACHE STRING "Cleaner description" )
set ( ${PROJECT_NAME}_PRODUCT_VERSION "${${PROJECT_NAME}_FILE_VERSION}" CACHE STRING "Product version field" )
set ( ${PROJECT_NAME}_MANIFEST_PATH ${CMAKE_CURRENT_LIST_DIR}/resources/cleaner.manifest CACHE STRING "Path to cleaner manifest" )
# test options
set ( ${PROJECT_NAME}_ENABLE_TEST ON CACHE BOOL "Built test app and allow to run a test with it" )

# resources
configure_file ( ${CMAKE_CURRENT_LIST_DIR}/resources/cleaner.rc
        ${CMAKE_CURRENT_BINARY_DIR}/cleaner.rc )

# dependencies
ojdkbuild_add_subdirectory ( ${OJDKBUILD_DIR}/contrib/ojdkbuild-utils ojdkbuild_utils )
ojdkbuild_add_external ( ${OJDKBUILD_DIR}/external/popt )

set ( ${PROJECT_NAME}_DEPS ojdkbuild_utils popt )
ojdkbuild_pkg_check_modules ( ${PROJECT_NAME}_DEPS_PC REQUIRED ${PROJECT_NAME}_DEPS )

# target
add_executable ( ${PROJECT_NAME}
        src/cleaner.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/cleaner.rc )

target_include_directories ( ${PROJECT_NAME} BEFORE PRIVATE
        ${${PROJECT_NAME}_DEPS_PC_INCLUDE_DIRS} )

target_compile_options ( ${PROJECT_NAME} PRIVATE /W4 /WX )

target_link_libraries ( ${PROJECT_NAME}
        ojdkbuild_utils
        popt
        shell32 )

set_property ( TARGET ${PROJECT_NAME} APPEND_STRING PROPERTY LINK_FLAGS "/manifest:no" )

if ( ${PROJECT_NAME}_ENABLE_TEST )

    add_custom_target ( ${PROJECT_NAME}_test
            COMMAND ${CMAKE_COMMAND} -E remove_directory $ENV{LOCALAPPDATA}/${PROJECT_NAME_test}
            COMMAND ${CMAKE_COMMAND} -E make_directory $ENV{LOCALAPPDATA}/${PROJECT_NAME_test}
            COMMAND ${CMAKE_COMMAND} -E make_directory $ENV{LOCALAPPDATA}/${PROJECT_NAME_test}/testdir
            COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/resources/testfile.txt $ENV{LOCALAPPDATA}/${PROJECT_NAME_test}/testfile.txt
            COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}.exe -h
            # TODO
            DEPENDS ${PROJECT_NAME}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Running cleaner test ..." )
endif ( )