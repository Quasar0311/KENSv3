# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.19.2)

# We name the project and the target for the ExternalProject_Add() call
# to something that will highlight to the user what we are working on if
# something goes wrong and an error message is produced.

project(kens_solution-populate NONE)

include(ExternalProject)
ExternalProject_Add(kens_solution-populate
                     "UPDATE_DISCONNECTED" "False" "URL" "https://anlab-kaist.github.io/KENSv3/solution/kens_solution-universal-Darwin-AppleClang.zip"
                    SOURCE_DIR          "/Users/quasar/Desktop/KENSv3/build/_deps/kens_solution-src"
                    BINARY_DIR          "/Users/quasar/Desktop/KENSv3/build/_deps/kens_solution-build"
                    CONFIGURE_COMMAND   ""
                    BUILD_COMMAND       ""
                    INSTALL_COMMAND     ""
                    TEST_COMMAND        ""
                    USES_TERMINAL_DOWNLOAD  YES
                    USES_TERMINAL_UPDATE    YES
)


