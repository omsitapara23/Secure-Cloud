# cmake -H. -Bbuild
# cmake --build build

cmake_minimum_required(VERSION 2.8)
set(CMAKE_CXX_STANDARD 11)
project(cpp-cmake-circle-ci)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)
add_executable(myint_test ${PROJECT_SOURCE_DIR}/tests/myIntTest.cpp)
add_executable(bank_test ${PROJECT_SOURCE_DIR}/tests/bankTest.cpp)
add_executable(dh_test ${PROJECT_SOURCE_DIR}/tests/dhtest.cpp -lcrypto++)

