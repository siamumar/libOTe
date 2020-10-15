file(GLOB_RECURSE SRCS *.cpp)                                                                                                                                                                                   

include_directories(${CMAKE_SOURCE_DIR})

message(${CMAKE_SOURCE_DIR})

add_executable(netio__ ${SRCS})

find_package(emp-tool REQUIRED)
include_directories(${EMP-TOOL_INCLUDE_DIRS})
find_package(Boost REQUIRED COMPONENTS program_options system)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fconcepts")

message(${CMAKE_CXX_FLAGS})
                                             
target_link_libraries(netio__ libOTe cryptoTools ${Boost_LIBRARIES} ${EMP-TOOL_LIBRARIES})