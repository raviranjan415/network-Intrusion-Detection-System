# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles\\IntrusionDetectionSystem_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\IntrusionDetectionSystem_autogen.dir\\ParseCache.txt"
  "IntrusionDetectionSystem_autogen"
  )
endif()
