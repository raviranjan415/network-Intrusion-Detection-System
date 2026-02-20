cmake_minimum_required(VERSION 3.16)
project(IntrusionDetectionSystem LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 COMPONENTS Widgets REQUIRED)

set(SOURCES
    main.cpp
    mainwindow.cpp
)

set(HEADERS
    mainwindow.h
)

qt_standard_project_setup()

qt_add_executable(IntrusionDetectionSystem
    ${SOURCES}
    ${HEADERS}
)

target_link_libraries(IntrusionDetectionSystem PRIVATE Qt6::Widgets)

