# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.30

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/kala185/Desktop/KRand

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/kala185/Desktop/KRand/build

# Include any dependencies generated for this target.
include CMakeFiles/KRandShared.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/KRandShared.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/KRandShared.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/KRandShared.dir/flags.make

CMakeFiles/KRandShared.dir/src/KRand.cpp.o: CMakeFiles/KRandShared.dir/flags.make
CMakeFiles/KRandShared.dir/src/KRand.cpp.o: /home/kala185/Desktop/KRand/src/KRand.cpp
CMakeFiles/KRandShared.dir/src/KRand.cpp.o: CMakeFiles/KRandShared.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/kala185/Desktop/KRand/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/KRandShared.dir/src/KRand.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/KRandShared.dir/src/KRand.cpp.o -MF CMakeFiles/KRandShared.dir/src/KRand.cpp.o.d -o CMakeFiles/KRandShared.dir/src/KRand.cpp.o -c /home/kala185/Desktop/KRand/src/KRand.cpp

CMakeFiles/KRandShared.dir/src/KRand.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/KRandShared.dir/src/KRand.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/kala185/Desktop/KRand/src/KRand.cpp > CMakeFiles/KRandShared.dir/src/KRand.cpp.i

CMakeFiles/KRandShared.dir/src/KRand.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/KRandShared.dir/src/KRand.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/kala185/Desktop/KRand/src/KRand.cpp -o CMakeFiles/KRandShared.dir/src/KRand.cpp.s

# Object files for target KRandShared
KRandShared_OBJECTS = \
"CMakeFiles/KRandShared.dir/src/KRand.cpp.o"

# External object files for target KRandShared
KRandShared_EXTERNAL_OBJECTS =

libKRandShared.so: CMakeFiles/KRandShared.dir/src/KRand.cpp.o
libKRandShared.so: CMakeFiles/KRandShared.dir/build.make
libKRandShared.so: CMakeFiles/KRandShared.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/kala185/Desktop/KRand/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX shared library libKRandShared.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/KRandShared.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/KRandShared.dir/build: libKRandShared.so
.PHONY : CMakeFiles/KRandShared.dir/build

CMakeFiles/KRandShared.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/KRandShared.dir/cmake_clean.cmake
.PHONY : CMakeFiles/KRandShared.dir/clean

CMakeFiles/KRandShared.dir/depend:
	cd /home/kala185/Desktop/KRand/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/kala185/Desktop/KRand /home/kala185/Desktop/KRand /home/kala185/Desktop/KRand/build /home/kala185/Desktop/KRand/build /home/kala185/Desktop/KRand/build/CMakeFiles/KRandShared.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/KRandShared.dir/depend

