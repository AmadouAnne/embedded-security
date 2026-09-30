# Content hash of the firmware sources, embedded in the binary and reported to
# the HIL host so every run is tied to an exact source tree.
# Algorithm (mirrored in hil/provenance.py): for each file in sorted relative
# path order, the line "<relpath> <sha256>\n"; BUILD_ID = sha256(lines)[:16].
file(GLOB files RELATIVE ${SRC_DIR}
     ${SRC_DIR}/src/*.c ${SRC_DIR}/include/*.h ${SRC_DIR}/config/*.h
     ${SRC_DIR}/ld/*.ld ${SRC_DIR}/CMakeLists.txt ${SRC_DIR}/fetch_deps.sh)
list(SORT files)
set(manifest "")
foreach(f ${files})
  file(SHA256 ${SRC_DIR}/${f} h)
  string(APPEND manifest "${f} ${h}\n")
endforeach()
string(SHA256 id "${manifest}")
string(SUBSTRING ${id} 0 16 id)
set(content "#define BUILD_ID \"${id}\"\n")
if(EXISTS ${OUT})
  file(READ ${OUT} old)
endif()
if(NOT "${old}" STREQUAL "${content}")
  file(WRITE ${OUT} "${content}")
endif()
