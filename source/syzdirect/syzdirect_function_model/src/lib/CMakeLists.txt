set (AnalyzerSourceCodes
	Common.h
	Common.cc
	Analyzer.h
	Analyzer.cc
	CallGraph.h
	CallGraph.cc
	DataFlowAnalysis.h
	DataFlowAnalysis.cc
	TypeInitializer.cc
	TypeInitializer.h
	CodeFeatures.cc
	CodeFeatures.h
	FopsFinder.cc
	FopsFinder.h
	Signature.h
	Signature.cc
	DeviceExtractor.cc
	DeviceExtractor.h
	NetworkInterfaceExtractor.cc
	NetworkInterfaceExtractor.h
	FilesystemExtractor.cc
	FilesystemExtractor.h
	CallGraphSearch.cc
	CallGraphSearch.h
	DbgInfoHelper.cc
	DbgInfoHelper.h
	Utils.cc
	Utils.h
	PointerAnalysis.h
	PointerAnalysis.cc
	CommonSyscallExtractor.cc
	CommonSyscallExtractor.h
	ArgMapParser.cc
	ArgMapParser.h
	DescriptionGenerator.h
	DescriptionGenerator.cc)

file(COPY configs/ DESTINATION configs)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
set(CMAKE_MACOSX_RPATH 0)

if (DEBUG_CUSTOM)
	add_definitions(-DDEBUG_CUSTOM)
endif()
# Build libraries.
add_library (AnalyzerObj OBJECT ${AnalyzerSourceCodes} )
add_library (Analyzer SHARED $<TARGET_OBJECTS:AnalyzerObj>)
add_library (AnalyzerStatic STATIC $<TARGET_OBJECTS:AnalyzerObj>)

# Build executable.
set (EXECUTABLE_OUTPUT_PATH ${ANALYZER_BINARY_DIR})
link_directories (${ANALYZER_BINARY_DIR}/lib)
add_executable(interface_generator ${AnalyzerSourceCodes})
target_link_libraries(interface_generator 
	LLVMAsmParser 
	LLVMSupport 
	LLVMCore 
	LLVMAnalysis
	LLVMIRReader
	AnalyzerStatic
	)
