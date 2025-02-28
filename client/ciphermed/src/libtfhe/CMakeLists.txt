cmake_minimum_required(VERSION 3.0)
add_definitions(-w)
# include the fft processors in the build process
add_subdirectory(fft_processors)

set(SRCS
    autogenerated.cpp
    lwebootstrappingkey.cpp
    lwe.cpp
    lwe-functions.cpp
    lwekey.cpp
    lwekeyswitch.cpp
    lweparams.cpp
    lwesamples.cpp
    multiplication.cpp
    numeric-functions.cpp
    polynomials.cpp
    tgsw.cpp
    tlwe.cpp
    tlwe-functions.cpp
    tgsw-functions.cpp
    tlwe-fft-operations.cpp
    tgsw-fft-operations.cpp
    toruspolynomial-functions.cpp
    boot-gates.cpp
    lwe-keyswitch-functions.cpp
    lwe-bootstrapping-functions.cpp
    lwe-bootstrapping-functions-fft.cpp
    tfhe_io.cpp
    tfhe_generic_streams.cpp
    tfhe_garbage_collector.cpp
    tfhe_gate_bootstrapping.cpp
    tfhe_gate_bootstrapping_structures.cpp

    mkTFHEparams.cpp
    mkTFHEkeys.cpp
    mkTFHEkeygen.cpp
    mkTFHEsamples.cpp
    mkTFHEfunctions.cpp
    )


add_library(tfhe-core OBJECT ${SRCS} ${TFHE_HEADERS})
set_property(TARGET tfhe-core PROPERTY POSITION_INDEPENDENT_CODE ON)

foreach (FFT_PROCESSOR IN LISTS FFT_PROCESSORS) 
    add_library(tfhe-${FFT_PROCESSOR} SHARED
	$<TARGET_OBJECTS:tfhe-core>
        $<TARGET_OBJECTS:tfhe-fft-${FFT_PROCESSOR}>)
    set_property(TARGET tfhe-${FFT_PROCESSOR} PROPERTY POSITION_INDEPENDENT_CODE ON)

    if (FFT_PROCESSOR STREQUAL "fftw")
        target_link_libraries(tfhe-fftw ${FFTW_LIBRARIES})
    endif (FFT_PROCESSOR STREQUAL "fftw")

    install(TARGETS tfhe-${FFT_PROCESSOR}
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
endforeach (FFT_PROCESSOR IN LISTS FFT_PROCESSORS) 

