cmake_minimum_required(VERSION 3.21)
project(easy_encrypt)

set(CMAKE_CXX_STANDARD 20)

##TODO fill in the paths below
#custom variables
set(CUSTOM_LIBRARY_PATH /usr/local) # /path/to/libraries/dir
set(OPENSSL_PATH /usr/lib64) # /path/to/library/dir
#set(BOOST_PATH /opt/homebrew/opt/boost@1.76) # /path/to/library/dir
set(INSTALL_PARENT_DIR /usr/local) # /path/to/install/dir

set(OPENSSL_LIBRARY_PATH /usr/lib64)
set(OPENSSL_HEADERS_PATH /usr/include)
#set(BOOST_LIBRARY_PATH ${BOOST_PATH}/lib)
#set(BOOST_HEADERS_PATH ${BOOST_PATH}/include)
set(INSTALL_PATH_LIB ${INSTALL_PARENT_DIR}/lib)
set(INSTALL_PATH_HEADERS ${INSTALL_PARENT_DIR}/include)

set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} ${CUSTOM_LIBRARY_PATH})
link_directories(${OPENSSL_LIBRARY_PATH})
include_directories(${OPENSSL_HEADERS_PATH})

find_library(OpenSSL openssl
        PATHS ${OPENSSL_PATH})
find_library(Crypto crypto
        PATHS ${OPENSSL_PATH})
#find_library(Boost boost
#        PATHS ${BOOST_PATH})

add_library(easy_encrypt SHARED EasyEncrypt.cpp EasyEncrypt.h Base64.h)

target_link_libraries(${PROJECT_NAME} ssl crypto)
set_target_properties(easy_encrypt PROPERTIES PREFIX "" PUBLIC_HEADER EasyEncrypt.h)

#shared libary install (TODO)
install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION ${INSTALL_DIR}
        PUBLIC_HEADER DESTINATION ${INSTALL_PATH_HEADERS})
