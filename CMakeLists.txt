cmake_minimum_required(VERSION 3.21)
project(untitled)

set(CMAKE_CXX_STANDARD 14)

add_compile_definitions(MG_ENABLE_MD5=1)
#add_compile_definitions(MG_ENABLE_LINES=1)

add_compile_definitions(MG_ENABLE_MBEDTLS=1)
#include_directories(/home/hooman/CLionProjects/mbedtls-3.1.0/include/)
#link_directories(${CMAKE_SOURCE_DIR}/)

include_directories(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/mbed)
add_executable(untitled main.c api.c cJSON.c mongoose.c
        mbed/aes.c
        mbed/aesni.c
        mbed/aria.c
        mbed/asn1parse.c
        mbed/asn1write.c
        mbed/base64.c
        mbed/bignum.c
        mbed/camellia.c
        mbed/ccm.c
        mbed/chacha20.c
        mbed/chachapoly.c
        mbed/cipher.c
        mbed/cipher_wrap.c
        mbed/constant_time.c
        mbed/cmac.c
        mbed/ctr_drbg.c
        mbed/des.c
        mbed/dhm.c
        mbed/ecdh.c
        mbed/ecdsa.c
        mbed/ecjpake.c
        mbed/ecp.c
        mbed/ecp_curves.c
        mbed/entropy.c
        mbed/entropy_poll.c
        mbed/error.c
        mbed/gcm.c
        mbed/hkdf.c
        mbed/hmac_drbg.c
        mbed/md.c
        mbed/md5.c
        mbed/memory_buffer_alloc.c
        mbed/mps_reader.c
        mbed/mps_trace.c
        mbed/nist_kw.c
        mbed/oid.c
        mbed/padlock.c
        mbed/pem.c
        mbed/pk.c
        mbed/pk_wrap.c
        mbed/pkcs12.c
        mbed/pkcs5.c
        mbed/pkparse.c
        mbed/pkwrite.c
        mbed/platform.c
        mbed/platform_util.c
        mbed/poly1305.c
        mbed/psa_crypto.c
        mbed/psa_crypto_aead.c
        mbed/psa_crypto_cipher.c
        mbed/psa_crypto_client.c
        mbed/psa_crypto_driver_wrappers.c
        mbed/psa_crypto_ecp.c
        mbed/psa_crypto_hash.c
        mbed/psa_crypto_mac.c
        mbed/psa_crypto_rsa.c
        mbed/psa_crypto_se.c
        mbed/psa_crypto_slot_management.c
        mbed/psa_crypto_storage.c
        mbed/psa_its_file.c
        mbed/ripemd160.c
        mbed/rsa.c
        mbed/rsa_alt_helpers.c
        mbed/sha1.c
        mbed/sha256.c
        mbed/sha512.c
        mbed/ssl_debug_helpers_generated.c
        mbed/threading.c
        mbed/timing.c
        mbed/version.c
        mbed/version_features.c

        mbed/x509.c
        mbed/x509_create.c
        mbed/x509_crl.c
        mbed/x509_crt.c
        mbed/x509_csr.c
        mbed/x509write_crt.c
        mbed/x509write_csr.c

        mbed/debug.c
        mbed/net_sockets.c
        mbed/ssl_cache.c
        mbed/ssl_ciphersuites.c
        mbed/ssl_cli.c
        mbed/ssl_cookie.c
        mbed/ssl_msg.c
        mbed/ssl_srv.c
        mbed/ssl_ticket.c
        mbed/ssl_tls.c
        mbed/ssl_tls13_keys.c
        mbed/ssl_tls13_server.c
        mbed/ssl_tls13_client.c
        mbed/ssl_tls13_generic.c
        )

target_link_libraries(untitled pthread dl)
#target_link_libraries(untitled pthread dl libmbedx509.a libmbedtls.a libmbedcrypto.a)
