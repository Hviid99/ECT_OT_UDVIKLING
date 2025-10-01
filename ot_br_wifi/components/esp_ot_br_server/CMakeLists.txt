idf_component_register(
    SRC_DIRS src
    INCLUDE_DIRS include
    #PRIV_INCLUDE_DIRS private_include
    REQUIRES json mdns fatfs spiffs esp_eth nvs_flash freertos openthread esp_http_server protocol_examples_common
    EMBED_FILES "favicon.ico"
)
target_sources(${COMPONENT_LIB} PRIVATE src/udp_br_func.c)
spiffs_create_partition_image(web_storage frontend FLASH_IN_PROJECT)


