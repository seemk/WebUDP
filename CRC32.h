#pragma once

#include <stdint.h>
#include <stddef.h>

uint32_t StunCRC32(const void* data, size_t len);
uint32_t SctpCRC32(const void* data, size_t len);
