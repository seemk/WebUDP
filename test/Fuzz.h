#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

inline uint8_t* LoadFile(const char* name, size_t* length) {
  FILE* f = fopen(name, "rb");
  if (!f) {
    return NULL;
  }
  fseek(f, 0, SEEK_END);
  int64_t size = ftell(f);
  fseek(f, 0, SEEK_SET);
  uint8_t* data = (uint8_t*)calloc(size, 1);
  size_t read = fread(data, 1, size, f);
  *length = read;
  fclose(f);
  return data;
}

