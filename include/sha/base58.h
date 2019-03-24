#ifndef BASE58__H_INCLUDED
#define BASE58__H_INCLUDED
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

uint32_t base58Encode(const uint8_t* pIn, uint32_t cbSize, char* pOut);
uint32_t base58Decode(const char* pIn, uint32_t cbSize, uint8_t* pOut);

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus

#endif //BASE58__H_INCLUDED
