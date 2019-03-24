#ifndef _ENDIAN_H_INCLUDED_6_27_2014_
#define _ENDIAN_H_INCLUDED_6_27_2014_

typedef uint8_t uchar;
typedef uint32_t uint;

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

void Int2Byte(const uint* pIn, uchar* pOut, uint nLen);
void Byte2Int(const uchar* pIn, uint* pOut, uint nLen);

void Int2LByte(const uint* pIn, uchar* pOut, uint nLen);
void LByte2Int(const uchar* pIn, uint* pOut, uint nLen);

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


#endif //#ifndef _ENDIAN_H_INCLUDED_6_27_2014_
