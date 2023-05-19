#pragma once
#include<windows.h>
#include<iostream>
#include<stdlib.h>

/*对齐*/
DWORD __stdcall PEAlign(DWORD value, DWORD align);
/*读取PE文件*/
LPVOID __stdcall createFileBuffer(LPCTSTR fileName);
/*创建拉伸PE文件*/
LPVOID __stdcall file2Image(LPVOID lpFileBuffer, DWORD *pdwBufferSize);
/*将拉伸后的PE文件复原*/
LPVOID __stdcall image2File(LPVOID lpImageBuffer, DWORD *pdwBufferSize);
/*合并节*/
LPVOID __stdcall mergeSection(LPVOID lpImageBuffer);
/*内存偏移转文件偏移*/
DWORD RVA2FOA(LPVOID lpBuffer, DWORD RVA);
/*文件偏移转内存偏移*/
DWORD FOA2RVA(LPVOID lpBuffer, DWORD FOA);
/*通过函数名获取函数地址*/
DWORD getFunctionAddressByName(LPVOID lpFileBuffer, LPCTSTR checkName);
/*通过导出序号获取函数地址*/
DWORD getFunctionAddressByOrdinal(LPVOID lpFileBuffer, DWORD checkOrdinal);
/*按给定大小新增节，返回一个新的缓冲区*/
LPVOID addNewSection(LPVOID lpFileBuffer, DWORD size);