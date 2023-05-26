#pragma once
#include<windows.h>
#include<iostream>
#include<stdlib.h>
#include"PEDir.h"

/*对齐*/
extern "C" _declspec(dllexport) DWORD __stdcall PEAlign(DWORD value, DWORD align);
/*读取PE文件*/
extern "C" _declspec(dllexport) LPVOID __stdcall createFileBuffer(LPCTSTR fileName);
extern "C" _declspec(dllexport) DWORD _stdcall saveFileBuffer(LPCTSTR fileName,LPVOID lpFileBuffer);
/*创建拉伸PE文件*/
extern "C" _declspec(dllexport) LPVOID __stdcall file2Image(LPVOID lpFileBuffer, DWORD *pdwBufferSize);
/*将拉伸后的PE文件复原*/
extern "C" _declspec(dllexport) LPVOID __stdcall image2File(LPVOID lpImageBuffer, DWORD *pdwBufferSize);
/*合并节*/
extern "C" _declspec(dllexport) LPVOID __stdcall mergeSection(LPVOID lpImageBuffer);
/*内存偏移转文件偏移*/
extern "C" _declspec(dllexport) DWORD __stdcall RVA2FOA(LPVOID lpBuffer, DWORD RVA);
/*文件偏移转内存偏移*/
extern "C" _declspec(dllexport) DWORD __stdcall FOA2RVA(LPVOID lpBuffer, DWORD FOA);
/*通过函数名获取函数地址*/
extern "C" _declspec(dllexport) DWORD __stdcall getFunctionAddressByName(LPVOID lpFileBuffer, LPCTSTR checkName);
/*通过导出序号获取函数地址*/
extern "C" _declspec(dllexport) DWORD __stdcall getFunctionAddressByOrdinal(LPVOID lpFileBuffer, DWORD checkOrdinal);
/*按给定大小新增节，返回一个新的缓冲区*/
extern "C" _declspec(dllexport) LPVOID __stdcall addNewSection(LPVOID lpFileBuffer, DWORD size);