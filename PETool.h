#pragma once
#include<windows.h>
#include<iostream>
#include<stdlib.h>
#include"PEDir.h"

/*����*/
extern "C" _declspec(dllexport) DWORD __stdcall PEAlign(DWORD value, DWORD align);
/*��ȡPE�ļ�*/
extern "C" _declspec(dllexport) LPVOID __stdcall createFileBuffer(LPCTSTR fileName);
extern "C" _declspec(dllexport) DWORD _stdcall saveFileBuffer(LPCTSTR fileName,LPVOID lpFileBuffer);
/*��������PE�ļ�*/
extern "C" _declspec(dllexport) LPVOID __stdcall file2Image(LPVOID lpFileBuffer, DWORD *pdwBufferSize);
/*��������PE�ļ���ԭ*/
extern "C" _declspec(dllexport) LPVOID __stdcall image2File(LPVOID lpImageBuffer, DWORD *pdwBufferSize);
/*�ϲ���*/
extern "C" _declspec(dllexport) LPVOID __stdcall mergeSection(LPVOID lpImageBuffer);
/*�ڴ�ƫ��ת�ļ�ƫ��*/
extern "C" _declspec(dllexport) DWORD __stdcall RVA2FOA(LPVOID lpBuffer, DWORD RVA);
/*�ļ�ƫ��ת�ڴ�ƫ��*/
extern "C" _declspec(dllexport) DWORD __stdcall FOA2RVA(LPVOID lpBuffer, DWORD FOA);
/*ͨ����������ȡ������ַ*/
extern "C" _declspec(dllexport) DWORD __stdcall getFunctionAddressByName(LPVOID lpFileBuffer, LPCTSTR checkName);
/*ͨ��������Ż�ȡ������ַ*/
extern "C" _declspec(dllexport) DWORD __stdcall getFunctionAddressByOrdinal(LPVOID lpFileBuffer, DWORD checkOrdinal);
/*��������С�����ڣ�����һ���µĻ�����*/
extern "C" _declspec(dllexport) LPVOID __stdcall addNewSection(LPVOID lpFileBuffer, DWORD size);