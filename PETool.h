#pragma once
#include<windows.h>
#include<iostream>
#include<stdlib.h>
#include"PEDir.h"

/*����*/
DWORD __stdcall PEAlign(DWORD value, DWORD align);
/*��ȡPE�ļ�*/
LPVOID __stdcall createFileBuffer(LPCTSTR fileName);
/*����PE�ļ�*/
DWORD _stdcall saveFileBuffer(LPCTSTR fileName, LPVOID lpFileBuffer);
/*��������PE�ļ�*/
LPVOID __stdcall file2Image(LPVOID lpFileBuffer, DWORD *pdwBufferSize);
/*��������PE�ļ���ԭ*/
LPVOID __stdcall image2File(LPVOID lpImageBuffer, DWORD *pdwBufferSize);
/*�ϲ���*/
LPVOID __stdcall mergeSection(LPVOID lpImageBuffer);
/*�ڴ�ƫ��ת�ļ�ƫ��*/
DWORD __stdcall RVA2FOA(LPVOID lpBuffer, DWORD RVA);
/*�ļ�ƫ��ת�ڴ�ƫ��*/
DWORD __stdcall FOA2RVA(LPVOID lpBuffer, DWORD FOA);
/*ͨ����������ȡ������ַ*/
DWORD __stdcall getFunctionAddressByName(LPVOID lpFileBuffer, LPCTSTR checkName);
/*ͨ��������Ż�ȡ������ַ*/
DWORD __stdcall getFunctionAddressByOrdinal(LPVOID lpFileBuffer, DWORD checkOrdinal);
/*��������С�����ڣ�����һ���µĻ�����*/
LPVOID __stdcall  addNewSection(LPVOID lpFileBuffer, DWORD size);