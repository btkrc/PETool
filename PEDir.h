#pragma once
#include"PETool.h"


/*���㵼�����С�����������ӱ�ͺ������ƣ������ļ���С����*/
DWORD computeExportSize(LPVOID lpFileBuffer);
/*�ƶ�������ָ���Ľ�����ָ��ƫ��*/
DWORD moveExportDir(LPVOID lpFileBuffer, DWORD sectionIndex, DWORD writeOffSet);
/*�����ض�λ��Ĵ�С*/
DWORD computeRelocSize(LPVOID lpFileBuffer);
/*�ƶ��ض�λ��ָ���Ľ�����ָ��ƫ��*/
DWORD moveRelocDir(LPVOID lpFileBuffer, DWORD sectionIndex, DWORD writeOffSet);