#pragma once
#include"PETool.h"


/*计算导出表大小（包含三个子表和函数名称），以文件大小对齐*/
DWORD computeExportSize(LPVOID lpFileBuffer);
/*移动导出表到指定的节区并指定偏移*/
DWORD moveExportDir(LPVOID lpFileBuffer, DWORD sectionIndex, DWORD writeOffSet);
/*计算重定位表的大小*/
DWORD computeRelocSize(LPVOID lpFileBuffer);
/*移动重定位表到指定的节区并指定偏移*/
DWORD moveRelocDir(LPVOID lpFileBuffer, DWORD sectionIndex, DWORD writeOffSet);