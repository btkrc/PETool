#include"pch.h"
#include"utils.h"
/*功能函数，抹除DOS Stub用于新增节*/
DWORD deleteDOSStub(LPVOID lpFileBuffer) {
    PIMAGE_DOS_HEADER pDOS = (PIMAGE_DOS_HEADER)lpFileBuffer;
    PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)((DWORD)pDOS + pDOS->e_lfanew);
    PIMAGE_FILE_HEADER pFile = (PIMAGE_FILE_HEADER)((DWORD)pNT + 4);
    PIMAGE_OPTIONAL_HEADER pOptional = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFile + 20);
    PIMAGE_SECTION_HEADER pSections = (PIMAGE_SECTION_HEADER)((DWORD)pOptional + pFile->SizeOfOptionalHeader);
    //定位到最后一个节头
    PIMAGE_SECTION_HEADER pLastSection = (PIMAGE_SECTION_HEADER)((DWORD)pSections + (pFile->NumberOfSections - 1) * 40);

    /*已经修改过直接返回*/
    if (pDOS->e_lfanew == 0x40) {
        return 1;
    }

    /*
    *****************************
    抹除DOS Stub用于新增节表
    */

    /*计算节表后的空白区，为了便于验证不作判断*/
    DWORD dwSpace = ((DWORD)pDOS + pOptional->SizeOfHeaders) - ((DWORD)pLastSection + 40);

    /*计算移动数据的大小（PE头到最后一个节表的结尾处）*/
    DWORD dwMoveSize = ((DWORD)pSections + (pFile->NumberOfSections) * 40) - (DWORD)pNT;
    /*分配临时内存，储存移动数据*/
    LPVOID lpTemp = malloc(dwMoveSize);
    memset(lpTemp, 0, dwMoveSize);

    /*备份数据*/
    memcpy(lpTemp, pNT, dwMoveSize);

    /*清空原本PE头*/
    memset(pNT, 0, dwMoveSize);

    /*在原本DOS Stub开头处写入PE头到最后一个节表结束的数据
    IMAGE_DOS_HEADER占64字节，偏移64字节就是DOS Stub*/
    memcpy((LPVOID)(DWORD(pDOS) + 64), lpTemp, dwMoveSize);

    /*修正PE头偏移（DOS头占64字节，后面紧跟PE头）*/
    pDOS->e_lfanew = 0x40;

    free(lpTemp);

    return 0;

}