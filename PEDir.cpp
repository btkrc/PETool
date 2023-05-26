#pragma once
#include"pch.h"
#include"PETool.h"
#include"utils.h"
#include"PEDir.h"

/*计算导出表大小（包含三个子表和函数名称），以文件大小对齐*/
DWORD computeExportSize(LPVOID lpFileBuffer) {
    PIMAGE_DOS_HEADER pDos =
        (PIMAGE_DOS_HEADER)lpFileBuffer;
    PIMAGE_NT_HEADERS pNT =
        (PIMAGE_NT_HEADERS)((DWORD)lpFileBuffer + pDos->e_lfanew);
    PIMAGE_FILE_HEADER pFile =
        (PIMAGE_FILE_HEADER)((DWORD)pNT + 4);
    PIMAGE_OPTIONAL_HEADER pOption =
        (PIMAGE_OPTIONAL_HEADER)((DWORD)pFile + IMAGE_SIZEOF_FILE_HEADER);

    /*导出表IDD结构*/
    IMAGE_DATA_DIRECTORY exportIDD = pOption->DataDirectory[0];
    /*导出表地址是RVA，需要转换成FOA*/
    PIMAGE_EXPORT_DIRECTORY pExportDir =
        (PIMAGE_EXPORT_DIRECTORY)(RVA2FOA(lpFileBuffer, exportIDD.VirtualAddress) + (DWORD)lpFileBuffer);

    /*获取函数地址表、函数名称表、函数序号表的地址*/
    PDWORD lpAddOfFns = (PDWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfFunctions) + (DWORD)lpFileBuffer);
    PDWORD lpAddOfNames = (PDWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfNames) + (DWORD)lpFileBuffer);
    /*序号表的数据为2个字节*/
    PWORD lpAddOfOrdinals = (PWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfNameOrdinals) + (DWORD)lpFileBuffer);


    /*导出表和三个子表的大小*/
    DWORD computeResult = sizeof(IMAGE_EXPORT_DIRECTORY) +
        pExportDir->NumberOfFunctions * 4 +
        pExportDir->NumberOfNames * 2 +
        pExportDir->NumberOfNames * 4;

    /*计算所有函数名的大小*/
    for (int i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCTSTR fnName = (LPCTSTR)(RVA2FOA(lpFileBuffer, lpAddOfNames[i]) + (DWORD)lpFileBuffer);
        /*大小+1储存\0结尾*/
        DWORD strLen = strlen(fnName) + 1;
        computeResult += strLen;
    }


    /*返回对齐后的大小*/
    return PEAlign(computeResult, pOption->FileAlignment);
}


DWORD moveExportDir(LPVOID lpFileBuffer, DWORD sectionIndex, DWORD writeOffSet) {
    PIMAGE_DOS_HEADER pDos =
        (PIMAGE_DOS_HEADER)lpFileBuffer;
    PIMAGE_NT_HEADERS pNT =
        (PIMAGE_NT_HEADERS)((DWORD)lpFileBuffer + pDos->e_lfanew);
    PIMAGE_FILE_HEADER pFile =
        (PIMAGE_FILE_HEADER)((DWORD)pNT + 4);
    PIMAGE_OPTIONAL_HEADER pOption =
        (PIMAGE_OPTIONAL_HEADER)((DWORD)pFile + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER pFirstSection =
        PIMAGE_SECTION_HEADER((DWORD)pOption + pFile->SizeOfOptionalHeader);
    /*获取最后一个节表的地址*/
    PIMAGE_SECTION_HEADER pWriteSection =
        PIMAGE_SECTION_HEADER((DWORD)pFirstSection + (sectionIndex * IMAGE_SIZEOF_SECTION_HEADER));
    /*导出表IDD结构*/
    IMAGE_DATA_DIRECTORY exportIDD = pOption->DataDirectory[0];
    /*导出表地址是RVA，需要转换成FOA*/
    PIMAGE_EXPORT_DIRECTORY pExportDir =
        (PIMAGE_EXPORT_DIRECTORY)(RVA2FOA(lpFileBuffer, exportIDD.VirtualAddress) + (DWORD)lpFileBuffer);

    /*获取函数地址表、函数名称表、函数序号表的地址*/
    PDWORD lpAddOfFns = (PDWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfFunctions) + (DWORD)lpFileBuffer);
    PDWORD lpAddOfNames = (PDWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfNames) + (DWORD)lpFileBuffer);
    /*序号表的数据为2个字节*/
    PWORD lpAddOfOrdinals = (PWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfNameOrdinals) + (DWORD)lpFileBuffer);

    /*复制函数地址表*/
    PDWORD lpNewAddOfFns = (PDWORD)(pWriteSection->PointerToRawData + (DWORD)lpFileBuffer + writeOffSet);
    memcpy(lpNewAddOfFns, lpAddOfFns, pExportDir->NumberOfFunctions * 4);

    /*复制序号表*/
    PDWORD lpNewAddOfOrdinals = (PDWORD)((DWORD)lpNewAddOfFns + pExportDir->NumberOfFunctions * 4);
    memcpy(lpNewAddOfOrdinals, lpAddOfOrdinals, pExportDir->NumberOfNames * 2);

    /*复制名称表，需要修复*/
    PDWORD lpNewAddOfNames = (PDWORD)((DWORD)lpNewAddOfOrdinals + pExportDir->NumberOfNames * 2);
    /*数据块，储存函数名字符串*/
    PBYTE lpNameStrBlock = (PBYTE)((DWORD)lpNewAddOfNames + pExportDir->NumberOfNames * 4);

    /*复制函数名字符串，并修复名称表*/
    for (int i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCTSTR tempStr = (LPCTSTR)(RVA2FOA(lpFileBuffer, lpAddOfNames[i]) + (DWORD)lpFileBuffer);
        memcpy(lpNameStrBlock, tempStr, strlen(tempStr) + 1);
        /*修复名称表，储存字符串地址的RVA*/
        lpNewAddOfNames[i] = FOA2RVA(lpFileBuffer, (DWORD)lpNameStrBlock - (DWORD)lpFileBuffer);
        lpNameStrBlock += strlen(tempStr) + 1;
    }

    /*复制导出表*/
    PIMAGE_EXPORT_DIRECTORY pNewExportDir = (PIMAGE_EXPORT_DIRECTORY)lpNameStrBlock;
    memcpy(pNewExportDir, pExportDir, sizeof(PIMAGE_EXPORT_DIRECTORY));

    /*修复导出表的三个子表*/
    pNewExportDir->AddressOfFunctions = FOA2RVA(lpFileBuffer, (DWORD)lpNewAddOfFns - (DWORD)lpFileBuffer);
    pNewExportDir->AddressOfNameOrdinals = FOA2RVA(lpFileBuffer, (DWORD)lpNewAddOfOrdinals - (DWORD)lpFileBuffer);
    pNewExportDir->AddressOfNames = FOA2RVA(lpFileBuffer, (DWORD)lpNewAddOfNames - (DWORD)lpFileBuffer);

    /*修复目录项指向导出表的地址*/
    exportIDD.VirtualAddress = FOA2RVA(lpFileBuffer, (DWORD)pNewExportDir - (DWORD)lpFileBuffer);
    return 0;
}


DWORD computeRelocSize(LPVOID lpFileBuffer) {
    PIMAGE_DOS_HEADER pDos =
        (PIMAGE_DOS_HEADER)lpFileBuffer;
    PIMAGE_NT_HEADERS pNT =
        (PIMAGE_NT_HEADERS)((DWORD)lpFileBuffer + pDos->e_lfanew);
    PIMAGE_FILE_HEADER pFile =
        (PIMAGE_FILE_HEADER)((DWORD)pNT + 4);
    PIMAGE_OPTIONAL_HEADER pOption =
        (PIMAGE_OPTIONAL_HEADER)((DWORD)pFile + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER pFirstSection =
        (PIMAGE_SECTION_HEADER)((DWORD)pOption + pFile->SizeOfOptionalHeader);

    /*重定位表的信息结构*/
    IMAGE_DATA_DIRECTORY pReloc = (IMAGE_DATA_DIRECTORY)pOption->DataDirectory[5];

    /*获取重定位表的文件偏移*/
    PIMAGE_BASE_RELOCATION pRelocFileOffset =
        (PIMAGE_BASE_RELOCATION)(RVA2FOA(lpFileBuffer, (DWORD)pReloc.VirtualAddress) + (DWORD)lpFileBuffer);

    DWORD dwComputeResult = 0;
    for (int i = 0; pRelocFileOffset->VirtualAddress; i++) {
        dwComputeResult += pRelocFileOffset->SizeOfBlock;
        pRelocFileOffset = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocFileOffset + pRelocFileOffset->SizeOfBlock);
    }

    return dwComputeResult;

}

DWORD moveRelocDir(LPVOID lpFileBuffer, DWORD sectionIndex, DWORD writeOffSet) {
    PIMAGE_DOS_HEADER pDos =
        (PIMAGE_DOS_HEADER)lpFileBuffer;
    PIMAGE_NT_HEADERS pNT =
        (PIMAGE_NT_HEADERS)((DWORD)lpFileBuffer + pDos->e_lfanew);
    PIMAGE_FILE_HEADER pFile =
        (PIMAGE_FILE_HEADER)((DWORD)pNT + 4);
    PIMAGE_OPTIONAL_HEADER pOption =
        (PIMAGE_OPTIONAL_HEADER)((DWORD)pFile + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER pFirstSection =
        (PIMAGE_SECTION_HEADER)((DWORD)pOption + pFile->SizeOfOptionalHeader);

    PIMAGE_SECTION_HEADER pWriteSection =
        PIMAGE_SECTION_HEADER((DWORD)pFirstSection + (sectionIndex * IMAGE_SIZEOF_SECTION_HEADER));

    /*重定位表的信息结构*/
    IMAGE_DATA_DIRECTORY pReloc = (IMAGE_DATA_DIRECTORY)pOption->DataDirectory[5];

    /*获取重定位表的文件偏移*/
    PIMAGE_BASE_RELOCATION pRelocFileOffset =
        (PIMAGE_BASE_RELOCATION)(RVA2FOA(lpFileBuffer, (DWORD)pReloc.VirtualAddress) + (DWORD)lpFileBuffer);

    /*新的重定位表地址*/
    DWORD pNewRelocFileOffset = pWriteSection->PointerToRawData + (DWORD)lpFileBuffer + writeOffSet;


    for (int i = 0; pRelocFileOffset->VirtualAddress; i++) {
        DWORD blockSize = pRelocFileOffset->SizeOfBlock;
        memcpy((LPVOID)pNewRelocFileOffset, pRelocFileOffset, blockSize);
        pRelocFileOffset = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocFileOffset + blockSize);
        pNewRelocFileOffset += blockSize;
    }

    /*将新的地址转为RVA用以修复目录项*/
    pOption->DataDirectory[5].VirtualAddress =
        FOA2RVA(lpFileBuffer, pWriteSection->PointerToRawData + writeOffSet);

    return 0;
}
