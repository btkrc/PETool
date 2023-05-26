#pragma once
#include"pch.h"
#include"PETool.h"
#include"utils.h"
#include"PEDir.h"

/*���㵼�����С�����������ӱ�ͺ������ƣ������ļ���С����*/
DWORD computeExportSize(LPVOID lpFileBuffer) {
    PIMAGE_DOS_HEADER pDos =
        (PIMAGE_DOS_HEADER)lpFileBuffer;
    PIMAGE_NT_HEADERS pNT =
        (PIMAGE_NT_HEADERS)((DWORD)lpFileBuffer + pDos->e_lfanew);
    PIMAGE_FILE_HEADER pFile =
        (PIMAGE_FILE_HEADER)((DWORD)pNT + 4);
    PIMAGE_OPTIONAL_HEADER pOption =
        (PIMAGE_OPTIONAL_HEADER)((DWORD)pFile + IMAGE_SIZEOF_FILE_HEADER);

    /*������IDD�ṹ*/
    IMAGE_DATA_DIRECTORY exportIDD = pOption->DataDirectory[0];
    /*�������ַ��RVA����Ҫת����FOA*/
    PIMAGE_EXPORT_DIRECTORY pExportDir =
        (PIMAGE_EXPORT_DIRECTORY)(RVA2FOA(lpFileBuffer, exportIDD.VirtualAddress) + (DWORD)lpFileBuffer);

    /*��ȡ������ַ���������Ʊ�������ű�ĵ�ַ*/
    PDWORD lpAddOfFns = (PDWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfFunctions) + (DWORD)lpFileBuffer);
    PDWORD lpAddOfNames = (PDWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfNames) + (DWORD)lpFileBuffer);
    /*��ű������Ϊ2���ֽ�*/
    PWORD lpAddOfOrdinals = (PWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfNameOrdinals) + (DWORD)lpFileBuffer);


    /*������������ӱ�Ĵ�С*/
    DWORD computeResult = sizeof(IMAGE_EXPORT_DIRECTORY) +
        pExportDir->NumberOfFunctions * 4 +
        pExportDir->NumberOfNames * 2 +
        pExportDir->NumberOfNames * 4;

    /*�������к������Ĵ�С*/
    for (int i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCTSTR fnName = (LPCTSTR)(RVA2FOA(lpFileBuffer, lpAddOfNames[i]) + (DWORD)lpFileBuffer);
        /*��С+1����\0��β*/
        DWORD strLen = strlen(fnName) + 1;
        computeResult += strLen;
    }


    /*���ض����Ĵ�С*/
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
    /*��ȡ���һ���ڱ�ĵ�ַ*/
    PIMAGE_SECTION_HEADER pWriteSection =
        PIMAGE_SECTION_HEADER((DWORD)pFirstSection + (sectionIndex * IMAGE_SIZEOF_SECTION_HEADER));
    /*������IDD�ṹ*/
    IMAGE_DATA_DIRECTORY exportIDD = pOption->DataDirectory[0];
    /*�������ַ��RVA����Ҫת����FOA*/
    PIMAGE_EXPORT_DIRECTORY pExportDir =
        (PIMAGE_EXPORT_DIRECTORY)(RVA2FOA(lpFileBuffer, exportIDD.VirtualAddress) + (DWORD)lpFileBuffer);

    /*��ȡ������ַ���������Ʊ�������ű�ĵ�ַ*/
    PDWORD lpAddOfFns = (PDWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfFunctions) + (DWORD)lpFileBuffer);
    PDWORD lpAddOfNames = (PDWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfNames) + (DWORD)lpFileBuffer);
    /*��ű������Ϊ2���ֽ�*/
    PWORD lpAddOfOrdinals = (PWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfNameOrdinals) + (DWORD)lpFileBuffer);

    /*���ƺ�����ַ��*/
    PDWORD lpNewAddOfFns = (PDWORD)(pWriteSection->PointerToRawData + (DWORD)lpFileBuffer + writeOffSet);
    memcpy(lpNewAddOfFns, lpAddOfFns, pExportDir->NumberOfFunctions * 4);

    /*������ű�*/
    PDWORD lpNewAddOfOrdinals = (PDWORD)((DWORD)lpNewAddOfFns + pExportDir->NumberOfFunctions * 4);
    memcpy(lpNewAddOfOrdinals, lpAddOfOrdinals, pExportDir->NumberOfNames * 2);

    /*�������Ʊ���Ҫ�޸�*/
    PDWORD lpNewAddOfNames = (PDWORD)((DWORD)lpNewAddOfOrdinals + pExportDir->NumberOfNames * 2);
    /*���ݿ飬���溯�����ַ���*/
    PBYTE lpNameStrBlock = (PBYTE)((DWORD)lpNewAddOfNames + pExportDir->NumberOfNames * 4);

    /*���ƺ������ַ��������޸����Ʊ�*/
    for (int i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCTSTR tempStr = (LPCTSTR)(RVA2FOA(lpFileBuffer, lpAddOfNames[i]) + (DWORD)lpFileBuffer);
        memcpy(lpNameStrBlock, tempStr, strlen(tempStr) + 1);
        /*�޸����Ʊ������ַ�����ַ��RVA*/
        lpNewAddOfNames[i] = FOA2RVA(lpFileBuffer, (DWORD)lpNameStrBlock - (DWORD)lpFileBuffer);
        lpNameStrBlock += strlen(tempStr) + 1;
    }

    /*���Ƶ�����*/
    PIMAGE_EXPORT_DIRECTORY pNewExportDir = (PIMAGE_EXPORT_DIRECTORY)lpNameStrBlock;
    memcpy(pNewExportDir, pExportDir, sizeof(PIMAGE_EXPORT_DIRECTORY));

    /*�޸�������������ӱ�*/
    pNewExportDir->AddressOfFunctions = FOA2RVA(lpFileBuffer, (DWORD)lpNewAddOfFns - (DWORD)lpFileBuffer);
    pNewExportDir->AddressOfNameOrdinals = FOA2RVA(lpFileBuffer, (DWORD)lpNewAddOfOrdinals - (DWORD)lpFileBuffer);
    pNewExportDir->AddressOfNames = FOA2RVA(lpFileBuffer, (DWORD)lpNewAddOfNames - (DWORD)lpFileBuffer);

    /*�޸�Ŀ¼��ָ�򵼳���ĵ�ַ*/
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

    /*�ض�λ�����Ϣ�ṹ*/
    IMAGE_DATA_DIRECTORY pReloc = (IMAGE_DATA_DIRECTORY)pOption->DataDirectory[5];

    /*��ȡ�ض�λ����ļ�ƫ��*/
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

    /*�ض�λ�����Ϣ�ṹ*/
    IMAGE_DATA_DIRECTORY pReloc = (IMAGE_DATA_DIRECTORY)pOption->DataDirectory[5];

    /*��ȡ�ض�λ����ļ�ƫ��*/
    PIMAGE_BASE_RELOCATION pRelocFileOffset =
        (PIMAGE_BASE_RELOCATION)(RVA2FOA(lpFileBuffer, (DWORD)pReloc.VirtualAddress) + (DWORD)lpFileBuffer);

    /*�µ��ض�λ���ַ*/
    DWORD pNewRelocFileOffset = pWriteSection->PointerToRawData + (DWORD)lpFileBuffer + writeOffSet;


    for (int i = 0; pRelocFileOffset->VirtualAddress; i++) {
        DWORD blockSize = pRelocFileOffset->SizeOfBlock;
        memcpy((LPVOID)pNewRelocFileOffset, pRelocFileOffset, blockSize);
        pRelocFileOffset = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocFileOffset + blockSize);
        pNewRelocFileOffset += blockSize;
    }

    /*���µĵ�ַתΪRVA�����޸�Ŀ¼��*/
    pOption->DataDirectory[5].VirtualAddress =
        FOA2RVA(lpFileBuffer, pWriteSection->PointerToRawData + writeOffSet);

    return 0;
}
