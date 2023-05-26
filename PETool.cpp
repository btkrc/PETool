#pragma once
#include"pch.h"
#include"PETool.h"
#include"utils.h"

DWORD __stdcall PEAlign(DWORD value, DWORD align) {
    if (value <= align) {
        return align;
    }
    if (value > align && !(value % align)) {
        return value;
    }
    if (value > align && (value % align)) {
        return value + (align - (value % align));
    }

    return NULL;
}

LPVOID __stdcall createFileBuffer(LPCTSTR fileName) {
    FILE *fp;

    errno_t err = fopen_s(&fp, fileName, "rb");

    if (err) {
        printf("err %d\n", err);
        return NULL;
    }

    if (!fp) {
        printf("fopen error\n");
        return NULL;
    }

    /*获取文件大小*/
    fseek(fp, 0, SEEK_END);
    DWORD size = ftell(fp);

    LPVOID lpFileBuffer = malloc(size);

    if (!lpFileBuffer) {
        printf("申请内存失败..\n");
        fclose(fp);
        return NULL;
    }

    fseek(fp, 0, SEEK_SET);

    fread_s(lpFileBuffer, size, size, 1, fp);

    fclose(fp);

    return lpFileBuffer;
}

DWORD __stdcall saveFileBuffer(LPCTSTR fileName, LPVOID lpFileBuffer) {
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
    //定位到最后一个节头
    PIMAGE_SECTION_HEADER pLastSection = (PIMAGE_SECTION_HEADER)((DWORD)pFirstSection + (pFile->NumberOfSections - 1) * 40);

    FILE *fp;
    fopen_s(&fp, fileName, "wb+");
    if (!fp) {
        printf("fopen error\n");
        return 1;
    }

    fseek(fp, 0, SEEK_SET);

    DWORD count = fwrite(lpFileBuffer, pLastSection->PointerToRawData + pLastSection->SizeOfRawData, 1, fp);

    if (count) {
        return 0;
    }

    fclose(fp);

}

LPVOID __stdcall file2Image(LPVOID lpFileBuffer, DWORD *pdwBufferSize) {
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

    /*按照拉伸后的大小申请内存*/
    LPVOID lpImageBuffer = malloc(pOption->SizeOfImage);

    memset(lpImageBuffer, 0, pOption->SizeOfImage);

    /*写入头部，不需要对齐，下面从VA开始写入*/
    memcpy(lpImageBuffer, lpFileBuffer, pOption->SizeOfHeaders);

    /*遍历写入节区，按照内存对齐写入*/
    PIMAGE_SECTION_HEADER pSectionHeader = pFirstSection;
    for (int i = 0; i < pFile->NumberOfSections; i++) {
        memcpy(
            (LPVOID)((DWORD)lpImageBuffer + pSectionHeader->VirtualAddress),
            (LPVOID)((DWORD)lpFileBuffer + pSectionHeader->PointerToRawData),
            pSectionHeader->Misc.VirtualSize
        );
        /*指向下一个节表*/
        pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);
    }

    *pdwBufferSize = pOption->SizeOfImage;


    return lpImageBuffer;
}

LPVOID __stdcall image2File(LPVOID lpImageBuffer, DWORD *pdwBufferSize) {
    PIMAGE_DOS_HEADER pDos =
        (PIMAGE_DOS_HEADER)lpImageBuffer;
    PIMAGE_NT_HEADERS pNT =
        (PIMAGE_NT_HEADERS)((DWORD)lpImageBuffer + pDos->e_lfanew);
    PIMAGE_FILE_HEADER pFile =
        (PIMAGE_FILE_HEADER)((DWORD)pNT + 4);
    PIMAGE_OPTIONAL_HEADER pOption =
        (PIMAGE_OPTIONAL_HEADER)((DWORD)pFile + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER pFirstSection =
        PIMAGE_SECTION_HEADER((DWORD)pOption + pFile->SizeOfOptionalHeader);

    /*获取最后一个节表的地址*/
    PIMAGE_SECTION_HEADER pLastSection =
        PIMAGE_SECTION_HEADER((DWORD)pFirstSection + ((pFile->NumberOfSections - 1) * IMAGE_SIZEOF_SECTION_HEADER));

    /*获取FileBuffer的大小，用最后一个节的文件偏移加上文件对齐大小得出*/
    *pdwBufferSize = pLastSection->PointerToRawData + pLastSection->SizeOfRawData;

    /*按照文件对齐大小分配内存*/
    LPVOID lpFileBuffer = malloc(*pdwBufferSize);

    memset(lpFileBuffer, 0, *pdwBufferSize);

    /*写入头，按照文件对齐*/
    memcpy(lpFileBuffer, lpImageBuffer, pOption->SizeOfHeaders);

    PIMAGE_SECTION_HEADER pSectionHeader = pFirstSection;
    for (int i = 0; i < pFile->NumberOfSections; i++) {
        /*按照文件对齐遍历写入*/
        memcpy(
            (LPVOID)((DWORD)lpFileBuffer + pSectionHeader->PointerToRawData),
            (LPVOID)((DWORD)lpImageBuffer + pSectionHeader->VirtualAddress),
            pSectionHeader->SizeOfRawData
        );

        /*指向下一个节表*/
        pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);
    }

    return lpFileBuffer;
}


LPVOID __stdcall mergeSection(LPVOID lpImageBuffer) {
    PIMAGE_DOS_HEADER pDos =
        (PIMAGE_DOS_HEADER)lpImageBuffer;
    PIMAGE_NT_HEADERS pNT =
        (PIMAGE_NT_HEADERS)((DWORD)lpImageBuffer + pDos->e_lfanew);
    PIMAGE_FILE_HEADER pFile =
        (PIMAGE_FILE_HEADER)((DWORD)pNT + 4);
    PIMAGE_OPTIONAL_HEADER pOption =
        (PIMAGE_OPTIONAL_HEADER)((DWORD)pFile + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER pFirstSection =
        (PIMAGE_SECTION_HEADER)((DWORD)pOption + pFile->SizeOfOptionalHeader);

    /*获取头内存对齐后的大小*/
    DWORD alignHeaderSize = PEAlign(pOption->SizeOfHeaders, pOption->SectionAlignment);
    /*获取最后一个节*/
    PIMAGE_SECTION_HEADER pLastSection =
        PIMAGE_SECTION_HEADER((DWORD)pFirstSection + ((pFile->NumberOfSections - 1) * IMAGE_SIZEOF_SECTION_HEADER));

    /*计算最后一个节的大小中更大的一个*/
    DWORD max = pLastSection->SizeOfRawData < pLastSection->Misc.VirtualSize ? pLastSection->Misc.VirtualSize : pLastSection->SizeOfRawData;

    /*计算整个节区的大小*/
    pFirstSection->SizeOfRawData = pFirstSection->Misc.VirtualSize = (DWORD)pLastSection->VirtualAddress + max - alignHeaderSize;

    pFirstSection->PointerToRawData = pFirstSection->VirtualAddress;
    /*遍历修改第一个节表的属性 包含所有节表的属性*/
    PIMAGE_SECTION_HEADER pSectionHeader = pFirstSection;
    for (int i = 0; i < pFile->NumberOfSections; i++) {
        pFirstSection->Characteristics |= pSectionHeader->Characteristics;
        pFirstSection = (PIMAGE_SECTION_HEADER)((DWORD)pFirstSection + 40);
    }

    /*将节表的数量置1*/
    pFile->NumberOfSections = 1;

    return lpImageBuffer;

}


DWORD __stdcall RVA2FOA(LPVOID lpBuffer, DWORD RVA) {
    PIMAGE_DOS_HEADER pDos =
        (PIMAGE_DOS_HEADER)lpBuffer;
    PIMAGE_NT_HEADERS pNT =
        (PIMAGE_NT_HEADERS)((DWORD)lpBuffer + pDos->e_lfanew);
    PIMAGE_FILE_HEADER pFile =
        (PIMAGE_FILE_HEADER)((DWORD)pNT + 4);
    PIMAGE_OPTIONAL_HEADER pOption =
        (PIMAGE_OPTIONAL_HEADER)((DWORD)pFile + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER pFirstSection =
        PIMAGE_SECTION_HEADER((DWORD)pOption + pFile->SizeOfOptionalHeader);

    DWORD FOA;

    /*对齐相同时不需转换*/
    if (pOption->FileAlignment == pOption->SectionAlignment) {
        return RVA;
    }

    /*判断RVA是否处于头中*/
    if (RVA < pOption->SizeOfHeaders || pOption->FileAlignment == pOption->SectionAlignment) {
        return RVA;
    }

    PIMAGE_SECTION_HEADER pSectionHeader = pFirstSection;

    /*判断RVA处于哪一个节区*/
    for (int i = 0; i < pFile->NumberOfSections; i++) {
        if (RVA >= pSectionHeader->VirtualAddress &&
            RVA < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize) {
            /*获取RVA和节区VA的偏移*/
            DWORD relSectionImageAdd = RVA - pSectionHeader->VirtualAddress;
            /*偏移加上节区文件地址得到FOA*/
            FOA = relSectionImageAdd + pSectionHeader->PointerToRawData;
            return FOA;
        }

        /*指向下一个节表*/
        pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);
    }

    return NULL;

}

DWORD __stdcall FOA2RVA(LPVOID lpBuffer, DWORD FOA) {
    PIMAGE_DOS_HEADER pDos =
        (PIMAGE_DOS_HEADER)lpBuffer;
    PIMAGE_NT_HEADERS pNT =
        (PIMAGE_NT_HEADERS)((DWORD)lpBuffer + pDos->e_lfanew);
    PIMAGE_FILE_HEADER pFile =
        (PIMAGE_FILE_HEADER)((DWORD)pNT + 4);
    PIMAGE_OPTIONAL_HEADER pOption =
        (PIMAGE_OPTIONAL_HEADER)((DWORD)pFile + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER pFirstSection =
        PIMAGE_SECTION_HEADER((DWORD)pOption + pFile->SizeOfOptionalHeader);

    DWORD RVA;

    if (pOption->FileAlignment == pOption->SectionAlignment) {
        return FOA;
    }

    /*判断FOA是否处于头中*/
    if (FOA < pOption->SizeOfHeaders || pOption->FileAlignment == pOption->SectionAlignment) {
        return FOA;
    }

    PIMAGE_SECTION_HEADER pSectionHeader = pFirstSection;

    for (int i = 0; pFile->NumberOfSections; i++) {
        if (FOA >= pSectionHeader->PointerToRawData &&
            FOA < pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData) {
            /*获取FOA和节区文件地址的偏移*/
            DWORD relSectionFileAdd = FOA - pSectionHeader->PointerToRawData;
            /*偏移加节区的VA得到RVA*/
            RVA = relSectionFileAdd + pSectionHeader->VirtualAddress;
            return RVA;
        }
        /*指向下一个节表*/
        pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);
    }

    return NULL;
}


DWORD __stdcall getFunctionAddressByName(LPVOID lpFileBuffer, LPCTSTR checkName) {
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

    PIMAGE_EXPORT_DIRECTORY pExportDir =
        (PIMAGE_EXPORT_DIRECTORY)(RVA2FOA(lpFileBuffer, pOption->DataDirectory[0].VirtualAddress) + (DWORD)lpFileBuffer);

    /*获取函数地址表、函数名称表、函数序号表的地址*/
    PDWORD lpAddOfFns = (PDWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfFunctions) + (DWORD)lpFileBuffer);
    PDWORD lpAddOfNames = (PDWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfNames) + (DWORD)lpFileBuffer);
    /*序号表的数据为2个字节*/
    PWORD lpAddOfOrdinals = (PWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfNameOrdinals) + (DWORD)lpFileBuffer);

    DWORD FnAddr = 0;

    for (int i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCTSTR fnName = (LPCTSTR)(RVA2FOA(lpFileBuffer, lpAddOfNames[i]) + (DWORD)lpFileBuffer);
        if (!strcmp(fnName, checkName)) {
            /*找到名字后通过下标继续索引序号表*/
            DWORD fnOrdinal = lpAddOfOrdinals[i];
            FnAddr = lpAddOfFns[fnOrdinal];
            return FnAddr;
        }
    }
    /*未找到，返回无效地址*/
    return 0;
}

DWORD __stdcall getFunctionAddressByOrdinal(LPVOID lpFileBuffer, DWORD checkOrdinal) {
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

    PIMAGE_EXPORT_DIRECTORY pExportDir =
        (PIMAGE_EXPORT_DIRECTORY)(RVA2FOA(lpFileBuffer, pOption->DataDirectory[0].VirtualAddress) + (DWORD)lpFileBuffer);

    /*获取函数地址表、函数名称表、函数序号表的地址*/
    PDWORD lpAddOfFns = (PDWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfFunctions) + (DWORD)lpFileBuffer);
    PDWORD lpAddOfNames = (PDWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfNames) + (DWORD)lpFileBuffer);
    /*序号表的数据为2个字节*/
    PWORD lpAddOfOrdinals = (PWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfNameOrdinals) + (DWORD)lpFileBuffer);

    /*导出序号 - Base得到序号表中的序号（地址表下标）*/
    DWORD ordinal = checkOrdinal - pExportDir->Base;

    /*序号不在地址表下标范围内*/
    if (ordinal >= pExportDir->NumberOfFunctions || ordinal < 0) {
        return 0;
    }

    DWORD fnAddr = lpAddOfFns[ordinal];

    return fnAddr;

}

/******************
新增节
*/

/*
新增节表并修改属性*/
LPVOID __stdcall addNewSection(LPVOID lpFileBuffer, DWORD size) {

    deleteDOSStub(lpFileBuffer);

    PIMAGE_DOS_HEADER pDOS = (PIMAGE_DOS_HEADER)lpFileBuffer;
    PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)((DWORD)pDOS + pDOS->e_lfanew);
    PIMAGE_FILE_HEADER pFile = (PIMAGE_FILE_HEADER)((DWORD)pNT + 4);
    PIMAGE_OPTIONAL_HEADER pOptional = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFile + 20);
    PIMAGE_SECTION_HEADER pSections = (PIMAGE_SECTION_HEADER)((DWORD)pOptional + pFile->SizeOfOptionalHeader);
    //定位到最后一个节头
    PIMAGE_SECTION_HEADER pLastSection = (PIMAGE_SECTION_HEADER)((DWORD)pSections + (pFile->NumberOfSections - 1) * 40);

    /*计算节表后的空白区*/
    DWORD dwSpace = ((DWORD)pDOS + pOptional->SizeOfHeaders) - ((DWORD)pLastSection + 40);
    if (dwSpace < 80) {
        return NULL;
    }

    /*新增节的地址*/
    PIMAGE_SECTION_HEADER pNewSection = PIMAGE_SECTION_HEADER((DWORD)pLastSection + 40);


    memcpy(pNewSection, pLastSection, 40);

    /*增加节的记数*/
    pFile->NumberOfSections = pFile->NumberOfSections + 1;

    /*修改内存和文件对齐后的大小*/
    pNewSection->SizeOfRawData = PEAlign(size, pOptional->FileAlignment);
    pNewSection->Misc.VirtualSize = PEAlign(size, pOptional->SectionAlignment);

    /*修改地址*/
    pNewSection->PointerToRawData =
        PEAlign((pLastSection->PointerToRawData + pLastSection->SizeOfRawData), pOptional->FileAlignment);
    pNewSection->VirtualAddress =
        PEAlign((pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize), pOptional->SectionAlignment);


    /*修改包含代码段和可执行属性*/
    pNewSection->Characteristics =
        (pNewSection->Characteristics | IMAGE_SCN_CNT_CODE) | IMAGE_SCN_MEM_EXECUTE;

    /*修改内存大小*/
    pOptional->SizeOfImage =
        PEAlign((pOptional->SizeOfImage + pNewSection->Misc.VirtualSize), pOptional->SectionAlignment);

    /*申请新内存存放修改后的PE文件*/
    LPVOID lpTemp = malloc(pNewSection->PointerToRawData + pNewSection->SizeOfRawData);
    memset(lpTemp, 0, pNewSection->PointerToRawData + pNewSection->SizeOfRawData);
    memcpy(lpTemp, lpFileBuffer, pNewSection->PointerToRawData);

    return lpTemp;
}


