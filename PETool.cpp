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

    /*��ȡ�ļ���С*/
    fseek(fp, 0, SEEK_END);
    DWORD size = ftell(fp);

    LPVOID lpFileBuffer = malloc(size);

    if (!lpFileBuffer) {
        printf("�����ڴ�ʧ��..\n");
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
    //��λ�����һ����ͷ
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

    /*���������Ĵ�С�����ڴ�*/
    LPVOID lpImageBuffer = malloc(pOption->SizeOfImage);

    memset(lpImageBuffer, 0, pOption->SizeOfImage);

    /*д��ͷ��������Ҫ���룬�����VA��ʼд��*/
    memcpy(lpImageBuffer, lpFileBuffer, pOption->SizeOfHeaders);

    /*����д������������ڴ����д��*/
    PIMAGE_SECTION_HEADER pSectionHeader = pFirstSection;
    for (int i = 0; i < pFile->NumberOfSections; i++) {
        memcpy(
            (LPVOID)((DWORD)lpImageBuffer + pSectionHeader->VirtualAddress),
            (LPVOID)((DWORD)lpFileBuffer + pSectionHeader->PointerToRawData),
            pSectionHeader->Misc.VirtualSize
        );
        /*ָ����һ���ڱ�*/
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

    /*��ȡ���һ���ڱ�ĵ�ַ*/
    PIMAGE_SECTION_HEADER pLastSection =
        PIMAGE_SECTION_HEADER((DWORD)pFirstSection + ((pFile->NumberOfSections - 1) * IMAGE_SIZEOF_SECTION_HEADER));

    /*��ȡFileBuffer�Ĵ�С�������һ���ڵ��ļ�ƫ�Ƽ����ļ������С�ó�*/
    *pdwBufferSize = pLastSection->PointerToRawData + pLastSection->SizeOfRawData;

    /*�����ļ������С�����ڴ�*/
    LPVOID lpFileBuffer = malloc(*pdwBufferSize);

    memset(lpFileBuffer, 0, *pdwBufferSize);

    /*д��ͷ�������ļ�����*/
    memcpy(lpFileBuffer, lpImageBuffer, pOption->SizeOfHeaders);

    PIMAGE_SECTION_HEADER pSectionHeader = pFirstSection;
    for (int i = 0; i < pFile->NumberOfSections; i++) {
        /*�����ļ��������д��*/
        memcpy(
            (LPVOID)((DWORD)lpFileBuffer + pSectionHeader->PointerToRawData),
            (LPVOID)((DWORD)lpImageBuffer + pSectionHeader->VirtualAddress),
            pSectionHeader->SizeOfRawData
        );

        /*ָ����һ���ڱ�*/
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

    /*��ȡͷ�ڴ�����Ĵ�С*/
    DWORD alignHeaderSize = PEAlign(pOption->SizeOfHeaders, pOption->SectionAlignment);
    /*��ȡ���һ����*/
    PIMAGE_SECTION_HEADER pLastSection =
        PIMAGE_SECTION_HEADER((DWORD)pFirstSection + ((pFile->NumberOfSections - 1) * IMAGE_SIZEOF_SECTION_HEADER));

    /*�������һ���ڵĴ�С�и����һ��*/
    DWORD max = pLastSection->SizeOfRawData < pLastSection->Misc.VirtualSize ? pLastSection->Misc.VirtualSize : pLastSection->SizeOfRawData;

    /*�������������Ĵ�С*/
    pFirstSection->SizeOfRawData = pFirstSection->Misc.VirtualSize = (DWORD)pLastSection->VirtualAddress + max - alignHeaderSize;

    pFirstSection->PointerToRawData = pFirstSection->VirtualAddress;
    /*�����޸ĵ�һ���ڱ������ �������нڱ������*/
    PIMAGE_SECTION_HEADER pSectionHeader = pFirstSection;
    for (int i = 0; i < pFile->NumberOfSections; i++) {
        pFirstSection->Characteristics |= pSectionHeader->Characteristics;
        pFirstSection = (PIMAGE_SECTION_HEADER)((DWORD)pFirstSection + 40);
    }

    /*���ڱ��������1*/
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

    /*������ͬʱ����ת��*/
    if (pOption->FileAlignment == pOption->SectionAlignment) {
        return RVA;
    }

    /*�ж�RVA�Ƿ���ͷ��*/
    if (RVA < pOption->SizeOfHeaders || pOption->FileAlignment == pOption->SectionAlignment) {
        return RVA;
    }

    PIMAGE_SECTION_HEADER pSectionHeader = pFirstSection;

    /*�ж�RVA������һ������*/
    for (int i = 0; i < pFile->NumberOfSections; i++) {
        if (RVA >= pSectionHeader->VirtualAddress &&
            RVA < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize) {
            /*��ȡRVA�ͽ���VA��ƫ��*/
            DWORD relSectionImageAdd = RVA - pSectionHeader->VirtualAddress;
            /*ƫ�Ƽ��Ͻ����ļ���ַ�õ�FOA*/
            FOA = relSectionImageAdd + pSectionHeader->PointerToRawData;
            return FOA;
        }

        /*ָ����һ���ڱ�*/
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

    /*�ж�FOA�Ƿ���ͷ��*/
    if (FOA < pOption->SizeOfHeaders || pOption->FileAlignment == pOption->SectionAlignment) {
        return FOA;
    }

    PIMAGE_SECTION_HEADER pSectionHeader = pFirstSection;

    for (int i = 0; pFile->NumberOfSections; i++) {
        if (FOA >= pSectionHeader->PointerToRawData &&
            FOA < pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData) {
            /*��ȡFOA�ͽ����ļ���ַ��ƫ��*/
            DWORD relSectionFileAdd = FOA - pSectionHeader->PointerToRawData;
            /*ƫ�Ƽӽ�����VA�õ�RVA*/
            RVA = relSectionFileAdd + pSectionHeader->VirtualAddress;
            return RVA;
        }
        /*ָ����һ���ڱ�*/
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

    /*��ȡ������ַ���������Ʊ�������ű�ĵ�ַ*/
    PDWORD lpAddOfFns = (PDWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfFunctions) + (DWORD)lpFileBuffer);
    PDWORD lpAddOfNames = (PDWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfNames) + (DWORD)lpFileBuffer);
    /*��ű������Ϊ2���ֽ�*/
    PWORD lpAddOfOrdinals = (PWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfNameOrdinals) + (DWORD)lpFileBuffer);

    DWORD FnAddr = 0;

    for (int i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCTSTR fnName = (LPCTSTR)(RVA2FOA(lpFileBuffer, lpAddOfNames[i]) + (DWORD)lpFileBuffer);
        if (!strcmp(fnName, checkName)) {
            /*�ҵ����ֺ�ͨ���±����������ű�*/
            DWORD fnOrdinal = lpAddOfOrdinals[i];
            FnAddr = lpAddOfFns[fnOrdinal];
            return FnAddr;
        }
    }
    /*δ�ҵ���������Ч��ַ*/
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

    /*��ȡ������ַ���������Ʊ�������ű�ĵ�ַ*/
    PDWORD lpAddOfFns = (PDWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfFunctions) + (DWORD)lpFileBuffer);
    PDWORD lpAddOfNames = (PDWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfNames) + (DWORD)lpFileBuffer);
    /*��ű������Ϊ2���ֽ�*/
    PWORD lpAddOfOrdinals = (PWORD)(RVA2FOA(lpFileBuffer, (DWORD)pExportDir->AddressOfNameOrdinals) + (DWORD)lpFileBuffer);

    /*������� - Base�õ���ű��е���ţ���ַ���±꣩*/
    DWORD ordinal = checkOrdinal - pExportDir->Base;

    /*��Ų��ڵ�ַ���±귶Χ��*/
    if (ordinal >= pExportDir->NumberOfFunctions || ordinal < 0) {
        return 0;
    }

    DWORD fnAddr = lpAddOfFns[ordinal];

    return fnAddr;

}

/******************
������
*/

/*
�����ڱ��޸�����*/
LPVOID __stdcall addNewSection(LPVOID lpFileBuffer, DWORD size) {

    deleteDOSStub(lpFileBuffer);

    PIMAGE_DOS_HEADER pDOS = (PIMAGE_DOS_HEADER)lpFileBuffer;
    PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)((DWORD)pDOS + pDOS->e_lfanew);
    PIMAGE_FILE_HEADER pFile = (PIMAGE_FILE_HEADER)((DWORD)pNT + 4);
    PIMAGE_OPTIONAL_HEADER pOptional = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFile + 20);
    PIMAGE_SECTION_HEADER pSections = (PIMAGE_SECTION_HEADER)((DWORD)pOptional + pFile->SizeOfOptionalHeader);
    //��λ�����һ����ͷ
    PIMAGE_SECTION_HEADER pLastSection = (PIMAGE_SECTION_HEADER)((DWORD)pSections + (pFile->NumberOfSections - 1) * 40);

    /*����ڱ��Ŀհ���*/
    DWORD dwSpace = ((DWORD)pDOS + pOptional->SizeOfHeaders) - ((DWORD)pLastSection + 40);
    if (dwSpace < 80) {
        return NULL;
    }

    /*�����ڵĵ�ַ*/
    PIMAGE_SECTION_HEADER pNewSection = PIMAGE_SECTION_HEADER((DWORD)pLastSection + 40);


    memcpy(pNewSection, pLastSection, 40);

    /*���ӽڵļ���*/
    pFile->NumberOfSections = pFile->NumberOfSections + 1;

    /*�޸��ڴ���ļ������Ĵ�С*/
    pNewSection->SizeOfRawData = PEAlign(size, pOptional->FileAlignment);
    pNewSection->Misc.VirtualSize = PEAlign(size, pOptional->SectionAlignment);

    /*�޸ĵ�ַ*/
    pNewSection->PointerToRawData =
        PEAlign((pLastSection->PointerToRawData + pLastSection->SizeOfRawData), pOptional->FileAlignment);
    pNewSection->VirtualAddress =
        PEAlign((pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize), pOptional->SectionAlignment);


    /*�޸İ�������κͿ�ִ������*/
    pNewSection->Characteristics =
        (pNewSection->Characteristics | IMAGE_SCN_CNT_CODE) | IMAGE_SCN_MEM_EXECUTE;

    /*�޸��ڴ��С*/
    pOptional->SizeOfImage =
        PEAlign((pOptional->SizeOfImage + pNewSection->Misc.VirtualSize), pOptional->SectionAlignment);

    /*�������ڴ����޸ĺ��PE�ļ�*/
    LPVOID lpTemp = malloc(pNewSection->PointerToRawData + pNewSection->SizeOfRawData);
    memset(lpTemp, 0, pNewSection->PointerToRawData + pNewSection->SizeOfRawData);
    memcpy(lpTemp, lpFileBuffer, pNewSection->PointerToRawData);

    return lpTemp;
}


