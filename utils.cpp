#include"pch.h"
#include"utils.h"
/*���ܺ�����Ĩ��DOS Stub����������*/
DWORD deleteDOSStub(LPVOID lpFileBuffer) {
    PIMAGE_DOS_HEADER pDOS = (PIMAGE_DOS_HEADER)lpFileBuffer;
    PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)((DWORD)pDOS + pDOS->e_lfanew);
    PIMAGE_FILE_HEADER pFile = (PIMAGE_FILE_HEADER)((DWORD)pNT + 4);
    PIMAGE_OPTIONAL_HEADER pOptional = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFile + 20);
    PIMAGE_SECTION_HEADER pSections = (PIMAGE_SECTION_HEADER)((DWORD)pOptional + pFile->SizeOfOptionalHeader);
    //��λ�����һ����ͷ
    PIMAGE_SECTION_HEADER pLastSection = (PIMAGE_SECTION_HEADER)((DWORD)pSections + (pFile->NumberOfSections - 1) * 40);

    /*�Ѿ��޸Ĺ�ֱ�ӷ���*/
    if (pDOS->e_lfanew == 0x40) {
        return 1;
    }

    /*
    *****************************
    Ĩ��DOS Stub���������ڱ�
    */

    /*����ڱ��Ŀհ�����Ϊ�˱�����֤�����ж�*/
    DWORD dwSpace = ((DWORD)pDOS + pOptional->SizeOfHeaders) - ((DWORD)pLastSection + 40);

    /*�����ƶ����ݵĴ�С��PEͷ�����һ���ڱ�Ľ�β����*/
    DWORD dwMoveSize = ((DWORD)pSections + (pFile->NumberOfSections) * 40) - (DWORD)pNT;
    /*������ʱ�ڴ棬�����ƶ�����*/
    LPVOID lpTemp = malloc(dwMoveSize);
    memset(lpTemp, 0, dwMoveSize);

    /*��������*/
    memcpy(lpTemp, pNT, dwMoveSize);

    /*���ԭ��PEͷ*/
    memset(pNT, 0, dwMoveSize);

    /*��ԭ��DOS Stub��ͷ��д��PEͷ�����һ���ڱ����������
    IMAGE_DOS_HEADERռ64�ֽڣ�ƫ��64�ֽھ���DOS Stub*/
    memcpy((LPVOID)(DWORD(pDOS) + 64), lpTemp, dwMoveSize);

    /*����PEͷƫ�ƣ�DOSͷռ64�ֽڣ��������PEͷ��*/
    pDOS->e_lfanew = 0x40;

    free(lpTemp);

    return 0;

}