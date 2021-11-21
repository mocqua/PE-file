#include<stdio.h>
#include "windows.h"

int main(int argc, char* argv[]) {
	const int max_path = 255;
	char filename[max_path] = { 0 };
	HANDLE file = NULL;
	DWORD filesize = NULL;
	DWORD bytesread = NULL;
	LPVOID filedata = NULL;
	PIMAGE_DOS_HEADER dosheader = {};
	PIMAGE_NT_HEADERS ntheaders = {};
	PIMAGE_SECTION_HEADER sectionheader = {};
	PIMAGE_SECTION_HEADER importsection = {};
	IMAGE_IMPORT_DESCRIPTOR* importdescriptor = {};	
	PIMAGE_THUNK_DATA thunkdata = {};
	DWORD thunk = NULL;
	DWORD rawoffset = NULL;
	strcpy_s(filename,"C:\\Users\\hmtp\\Downloads\\HackyBird.exe");
	printf("%s\n", filename);
	file = CreateFileA(filename, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("can not read file!");
		return 1;
	}
	filesize = GetFileSize(file, NULL);
	filedata = HeapAlloc(GetProcessHeap(), 0, filesize);
	ReadFile(file, filedata, filesize, &bytesread, NULL);

	dosheader = (PIMAGE_DOS_HEADER)filedata;
	printf("\nDOS HEADER\n");
	printf("e_magic \t 0x%x\n", dosheader->e_magic);
	printf("e_cblp \t 0x%x\n", dosheader->e_cblp);
	printf("e_cp \t 0x%x\n", dosheader->e_cp);
	printf("e_crlc \t 0x%x\n", dosheader->e_crlc);
	printf("e_cparhdr \t 0x%x\n", dosheader->e_cparhdr);
	printf("e_minalloc \t 0x%x\n", dosheader->e_minalloc);
	printf("e_maxalloc \t 0x%x\n", dosheader->e_maxalloc);
	printf("e_ss \t 0x%x\n", dosheader->e_ss); 
	printf("e_sp \t 0x%x\n", dosheader->e_sp);
	printf("e_csum \t 0x%x\n", dosheader->e_csum);
	printf("e_ip \t 0x%x\n", dosheader->e_ip);
	printf("e_cs \t 0x%x\n", dosheader->e_cs);
	printf("e_lfarlc \t 0x%x\n", dosheader->e_lfarlc);
	printf("e_ovno \t 0x%x\n", dosheader->e_ovno);
	printf("e_res \t 0x%x\n", dosheader->e_res);
	printf("e_oemid \t 0x%x\n", dosheader->e_oemid);
	printf("e_oeminfo \t 0x%x\n", dosheader->e_oeminfo);
	printf("e_res2 \t 0x%x\n", dosheader->e_res2);
	printf("e_lfanew \t 0x%x\n", dosheader->e_lfanew);

	printf("\nNT HEADERS\n");
	ntheaders = (PIMAGE_NT_HEADERS)((DWORD)filedata + dosheader->e_lfanew);
	printf("Signature \t 0x%x\n", ntheaders->Signature);
	printf("\t FILE HEADER\n");
	printf("\t Machine \t 0x%x\n", ntheaders->FileHeader.Machine);
	printf("\t NumberOfSections \t 0x%x\n", ntheaders->FileHeader.NumberOfSections);
	printf("\t TimeDateStamp \t 0x%x\n", ntheaders->FileHeader.TimeDateStamp);
	printf("\t PointerToSymbolTable \t 0x%x\n", ntheaders->FileHeader.PointerToSymbolTable);
	printf("\t NumberOfSymbols \t 0x%x\n", ntheaders->FileHeader.NumberOfSymbols);
	printf("\t SizeOfOptionalHeader \t 0x%x\n", ntheaders->FileHeader.SizeOfOptionalHeader);
	printf("\t Characteristics \t 0x%x\n", ntheaders->FileHeader.Characteristics);
	printf("\t OPTIONAL HEADER\n");
	printf("\t Magic \t 0x%x\n", ntheaders->OptionalHeader.Magic);
	printf("\t MajorLinkerVersion \t 0x%x\n", ntheaders->OptionalHeader.MajorLinkerVersion);
	printf("\t MinorLinkerVersion \t 0x%x\n", ntheaders->OptionalHeader.MinorLinkerVersion);
	printf("\t SizeOfCode \t 0x%x\n", ntheaders->OptionalHeader.SizeOfCode);
	printf("\t SizeOfInitializedData \t 0x%x\n", ntheaders->OptionalHeader.SizeOfInitializedData);
	printf("\t SizeOfUninitializedData \t 0x%x\n", ntheaders->OptionalHeader.SizeOfUninitializedData);
	printf("\t AddressOfEntryPoint \t 0x%x\n", ntheaders->OptionalHeader.AddressOfEntryPoint);
	printf("\t BaseOfCode \t 0x%x\n", ntheaders->OptionalHeader.BaseOfCode);
	//printf("\t BaseOfData \t 0x%x\n", ntheaders->OptionalHeader.BaseOfData);
	printf("\t ImageBase \t 0x%08x\n", ntheaders->OptionalHeader.ImageBase);
	printf("\t SectionAlignment \t 0x%x\n", ntheaders->OptionalHeader.SectionAlignment);
	printf("\t FileAlignment \t 0x%x\n", ntheaders->OptionalHeader.FileAlignment);
	printf("\t MajorOperatingSystemVersion \t 0x%x\n", ntheaders->OptionalHeader.MajorOperatingSystemVersion);
	printf("\t MinorOperatingSystemVersion \t 0x%x\n", ntheaders->OptionalHeader.MinorOperatingSystemVersion);
	printf("\t MajorImageVersion \t 0x%x\n", ntheaders->OptionalHeader.MajorImageVersion);
	printf("\t MinorImageVersion \t 0x%x\n", ntheaders->OptionalHeader.MinorImageVersion);
	printf("\t MajorSubsystemVersion \t 0x%x\n", ntheaders->OptionalHeader.MajorSubsystemVersion);
	printf("\t MinorSubsystemVersion \t 0x%x\n", ntheaders->OptionalHeader.MinorSubsystemVersion);
	printf("\t Win32VersionValue \t 0x%x\n", ntheaders->OptionalHeader.Win32VersionValue);
	printf("\t SizeOfImage \t 0x%x\n", ntheaders->OptionalHeader.SizeOfImage);
	printf("\t SizeOfHeaders \t 0x%x\n", ntheaders->OptionalHeader.SizeOfHeaders);
	printf("\t CheckSum \t 0x%x\n", ntheaders->OptionalHeader.CheckSum);
	printf("\t Subsystem \t 0x%x\n", ntheaders->OptionalHeader.Subsystem);
	printf("\t DllCharacteristics \t 0x%x\n", ntheaders->OptionalHeader.DllCharacteristics);
	printf("\t SizeOfStackReserve \t 0x%x\n", ntheaders->OptionalHeader.SizeOfStackReserve);
	printf("\t SizeOfStackCommit \t 0x%x\n", ntheaders->OptionalHeader.SizeOfStackCommit);
	printf("\t SizeOfHeapReserve \t 0x%x\n", ntheaders->OptionalHeader.SizeOfHeapReserve);
	printf("\t SizeOfHeapCommit \t 0x%x\n", ntheaders->OptionalHeader.SizeOfHeapCommit);
	printf("\t LoaderFlags \t 0x%x\n", ntheaders->OptionalHeader.LoaderFlags);
	printf("\t NumberOfRvaAndSizes \t 0x%x\n", ntheaders->OptionalHeader.NumberOfRvaAndSizes);
	printf("\n\t \t DATA DIRECTORIES\n");
	for (int i = 0; i < 16; i++)  {
		printf("\tData directories[%d]\n", i + 1);
		printf("\t \t 0x%x\n", ntheaders->OptionalHeader.DataDirectory[i].VirtualAddress);
		printf("\t \t 0x%x\n", ntheaders->OptionalHeader.DataDirectory[i].Size);
	}
	printf("\nSECTION HEADERS\n");	
	DWORD sectionoffset = (DWORD)ntheaders + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)ntheaders->FileHeader.SizeOfOptionalHeader;
	DWORD sectionsize = (DWORD)sizeof(IMAGE_SECTION_HEADER);
	DWORD importrva = ntheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD exportoffset = 0;	
	DWORD imageAddr = ntheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	sectionheader = (PIMAGE_SECTION_HEADER)sectionoffset;
	if (imageAddr < sectionheader->PointerToRawData) {
		exportoffset = imageAddr;
	}
	for (int i = 0; i < ntheaders->FileHeader.NumberOfSections; i++) {
		sectionheader = (PIMAGE_SECTION_HEADER)sectionoffset;
		printf("%s\n", sectionheader->Name);
		printf("VirtualSize 0x%x\n", sectionheader->Misc.VirtualSize);
		printf("VirtualAddress 0x%x\n", sectionheader->VirtualAddress);
		printf("SizeOfRawData 0x%x\n", sectionheader->SizeOfRawData);
		printf("PointerToRawData 0x%x\n", sectionheader->PointerToRawData);
		printf("PointerToRelocations 0x%x\n", sectionheader->PointerToRelocations);
		printf("PointerToLinenumbers 0x%x\n", sectionheader->PointerToLinenumbers);
		printf("NumberOfRelocations 0x%x\n", sectionheader->NumberOfRelocations);
		printf("NumberOfLinenumbers 0x%x\n", sectionheader->NumberOfLinenumbers);
		printf("Characteristics 0x%x\n", sectionheader->Characteristics);
		if (importrva >= sectionheader->VirtualAddress && importrva < sectionheader->VirtualAddress + sectionheader->Misc.VirtualSize) {
			importsection = sectionheader;
		}
		if (imageAddr >= sectionheader->VirtualAddress && imageAddr < sectionheader->VirtualAddress + sectionheader->Misc.VirtualSize) {
			exportoffset = imageAddr - sectionheader->VirtualAddress + sectionheader->PointerToRawData;
		}
		sectionoffset += sectionsize;
	}
	
	printf("\nEXPORT DIRECTORY\n");
	if (ntheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0) {
		IMAGE_EXPORT_DIRECTORY* exportTb = (IMAGE_EXPORT_DIRECTORY*)((DWORD)filedata + exportoffset);
		printf("\tCharacteristics: %08X\n", exportTb->Characteristics);
		printf("\tTimeDateStamp: %08X\n", exportTb->TimeDateStamp);
		printf("\tMajorVersion: %04X\n", exportTb->MajorVersion);
		printf("\tMinorVersion : %04X\n", exportTb->MinorVersion);
		printf("\tName: %08X\n", exportTb->Name);
		printf("\tBase: %08X\n", exportTb->Base);
		printf("\tNumberOfFunctions: %08X\n", exportTb->NumberOfFunctions);
		printf("\tNumberOfNames: % 08X \n", exportTb->NumberOfNames);
		printf("\tAddressOfFunctions: % 08X \n", exportTb->AddressOfFunctions);
		printf("\tAddressOfNames: % 08X \n", exportTb->AddressOfNames);
		printf("\tAddressOfNameOrdinals: % 08X \n", exportTb->AddressOfNameOrdinals);

		sectionoffset = (DWORD)ntheaders + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)ntheaders->FileHeader.SizeOfOptionalHeader;
		sectionsize = (DWORD)sizeof(IMAGE_SECTION_HEADER);
		DWORD AddressOfFunc_offset = 0;
		DWORD AddressOfFunc = exportTb->AddressOfFunctions;
		DWORD AddressOfName_offset = 0;
		DWORD AddressOfName = exportTb->AddressOfNames;
		DWORD AddressOfNameOrd_offset = 0;
		DWORD AddressOfNameOrd = exportTb->AddressOfNameOrdinals;
		DWORD Name_offset = 0;
		DWORD Name = exportTb->Name;

		sectionheader = (PIMAGE_SECTION_HEADER)sectionoffset;
		if (imageAddr < sectionheader->PointerToRawData) {
			exportoffset = imageAddr;
		}
		for (int i = 0; i < ntheaders->FileHeader.NumberOfSections; i++) {
			sectionheader = (PIMAGE_SECTION_HEADER)sectionoffset;
			if (AddressOfFunc >= sectionheader->VirtualAddress && AddressOfFunc < sectionheader->VirtualAddress + sectionheader->Misc.VirtualSize) {
				AddressOfFunc_offset = AddressOfFunc - sectionheader->VirtualAddress + sectionheader->PointerToRawData;
			}
			if (AddressOfName >= sectionheader->VirtualAddress && AddressOfName < sectionheader->VirtualAddress + sectionheader->Misc.VirtualSize) {
				AddressOfName_offset = AddressOfName - sectionheader->VirtualAddress + sectionheader->PointerToRawData;				
			}
			if (AddressOfNameOrd >= sectionheader->VirtualAddress && AddressOfNameOrd < sectionheader->VirtualAddress + sectionheader->Misc.VirtualSize) {
				AddressOfNameOrd_offset = AddressOfNameOrd - sectionheader->VirtualAddress + sectionheader->PointerToRawData;
			}
			if (Name >= sectionheader->VirtualAddress && Name < sectionheader->VirtualAddress + sectionheader->Misc.VirtualSize) {
				Name_offset = Name - sectionheader->VirtualAddress + sectionheader->PointerToRawData;
			}
			sectionoffset += sectionsize;
		}

		DWORD* addrFunc = (DWORD*)((DWORD)filedata + AddressOfFunc_offset);
		DWORD* addrName = (DWORD*)((DWORD)filedata + AddressOfName_offset);
		WORD* addrOrdi = (WORD*)((DWORD)filedata + AddressOfNameOrd_offset);	
		DWORD namesize = 0;		
		namesize += strlen((char*)filedata + Name_offset + namesize)+1;
		DWORD i, j;
		printf("\n\tOrdinal\tFuntion RVA\tName RVA\tName\n");
		for (i = 0; i < exportTb->NumberOfFunctions; i++) {
			if (addrFunc[i] == 0)
			{
				continue;

			}
			for (j = 0; j < exportTb->NumberOfNames; j++) {
				if (addrOrdi[j] == i) {										
					printf("\t%04X\t%08X\t%08X\t%s\n", i + exportTb->Base, addrFunc[i], addrName[j], (DWORD)filedata + Name_offset + namesize);
					namesize += strlen((char*)filedata + Name_offset + namesize) + 1;
					break;

				}
				if (j != exportTb->NumberOfNames) {
					continue;
				}
				else {
					printf("\t%04X\t%08X\t%s\t%s\n ", i + exportTb->Base, addrFunc[i], "--------", "--------");

				}
			}
		}
	}
	else {
		printf("NO EXPORT!\n");
	}

	
	printf("\nIMPORT DIRECTORY\n");
	rawoffset = (DWORD)filedata + importsection->PointerToRawData;
	importdescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(rawoffset + (ntheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importsection->VirtualAddress));
	while (importdescriptor->Name != 0) {
		printf("%s %x %x %x\n", rawoffset + (importdescriptor->Name - importsection->VirtualAddress), importdescriptor->Name, importsection->VirtualAddress, importdescriptor-(DWORD)filedata);
		thunk = importdescriptor->OriginalFirstThunk == 0 ? importdescriptor->FirstThunk : importdescriptor->OriginalFirstThunk;
		thunkdata = (PIMAGE_THUNK_DATA)(rawoffset + (thunk - importsection->VirtualAddress));
		while (thunkdata->u1.AddressOfData!=0)
		{
			if (thunkdata->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				printf("\t%x Ordinal: %x\n", thunkdata->u1.Ordinal, (WORD)thunkdata->u1.Function);
			}
			else {
				printf("\t%x %s\n", thunkdata->u1.Ordinal, (rawoffset + (thunkdata->u1.AddressOfData - importsection->VirtualAddress + 2)));
			}
			thunkdata++;
		}		
		importdescriptor++;
	}
	
	return 0;
}
