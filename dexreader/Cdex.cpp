#include "stdafx.h"
#include "Cdex.h"
#include "DexClass.h"
#include "InstrUtils.h"
#include "OpCodeNames.h"
#include "DexProto.h"
#include "DexCatch.h"


Cdex::Cdex(TCHAR * lpcTheFile)
{
  //DWORD dwFileMapSize;  // size of the file mapping
  //DWORD dwMapViewSize;  // the size of the view
  //DWORD dwFileMapStart; // where to start the file map view
   
                        // memory-mapped region


  // Create the test file. Open it "Create Always" to overwrite any
  // existing file. The data is re-created below
	hFile = CreateFile(lpcTheFile, 
                     GENERIC_READ | GENERIC_WRITE,
                     0, 
                     NULL,
                     OPEN_EXISTING, 
                     FILE_ATTRIBUTE_NORMAL, 
                     NULL);

  if (hFile == INVALID_HANDLE_VALUE)
  {
    printf("hFile is NULL\n");
    printf("Target file is %s\n", 
           lpcTheFile);
    return ;
  }
  dexsize = GetFileSize(hFile, NULL);
  hMapFile = CreateFileMapping( hFile,         // current file handle
                NULL,           // default security
                PAGE_READWRITE, // read/write permission
                0,              // size of mapping object, high
                dexsize,  // size of mapping object, low
                NULL);          // name of mapping object

  if (hMapFile == NULL) 
  {
    printf("hMapFile is NULL: last error: %d\n", GetLastError() );
    return;
  }

  // Map the view and test the results.

  lpMapAddress = MapViewOfFile(hMapFile,            // handle to 
                                                    // mapping object
                               FILE_MAP_ALL_ACCESS, // read/write 
                               0,                   // high-order 32 
                                                    // bits of file 
                                                    // offset
                               0,      // low-order 32
                                                    // bits of file 
                                                    // offset
                               dexsize);      // number of bytes
                                                    // to map
  if (lpMapAddress == NULL) 
  {
    printf("lpMapAddress is NULL: last error: %d\n", GetLastError());
    return ;
  }
  pDexFile = new DexFile;
  initDexStructure();
}
void Cdex::initDexStructure()
{
		u1* pData=(u1*)lpMapAddress;
		const u1* magic;
		if (memcmp(pData, DEX_MAGIC, 4) == 0) {
			magic = pData;
			if (memcmp(magic+4, DEX_MAGIC_VERS_API_13, 4) != 0) {
				printf("bad opt version (0x%02x %02x %02x %02x)",magic[4], magic[5], magic[6], magic[7]);
				exit(-1);
			}
		pDexFile->pOptHeader	=	(DexOptHeader*)pData;
		//pData=pData+sizeof(DexOptHeader);
		pDexFile->baseAddr		=	pData;
		pDexFile->pHeader		=	(DexHeader*)pData;
		pDexFile->pStringIds	=	(DexStringId*) (pData+pDexFile->pHeader->stringIdsOff);
		pDexFile->pTypeIds		=	(DexTypeId*)   (pData+pDexFile->pHeader->typeIdsOff);
		pDexFile->pFieldIds		=	(DexFieldId*)  (pData+pDexFile->pHeader->fieldIdsOff);
		pDexFile->pMethodIds	=	(DexMethodId*) (pData+pDexFile->pHeader->methodIdsOff);
		pDexFile->pProtoIds		=	(DexProtoId*)  (pData+pDexFile->pHeader->protoIdsOff);
		pDexFile->pClassDefs	=	(DexClassDef*) (pData+pDexFile->pHeader->classDefsOff);
		pDexFile->pLinkData		=	(DexLink*)	   (pData+pDexFile->pHeader->dataOff);

		gInstrWidth = dexCreateInstrWidthTable();
		gInstrFormat = dexCreateInstrFormatTable();
		
		}else
		{
			 printf("please input dex file.\n");
			 exit(-1);
		}
  	
}
void Cdex::showStringIds()
{
	//u1* pData=(u1*)();
	printf("\nThe size of stringIds is :%d\n",pDexFile->pHeader->stringIdsSize);
	printf("Listed below :\n");
	for(u4 j=0;j< pDexFile->pHeader->stringIdsSize;j++)
	{
		printf("%x\n",(DexStringId*)(pDexFile->pStringIds+j)->stringDataOff);	
		printf("%s\n",dexStringById(pDexFile,j));
	}
}
u1* Cdex::getStrByStringId(u1* pData,u4 i)
{
	u1* ptr=(u1*)(pData+(int)(DexStringId*)(pDexFile->pStringIds+i)->stringDataOff)+1;//第一个字节是计算字符串的长度，所以偏移一个字节
	return ptr;
}
void Cdex::showTypeIds()
{
	const DexFile* pData=(const DexFile*)(lpMapAddress);
	printf("The size of TypeId is :%d\n",pDexFile->pHeader->typeIdsSize);
	printf("Listed below :\n");
	for(int j=0;j< pDexFile->pHeader->typeIdsSize;j++)
	{
		//printf("%s\n",getStrByTypeId(pData,j));
		printf("%s\n",dexStringById(pData,j));
	}
}
u1* Cdex::getStrByTypeId(u1* pData,u4 i)
{
	u4 n=(u4)((DexTypeId*)(pDexFile->pTypeIds+i)->descriptorIdx);
	return getStrByStringId(pData,n);
}
void Cdex::showProtoIds()
{
	u1* pData=(u1*)(lpMapAddress);
	printf("The size of ProtoId is :%d\n",pDexFile->pHeader->protoIdsSize);
	printf("Listed below :\n");
	for(int j=0;j< pDexFile->pHeader->protoIdsSize;j++)
	{
		printf(" DexProtoId[%d]\n",j);
		u4 n=(u4)((DexProtoId*)(pDexFile->pProtoIds+j)->shortyIdx);
		u4 m=(u4)((DexProtoId*)(pDexFile->pProtoIds+j)->returnTypeIdx);
		u4 p=(u4)((DexProtoId*)(pDexFile->pProtoIds+j)->parametersOff);
		printf("	DexProtoId[%d]->shortyIdx	= %d",j,n);
		printf(" #%s\n",dexStringById(pDexFile,n));
		printf("	DexProtoId[%d]->returnTypeIdx	= %d",j,m);
		printf(" #%s\n",dexStringById(pDexFile,m));
		printf("	DexProtoId[%d]->parametersOff	= %x\n",j,p);
		if(p!=0){
			//DexTypeList
			DexTypeList* pDexTypeList=(DexTypeList*)(pData+p);
			printf("	 pDexTypeList->size	=%x\n",pDexTypeList->size);
			for(int q=0;q < pDexTypeList->size;q++){
				int k=pDexTypeList->list[q].typeIdx;
				printf("	 pDexTypeList->list[%d].typeIdx	=%d",q,k);
				//u4 u=((DexTypeId*)(pDexFile->pTypeIds+k))->descriptorIdx;
				printf("  #%s\n",dexStringByTypeIdx(pDexFile,k));
			}
		}
	}
}
void Cdex::showMethodIds()
{
	u1* pData=(u1*)(lpMapAddress);
	printf("The size of MethodId is :%d\n",pDexFile->pHeader->methodIdsSize);
	printf("Listed below :\n");
	for(int j=0;j < pDexFile->pHeader->methodIdsSize;j++)
	{
		printf("DexMethodId[%d]\n",j);
		
		u2 n=(u2)(DexMethodId*)(pDexFile->pMethodIds+j)->classIdx;  
		u2 m=(u2)(DexMethodId*)(pDexFile->pMethodIds+j)->protoIdx;	
		u4 p=(u4)(DexMethodId*)(pDexFile->pMethodIds+j)->nameIdx;	

		u4 u=(u4)(DexTypeId*)(pDexFile->pTypeIds+n)->descriptorIdx;
			u4 v=(u4)(DexProtoId*)(pDexFile->pProtoIds+m)->parametersOff;
			u4 w=(u4)(DexProtoId*)(pDexFile->pProtoIds+m)->returnTypeIdx;
			u4 x=(u4)(DexProtoId*)(pDexFile->pProtoIds+m)->shortyIdx;
	
			printf("DexMethodId[%d]->classIdx	=%d",j,n);
			printf("  #%s\n",dexStringByTypeIdx(pDexFile,n));
			
			printf("DexMethodId[%d]->protoIdx	=%d\n",j,m);

			printf("DexMethodId[%d]->protoIdx->parametersOff	=%d\n",j,v);
			
			if(v!=0){
			//DexTypeList
			DexTypeList* pDexTypeList=(DexTypeList*)(pData+v);
			printf("	 pDexTypeList->size	=%x\n",pDexTypeList->size);
				for(int q=0;q < pDexTypeList->size;q++){
					u2 k=pDexTypeList->list[q].typeIdx;
					printf("	 pDexTypeList->list[%d].typeIdx	=%d",q,k);
					printf("  #%s\n",dexStringByTypeIdx(pDexFile,k));
				}
			}

			printf("DexMethodId[%d]->protoIdx->returnTypeIdx	=%d",j,w);
			printf("  #%s\n",dexStringByTypeIdx(pDexFile,w));

			printf("DexMethodId[%d]->protoIdx->shortyIdx	=%d",j,x);
			printf("  #%s\n",dexStringById(pDexFile,x));
			
			printf("DexMethodId[%d]->nameIdx	=%d",j,p);
			printf("  #%s\n",dexStringById(pDexFile,p));		
	}
}
void Cdex::showFiledIds()
{
	u1* pData=(u1*)(lpMapAddress);
	printf("The size of FieldId is :%d\n",pDexFile->pHeader->fieldIdsSize);
	printf("Listed below :\n");
	for(int j=0;j < pDexFile->pHeader->fieldIdsSize;j++)
	{
		printf(" DexFieldId[%d]\n",j);
		
		u2 n=(u2)(DexFieldId*)(pDexFile->pFieldIds+j)->classIdx;	
		u2 m=(u2)(DexFieldId*)(pDexFile->pFieldIds+j)->typeIdx;
		u4 p=(u4)(DexFieldId*)(pDexFile->pFieldIds+j)->nameIdx;			

		printf(" DexFieldId[%d]->classIdx	=%d",j,n);
		printf("  #%s\n",dexStringByTypeIdx(pDexFile,n));
		printf(" DexFieldId[%d]->typeIdx	=%d",j,m);
		printf("  #%s\n",dexStringByTypeIdx(pDexFile,m));
		printf(" DexFieldId[%d]->nameIdx	=%d",j,p);	
		printf("  #%s\n",dexStringById(pDexFile,p));
		
	}
}
void Cdex::showClassDefs()
{
	u1* pData=(u1*)(lpMapAddress);
	printf("The size of ClassDef is :%d\n",pDexFile->pHeader->classDefsSize);
	printf("Listed below :\n");
	for(int j=0;j < pDexFile->pHeader->classDefsSize;j++)
	{
		printf(" DexClassDef[%d]\n",j);
		u4 n=(u4)(DexClassDef*)(pDexFile->pClassDefs+j)->classIdx;		 /* index into typeIds for this class */
		u4 m=(u4)(DexClassDef*)(pDexFile->pClassDefs+j)->accessFlags;
		u4 p=(u4)(DexClassDef*)(pDexFile->pClassDefs+j)->superclassIdx;  /* index into typeIds for superclass */
		u4 q=(u4)(DexClassDef*)(pDexFile->pClassDefs+j)->interfacesOff;	 /* file offset to DexTypeList */
		u4 u=(u4)(DexClassDef*)(pDexFile->pClassDefs+j)->sourceFileIdx;	 /* index into stringIds for source file name */
		u4 v=(u4)(DexClassDef*)(pDexFile->pClassDefs+j)->annotationsOff; /* file offset to annotations_directory_item */
		u4 w=(u4)(DexClassDef*)(pDexFile->pClassDefs+j)->classDataOff;	 /* file offset to class_data_item */		
		u4 x=(u4)(DexClassDef*)(pDexFile->pClassDefs+j)->staticValuesOff;/* file offset to DexEncodedArray */
		
		printf("  DexClassDef[%d]->classIdx	=%d",j,n);
		printf("  #%s\n",dexStringByTypeIdx(pDexFile,n));

		printf("  DexClassDef[%d]->superclassIdx	=%d",j,p);
		printf("  #%s\n",dexStringByTypeIdx(pDexFile,p));
		
		//display Interfaces
		showInterfaces(j,q,pData);
		
		printf("  DexClassDef[%d]->sourceFileIdx	=%d",j,u);
		printf("  #%s\n",dexStringById(pDexFile,u));

		//display annotations
		//showAnnotations(j,v,pData);	
		dumpClass(pDexFile,j);
	}

}

void Cdex::showInterfaces(int j,u4 q,u1* pData)
{
	printf("  DexClassDef[%d]->interfacesOff	=%d\n",j,q);
		if(q!=0)
		{
			DexTypeList* pDexTypeList=(DexTypeList*)(char*)(pData+q);
			u4 q1=pDexTypeList->size;
			for(int i=0;i< q1;i++)
			{
				u2 q2=pDexTypeList->list[i].typeIdx;
				printf("	 pDexTypeList->list[%d].typeIdx	=%d",i,q2);
				printf("  #%s\n",dexStringByTypeIdx(pDexFile,q2));
			}
		}

}
void Cdex::showAnnotations(int j,u4 v,u1 * pData)
{
		printf("  DexClassDef[%d]->annotationsOff	=%d\n",j,v);
		if(v!=0)
		{
			DexAnnotationsDirectoryItem* pDexAnnotationsDirectoryItem=(DexAnnotationsDirectoryItem*)(char*)(pData+v);
			//printf("find it.!!!\n");
			u4 classAnnotationsOff =	pDexAnnotationsDirectoryItem->classAnnotationsOff;
			u4 fieldsSize		   =	pDexAnnotationsDirectoryItem->fieldsSize;
			u4 methodsSize		   =	pDexAnnotationsDirectoryItem->methodsSize;
			u4 parametersSize	   =	pDexAnnotationsDirectoryItem->parametersSize;
			if(classAnnotationsOff!=0)
			{
				printf("find it classAnnotationsOff");//i haven't come accross this kind of sample.
			}
			if(fieldsSize!=0)
			{
				for(int i=0;i < fieldsSize;i++)
				{
					DexFieldAnnotationsItem* pDexFieldAnnotationsItem = (DexFieldAnnotationsItem*)((char*)(pDexAnnotationsDirectoryItem+sizeof(u4)*4)+i);
					pDexFieldAnnotationsItem->annotationsOff;
					u4 fieldIdx= pDexFieldAnnotationsItem->fieldIdx;
					
					u2 classIdx=(u2)(DexFieldId*)(pDexFile->pFieldIds+fieldIdx)->classIdx;
					u4 nameIdx=(u4)(DexFieldId*)(pDexFile->pFieldIds+fieldIdx)->nameIdx;
					u2 typeIdx=(u2)(DexFieldId*)(pDexFile->pFieldIds+fieldIdx)->typeIdx;					
					
					printf("  #%s\n",dexStringByTypeIdx(pDexFile,classIdx));
					printf("  #%s\n",dexStringByTypeIdx(pDexFile,nameIdx));
					printf("  #%s\n",dexStringById(pDexFile,typeIdx));
				}
			}
			if(methodsSize!=0)
			{

			}
			if(parametersSize!=0)
			{

			}
		}	
}

void Cdex::dumpClass(DexFile *pDexFile,int idx)
{
	const DexClassDef* pClassDef;
    DexClassData* pClassData;
    const u1* pEncodedData;
    const char* fileName;
    int i;
	pClassDef = dexGetClassDef(pDexFile, idx);
	pEncodedData = dexGetClassData(pDexFile, pClassDef);
	pClassData = dexReadAndVerifyClassData(&pEncodedData, NULL);
	if (pClassData == NULL) {
        fprintf(stderr, "Trouble reading class data\n");
        return;
    }

    if (pClassDef->sourceFileIdx == 0xffffffff) {
        fileName = NULL;
    } else {
        fileName = dexStringById(pDexFile, pClassDef->sourceFileIdx);
    }

    /*
     * TODO: Each class def points at a sourceFile, so maybe that
     * should be printed out. However, this needs to be coordinated
     * with the tools that parse this output.
     */

	printf("   The directMethodsSize is:%d\n",pClassData->header.directMethodsSize);
	for (i = 0; i < (int) pClassData->header.directMethodsSize; i++) {
        dumpMethod(pDexFile, fileName, &pClassData->directMethods[i], i);
    }
	printf("   The virtualMethodsSize is:%d\n",pClassData->header.virtualMethodsSize);
    for (i = 0; i < (int) pClassData->header.virtualMethodsSize; i++) {
        dumpMethod(pDexFile, fileName, &pClassData->virtualMethods[i], i);
    }

    free(pClassData);
}
void Cdex::dumpMethod(DexFile* pDexFile, const char* fileName,const DexMethod* pDexMethod, int i)
{
	const DexMethodId* pMethodId;
    const DexCode* pCode;
    const char* classDescriptor;
    const char* methodName;
    int firstLine;
	/* abstract and native methods don't get listed */
    if (pDexMethod->codeOff == 0)
        return;

    pMethodId = dexGetMethodId(pDexFile, pDexMethod->methodIdx);
    methodName = dexStringById(pDexFile, pMethodId->nameIdx);

    classDescriptor = dexStringByTypeIdx(pDexFile, pMethodId->classIdx);

    pCode = dexGetCode(pDexFile, pDexMethod);

	dumpCode(pDexFile,pDexMethod);

	/*for(int j=0;j< pCode->insnsSize;j++)
	{
		printf("%02x",(pCode->insns[j] & 0xFFFF00FF));
		printf("%02x ",(pCode->insns[j] & 0xFFFFFF00) >> 8);
	}
	printf("# ins byte code\n");*/
	
	/* abstract and native methods don't get listed */
    
}
void Cdex::dumpCode(DexFile* pDexFile, const DexMethod* pDexMethod)
{
	const DexCode* pCode = dexGetCode(pDexFile, pDexMethod);

    printf("      registers     : %d\n", pCode->registersSize);
    printf("      ins           : %d\n", pCode->insSize);
    printf("      outs          : %d\n", pCode->outsSize);
    printf("      insns size    : %d 16-bit code units\n", pCode->insnsSize);

    //if (gOptions.disassemble)
    dumpBytecodes(pDexFile, pDexMethod);
	dumpCatches(pDexFile, pCode);
    /* both of these are encoded in debug info */
    dumpPositions(pDexFile, pCode, pDexMethod);
    dumpLocals(pDexFile, pCode, pDexMethod);
}
void Cdex::dumpBytecodes(DexFile* pDexFile, const DexMethod* pDexMethod)
{
	const DexCode* pCode = dexGetCode(pDexFile, pDexMethod);
    const u2* insns;
    int insnIdx;
    FieldMethodInfo methInfo;
    int startAddr;
    char* className = NULL;

    //assert(pCode->insnsSize > 0);
    insns = pCode->insns;

    getMethodInfo(pDexFile, pDexMethod->methodIdx, &methInfo);
    startAddr = ((u1*)pCode - pDexFile->baseAddr);
    className = descriptorToDot(methInfo.classDescriptor);

    printf("%06x:                                        |[%06x] %s.%s:%s\n",
        startAddr, startAddr,
        className, methInfo.name, methInfo.signature);

    insnIdx = 0;
    while (insnIdx < (int) pCode->insnsSize) {
        int insnWidth;
        OpCode opCode;
        DecodedInstruction decInsn;
        u2 instr;

        instr = get2LE((const u1*)insns);
        if (instr == kPackedSwitchSignature) {
            insnWidth = 4 + get2LE((const u1*)(insns+1)) * 2;
        } else if (instr == kSparseSwitchSignature) {
            insnWidth = 2 + get2LE((const u1*)(insns+1)) * 4;
        } else if (instr == kArrayDataSignature) {
            int width = get2LE((const u1*)(insns+1));
            int size = get2LE((const u1*)(insns+2)) | 
                       (get2LE((const u1*)(insns+3))<<16);
            // The plus 1 is to round up for odd size and width 
            insnWidth = 4 + ((size * width) + 1) / 2;
        } else {
            opCode = OpCode(instr & 0xff);
            insnWidth = dexGetInstrWidthAbs(gInstrWidth, opCode);
            if (insnWidth == 0) {
                fprintf(stderr,
                    "GLITCH: zero-width instruction at idx=0x%04x\n", insnIdx);
                break;
            }
        }

        dexDecodeInstruction(gInstrFormat, insns, &decInsn);
        dumpInstruction(pDexFile, pCode, insnIdx, insnWidth, &decInsn);

        insns += insnWidth;
        insnIdx += insnWidth;
    }

    free(className);	
}
void Cdex::dumpCatches(DexFile* pDexFile, const DexCode* pCode)
{
	u4 triesSize = pCode->triesSize;

    if (triesSize == 0) {
        printf("      catches       : (none)\n");
        return;
    } 

    printf("      catches       : %d\n", triesSize);

    const DexTry* pTries = dexGetTries(pCode);
    u4 i;

    for (i = 0; i < triesSize; i++) {
        const DexTry* pTry = &pTries[i];
        u4 start = pTry->startAddr;
        u4 end = start + pTry->insnCount;
        DexCatchIterator iterator;
        
        printf("        0x%04x - 0x%04x\n", start, end);

        dexCatchIteratorInit(&iterator, pCode, pTry->handlerOff);

        for (;;) {
            DexCatchHandler* handler = dexCatchIteratorNext(&iterator);
            const char* descriptor;
            
            if (handler == NULL) {
                break;
            }
            
            descriptor = (handler->typeIdx == kDexNoIndex) ? "<any>" : 
                dexStringByTypeIdx(pDexFile, handler->typeIdx);
            
            printf("          %s -> 0x%04x\n", descriptor,
                    handler->address);
        }
    }
}
void Cdex::dumpPositions(DexFile* pDexFile, const DexCode* pCode,const DexMethod *pDexMethod)
{
	printf("      positions     : \n");
    const DexMethodId *pMethodId 
            = dexGetMethodId(pDexFile, pDexMethod->methodIdx);
    const char *classDescriptor
            = dexStringByTypeIdx(pDexFile, pMethodId->classIdx);

    dexDecodeDebugInfo(pDexFile, pCode, classDescriptor, pMethodId->protoIdx,
            pDexMethod->accessFlags, dumpPositionsCb, NULL, NULL);
}
void Cdex::dumpLocals(DexFile* pDexFile, const DexCode* pCode,const DexMethod *pDexMethod)
{
	printf("      locals        : \n");

    const DexMethodId *pMethodId 
            = dexGetMethodId(pDexFile, pDexMethod->methodIdx);
    const char *classDescriptor 
            = dexStringByTypeIdx(pDexFile, pMethodId->classIdx);

    dexDecodeDebugInfo(pDexFile, pCode, classDescriptor, pMethodId->protoIdx,pDexMethod->accessFlags, NULL, dumpLocalsCb, NULL);
}
void Cdex::dumpLocalsCb(void *cnxt, u2 reg, u4 startAddress,u4 endAddress, const char *name, const char *descriptor,const char *signature)
{
	printf("        0x%04x - 0x%04x reg=%d %s %s %s\n",startAddress, endAddress, reg, name, descriptor,signature);
}
bool Cdex::getMethodInfo(DexFile* pDexFile, u4 methodIdx, FieldMethodInfo* pMethInfo)
{
	const DexMethodId* pMethodId;

    if (methodIdx >= pDexFile->pHeader->methodIdsSize)
        return false;

    pMethodId = dexGetMethodId(pDexFile, methodIdx);
    pMethInfo->name = dexStringById(pDexFile, pMethodId->nameIdx);
    pMethInfo->signature = dexCopyDescriptorFromMethodId(pDexFile, pMethodId);

    pMethInfo->classDescriptor = 
            dexStringByTypeIdx(pDexFile, pMethodId->classIdx);
    return true;
}

char* Cdex::descriptorToDot(const char* str)
{
	int targetLen = strlen(str);
    int offset = 0;
    int arrayDepth = 0;
    char* newStr;

    /* strip leading [s; will be added to end */
    while (targetLen > 1 && str[offset] == '[') {
        offset++;
        targetLen--;
    }
    arrayDepth = offset;

    if (targetLen == 1) {
        /* primitive type */
        str = primitiveTypeLabel(str[offset]);
        offset = 0;
        targetLen = strlen(str);
    } else {
        /* account for leading 'L' and trailing ';' */
        if (targetLen >= 2 && str[offset] == 'L' &&
            str[offset+targetLen-1] == ';')
        {
            targetLen -= 2;
            offset++;
        }
    }

    newStr = (char*)malloc(targetLen + arrayDepth * 2 +1);

    /* copy class name over */
    int i;
    for (i = 0; i < targetLen; i++) {
        char ch = str[offset + i];
        newStr[i] = (ch == '/' || ch == '$') ? '.' : ch;
    }

    /* add the appropriate number of brackets for arrays */
    while (arrayDepth-- > 0) {
        newStr[i++] = '[';
        newStr[i++] = ']';
    }
    newStr[i] = '\0';
    //assert(i == targetLen + arrayDepth * 2);

    return newStr;	
}

const char* Cdex::getClassDescriptor(DexFile* pDexFile, u4 classIdx)
{
	return dexStringByTypeIdx(pDexFile, classIdx);
}

inline u2 Cdex::get2LE(unsigned char const* pSrc)
{
	return pSrc[0] | (pSrc[1] << 8);
}
void Cdex::dumpInstruction(DexFile* pDexFile, const DexCode* pCode, int insnIdx,int insnWidth, const DecodedInstruction* pDecInsn)
{
	const u2* insns = pCode->insns;
    int i;

    printf("%06x:", ((u1*)insns - pDexFile->baseAddr) + insnIdx*2);
    for (i = 0; i < 8; i++) {
        if (i < insnWidth) {
            if (i == 7) {
                printf(" ... ");
            } else {
                /* print 16-bit value in little-endian order */
                const u1* bytePtr = (const u1*) &insns[insnIdx+i];
                printf(" %02x%02x", bytePtr[0], bytePtr[1]);
            }
        } else {
            fputs("     ", stdout);
        }
    }

    if (pDecInsn->opCode == OP_NOP) {
        u2 instr = get2LE((const u1*) &insns[insnIdx]);
        if (instr == kPackedSwitchSignature) {
            printf("|%04x: packed-switch-data (%d units)",
                insnIdx, insnWidth);
        } else if (instr == kSparseSwitchSignature) {
            printf("|%04x: sparse-switch-data (%d units)",
                insnIdx, insnWidth);
        } else if (instr == kArrayDataSignature) {
            printf("|%04x: array-data (%d units)",
                insnIdx, insnWidth);
        } else {
            printf("|%04x: nop // spacer", insnIdx);
        }
    } else {
        printf("|%04x: %s", insnIdx, getOpcodeName(pDecInsn->opCode));
    }

    switch (dexGetInstrFormat(gInstrFormat, pDecInsn->opCode)) {
    case kFmt10x:        // op
        break;
    case kFmt12x:        // op vA, vB
        printf(" v%d, v%d", pDecInsn->vA, pDecInsn->vB);
        break;
    case kFmt11n:        // op vA, #+B
        printf(" v%d, #int %d // #%x",
            pDecInsn->vA, (s4)pDecInsn->vB, (u1)pDecInsn->vB);
        break;
    case kFmt11x:        // op vAA
        printf(" v%d", pDecInsn->vA);
        break;
    case kFmt10t:        // op +AA
    case kFmt20t:        // op +AAAA
        {
            s4 targ = (s4) pDecInsn->vA;
            printf(" %04x // %c%04x",
                insnIdx + targ,
                (targ < 0) ? '-' : '+',
                (targ < 0) ? -targ : targ);
        }
        break;
    case kFmt22x:        // op vAA, vBBBB
        printf(" v%d, v%d", pDecInsn->vA, pDecInsn->vB);
        break;
    case kFmt21t:        // op vAA, +BBBB
        {
            s4 targ = (s4) pDecInsn->vB;
            printf(" v%d, %04x // %c%04x", pDecInsn->vA,
                insnIdx + targ,
                (targ < 0) ? '-' : '+',
                (targ < 0) ? -targ : targ);
        }
        break;
    case kFmt21s:        // op vAA, #+BBBB
        printf(" v%d, #int %d // #%x",
            pDecInsn->vA, (s4)pDecInsn->vB, (u2)pDecInsn->vB);
        break;
    case kFmt21h:        // op vAA, #+BBBB0000[00000000]
        // The printed format varies a bit based on the actual opcode.
        if (pDecInsn->opCode == OP_CONST_HIGH16) {
            s4 value = pDecInsn->vB << 16;
            printf(" v%d, #int %d // #%x",
                pDecInsn->vA, value, (u2)pDecInsn->vB);
        } else {
            s8 value = ((s8) pDecInsn->vB) << 48;
            printf(" v%d, #long %lld // #%x",
                pDecInsn->vA, value, (u2)pDecInsn->vB);
        }
        break;
    case kFmt21c:        // op vAA, thing@BBBB
        if (pDecInsn->opCode == OP_CONST_STRING) {
            printf(" v%d, \"%s\" // string@%04x", pDecInsn->vA,
                dexStringById(pDexFile, pDecInsn->vB), pDecInsn->vB);
        } else if (pDecInsn->opCode == OP_CHECK_CAST ||
                   pDecInsn->opCode == OP_NEW_INSTANCE ||
                   pDecInsn->opCode == OP_CONST_CLASS)
        {
            printf(" v%d, %s // class@%04x", pDecInsn->vA,
                getClassDescriptor(pDexFile, pDecInsn->vB), pDecInsn->vB);
        } else /* OP_SGET* */ {
            FieldMethodInfo fieldInfo;
            if (getFieldInfo(pDexFile, pDecInsn->vB, &fieldInfo)) {
                printf(" v%d, %s.%s:%s // field@%04x", pDecInsn->vA,
                    fieldInfo.classDescriptor, fieldInfo.name,
                    fieldInfo.signature, pDecInsn->vB);
            } else {
                printf(" v%d, ??? // field@%04x", pDecInsn->vA, pDecInsn->vB);
            }
        }
        break;
    case kFmt23x:        // op vAA, vBB, vCC
        printf(" v%d, v%d, v%d", pDecInsn->vA, pDecInsn->vB, pDecInsn->vC);
        break;
    case kFmt22b:        // op vAA, vBB, #+CC
        printf(" v%d, v%d, #int %d // #%02x",
            pDecInsn->vA, pDecInsn->vB, (s4)pDecInsn->vC, (u1)pDecInsn->vC);
        break;
    case kFmt22t:        // op vA, vB, +CCCC
        {
            s4 targ = (s4) pDecInsn->vC;
            printf(" v%d, v%d, %04x // %c%04x", pDecInsn->vA, pDecInsn->vB,
                insnIdx + targ,
                (targ < 0) ? '-' : '+',
                (targ < 0) ? -targ : targ);
        }
        break;
    case kFmt22s:        // op vA, vB, #+CCCC
        printf(" v%d, v%d, #int %d // #%04x",
            pDecInsn->vA, pDecInsn->vB, (s4)pDecInsn->vC, (u2)pDecInsn->vC);
        break;
    case kFmt22c:        // op vA, vB, thing@CCCC
        if (pDecInsn->opCode >= OP_IGET && pDecInsn->opCode <= OP_IPUT_SHORT) {
            FieldMethodInfo fieldInfo;
            if (getFieldInfo(pDexFile, pDecInsn->vC, &fieldInfo)) {
                printf(" v%d, v%d, %s.%s:%s // field@%04x", pDecInsn->vA,
                    pDecInsn->vB, fieldInfo.classDescriptor, fieldInfo.name,
                    fieldInfo.signature, pDecInsn->vC);
            } else {
                printf(" v%d, v%d, ??? // field@%04x", pDecInsn->vA,
                    pDecInsn->vB, pDecInsn->vC);
            }
        } else {
            printf(" v%d, v%d, %s // class@%04x",
                pDecInsn->vA, pDecInsn->vB,
                getClassDescriptor(pDexFile, pDecInsn->vC), pDecInsn->vC);
        }
        break;
    case kFmt22cs:       // [opt] op vA, vB, field offset CCCC
        printf(" v%d, v%d, [obj+%04x]",
            pDecInsn->vA, pDecInsn->vB, pDecInsn->vC);
        break;
    case kFmt30t:
        printf(" #%08x", pDecInsn->vA);
        break;
    case kFmt31i:        // op vAA, #+BBBBBBBB
        {
            /* this is often, but not always, a float */
            union {
                float f;
                u4 i;
            } conv;
            conv.i = pDecInsn->vB;
            printf(" v%d, #float %f // #%08x",
                pDecInsn->vA, conv.f, pDecInsn->vB);
        }
        break;
    case kFmt31c:        // op vAA, thing@BBBBBBBB
        printf(" v%d, \"%s\" // string@%08x", pDecInsn->vA,
            dexStringById(pDexFile, pDecInsn->vB), pDecInsn->vB);
        break;
    case kFmt31t:       // op vAA, offset +BBBBBBBB
        printf(" v%d, %08x // +%08x",
            pDecInsn->vA, insnIdx + pDecInsn->vB, pDecInsn->vB);
        break;
    case kFmt32x:        // op vAAAA, vBBBB
        printf(" v%d, v%d", pDecInsn->vA, pDecInsn->vB);
        break;
    case kFmt35c:        // op vB, {vD, vE, vF, vG, vA}, thing@CCCC
        {
            /* NOTE: decoding of 35c doesn't quite match spec */
            fputs(" {", stdout);
            for (i = 0; i < (int) pDecInsn->vA; i++) {
                if (i == 0)
                    printf("v%d", pDecInsn->arg[i]);
                else
                    printf(", v%d", pDecInsn->arg[i]);
            }
            if (pDecInsn->opCode == OP_FILLED_NEW_ARRAY) {
                printf("}, %s // class@%04x",
                    getClassDescriptor(pDexFile, pDecInsn->vB), pDecInsn->vB);
            } else {
                FieldMethodInfo methInfo;
                if (getMethodInfo(pDexFile, pDecInsn->vB, &methInfo)) {
                    printf("}, %s.%s:%s // method@%04x",
                        methInfo.classDescriptor, methInfo.name,
                        methInfo.signature, pDecInsn->vB);
                } else {
                    printf("}, ??? // method@%04x", pDecInsn->vB);
                }
            }
        }
        break;
    case kFmt35ms:       // [opt] invoke-virtual+super
    case kFmt35fs:       // [opt] invoke-interface
        {
            fputs(" {", stdout);
            for (i = 0; i < (int) pDecInsn->vA; i++) {
                if (i == 0)
                    printf("v%d", pDecInsn->arg[i]);
                else
                    printf(", v%d", pDecInsn->arg[i]);
            }
            printf("}, [%04x] // vtable #%04x", pDecInsn->vB, pDecInsn->vB);
        }
        break;
    case kFmt3rc:        // op {vCCCC .. v(CCCC+AA-1)}, meth@BBBB
        {
            /*
             * This doesn't match the "dx" output when some of the args are
             * 64-bit values -- dx only shows the first register.
             */
            fputs(" {", stdout);
            for (i = 0; i < (int) pDecInsn->vA; i++) {
                if (i == 0)
                    printf("v%d", pDecInsn->vC + i);
                else
                    printf(", v%d", pDecInsn->vC + i);
            }
            if (pDecInsn->opCode == OP_FILLED_NEW_ARRAY_RANGE) {
                printf("}, %s // class@%04x",
                    getClassDescriptor(pDexFile, pDecInsn->vB), pDecInsn->vB);
            } else {
                FieldMethodInfo methInfo;
                if (getMethodInfo(pDexFile, pDecInsn->vB, &methInfo)) {
                    printf("}, %s.%s:%s // method@%04x",
                        methInfo.classDescriptor, methInfo.name,
                        methInfo.signature, pDecInsn->vB);
                } else {
                    printf("}, ??? // method@%04x", pDecInsn->vB);
                }
            }
        }
        break;
    case kFmt3rms:       // [opt] invoke-virtual+super/range
    case kFmt3rfs:       // [opt] invoke-interface/range
        {
            /*
             * This doesn't match the "dx" output when some of the args are
             * 64-bit values -- dx only shows the first register.
             */
            fputs(" {", stdout);
            for (i = 0; i < (int) pDecInsn->vA; i++) {
                if (i == 0)
                    printf("v%d", pDecInsn->vC + i);
                else
                    printf(", v%d", pDecInsn->vC + i);
            }
            printf("}, [%04x] // vtable #%04x", pDecInsn->vB, pDecInsn->vB);
        }
        break;
    case kFmt3rinline:   // [opt] execute-inline/range
        {
            fputs(" {", stdout);
            for (i = 0; i < (int) pDecInsn->vA; i++) {
                if (i == 0)
                    printf("v%d", pDecInsn->vC + i);
                else
                    printf(", v%d", pDecInsn->vC + i);
            }
            printf("}, [%04x] // inline #%04x", pDecInsn->vB, pDecInsn->vB);
        }
        break;
    case kFmt3inline:    // [opt] inline invoke
        {
#if 0
            const InlineOperation* inlineOpsTable = dvmGetInlineOpsTable();
            u4 tableLen = dvmGetInlineOpsTableLength();
#endif

            fputs(" {", stdout);
            for (i = 0; i < (int) pDecInsn->vA; i++) {
                if (i == 0)
                    printf("v%d", pDecInsn->arg[i]);
                else
                    printf(", v%d", pDecInsn->arg[i]);
            }
#if 0
            if (pDecInsn->vB < tableLen) {
                printf("}, %s.%s:%s // inline #%04x",
                    inlineOpsTable[pDecInsn->vB].classDescriptor,
                    inlineOpsTable[pDecInsn->vB].methodName,
                    inlineOpsTable[pDecInsn->vB].methodSignature,
                    pDecInsn->vB);
            } else {
#endif
                printf("}, [%04x] // inline #%04x", pDecInsn->vB, pDecInsn->vB);
#if 0
            }
#endif
        }
        break;
    case kFmt51l:        // op vAA, #+BBBBBBBBBBBBBBBB
        {
            /* this is often, but not always, a double */
            union {
                double d;
                u8 j;
            } conv;
            conv.j = pDecInsn->vB_wide;
            printf(" v%d, #double %f // #%016llx",
                pDecInsn->vA, conv.d, pDecInsn->vB_wide);
        }
        break;
    case kFmtUnknown:
        break;
    default:
        printf(" ???");
        break;
    }


    putchar('\n');
}
bool Cdex::getFieldInfo(DexFile* pDexFile, u4 fieldIdx, FieldMethodInfo* pFieldInfo)
{
	const DexFieldId* pFieldId;

    if (fieldIdx >= pDexFile->pHeader->fieldIdsSize)
        return false;

    pFieldId = dexGetFieldId(pDexFile, fieldIdx);
    pFieldInfo->name = dexStringById(pDexFile, pFieldId->nameIdx);
    pFieldInfo->signature = dexStringByTypeIdx(pDexFile, pFieldId->typeIdx);
    pFieldInfo->classDescriptor =
        dexStringByTypeIdx(pDexFile, pFieldId->classIdx);
    return true;
}
const char* Cdex::primitiveTypeLabel(char typeChar)
{
	switch (typeChar) {
    case 'B':   return "byte";
    case 'C':   return "char";
    case 'D':   return "double";
    case 'F':   return "float";
    case 'I':   return "int";
    case 'J':   return "long";
    case 'S':   return "short";
    case 'V':   return "void";
    case 'Z':   return "boolean";
    default:
                return "UNKNOWN";
    }
}
void Cdex::dexDecodeDebugInfo(const DexFile* pDexFile,const DexCode* pCode,const char* classDescriptor,u4 protoIdx,u4 accessFlags,DexDebugNewPositionCb posCb, DexDebugNewLocalCb localCb,void* cnxt)
{
	const u1 *stream = dexGetDebugInfoStream(pDexFile, pCode);
    u4 line;
    u4 parametersSize;
    u4 address = 0;
	std::vector<LocalInfo> localInReg(pCode->registersSize); //分配动态数组，利用标准模版库（）中表示size
    //LocalInfo localInReg[pCode->registersSize];
    u4 insnsSize = pCode->insnsSize;
    DexProto proto = { pDexFile, protoIdx };

    //memset(localInReg, 0, sizeof(LocalInfo) * pCode->registersSize);

    if (stream == NULL) {
        goto end;
    }

    line = readUnsignedLeb128(&stream);
    parametersSize = readUnsignedLeb128(&stream);

    u2 argReg = pCode->registersSize - pCode->insSize;

    if ((accessFlags & ACC_STATIC) == 0) {
        /*
         * The code is an instance method, which means that there is
         * an initial this parameter. Also, the proto list should
         * contain exactly one fewer argument word than the insSize
         * indicates.
         */
       // assert(pCode->insSize == (dexProtoComputeArgsSize(&proto) + 1));
        localInReg[argReg].name = "this";
        localInReg[argReg].descriptor = classDescriptor;
        localInReg[argReg].startAddress = 0;
        localInReg[argReg].live = true;
        argReg++;
    } else {
        //assert(pCode->insSize == dexProtoComputeArgsSize(&proto));
    }
    
    DexParameterIterator iterator;
    dexParameterIteratorInit(&iterator, &proto);

    while (parametersSize-- != 0) {
        const char* descriptor = dexParameterIteratorNextDescriptor(&iterator);
        const char *name;
        int reg;
        
        if ((argReg >= pCode->registersSize) || (descriptor == NULL)) {
            goto invalid_stream;
        }

        name = readStringIdx(pDexFile, &stream);
        reg = argReg;

        switch (descriptor[0]) {
            case 'D':
            case 'J':
                argReg += 2;
                break;
            default:
                argReg += 1;
                break;
        }

        if (name != NULL) {
            localInReg[reg].name = name;
            localInReg[reg].descriptor = descriptor;
            localInReg[reg].signature = NULL;
            localInReg[reg].startAddress = address;
            localInReg[reg].live = true;
        }
    }

    for (;;)  {
        u1 opcode = *stream++;
        u2 reg;

        switch (opcode) {
            case DBG_END_SEQUENCE:
                goto end;

            case DBG_ADVANCE_PC:
                address += readUnsignedLeb128(&stream);
                break;
                
            case DBG_ADVANCE_LINE:
                line += readSignedLeb128(&stream);
                break;

            case DBG_START_LOCAL:
            case DBG_START_LOCAL_EXTENDED:
                reg = readUnsignedLeb128(&stream);
                if (reg > pCode->registersSize) goto invalid_stream;

                // Emit what was previously there, if anything
                emitLocalCbIfLive (cnxt, reg, address, 
                    localInReg, localCb);

                localInReg[reg].name = readStringIdx(pDexFile, &stream);
                localInReg[reg].descriptor = readTypeIdx(pDexFile, &stream);
                if (opcode == DBG_START_LOCAL_EXTENDED) {
                    localInReg[reg].signature 
                        = readStringIdx(pDexFile, &stream);
                } else {
                    localInReg[reg].signature = NULL;
                }
                localInReg[reg].startAddress = address;
                localInReg[reg].live = true;
                break;

            case DBG_END_LOCAL:
                reg = readUnsignedLeb128(&stream);
                if (reg > pCode->registersSize) goto invalid_stream;

                emitLocalCbIfLive (cnxt, reg, address, localInReg, localCb);
                localInReg[reg].live = false;
                break;

            case DBG_RESTART_LOCAL:
                reg = readUnsignedLeb128(&stream);
                if (reg > pCode->registersSize) goto invalid_stream;

                if (localInReg[reg].name == NULL 
                        || localInReg[reg].descriptor == NULL) {
                    goto invalid_stream;
                }

                /*
                 * If the register is live, the "restart" is superfluous,
                 * and we don't want to mess with the existing start address.
                 */
                if (!localInReg[reg].live) {
                    localInReg[reg].startAddress = address;
                    localInReg[reg].live = true;
                }
                break;

            case DBG_SET_PROLOGUE_END:
            case DBG_SET_EPILOGUE_BEGIN:
            case DBG_SET_FILE:
                break;

            default: {
                int adjopcode = opcode - DBG_FIRST_SPECIAL;

                address += adjopcode / DBG_LINE_RANGE;
                line += DBG_LINE_BASE + (adjopcode % DBG_LINE_RANGE);

                if (posCb != NULL) {
                    int done; 
                    done = posCb(cnxt, address, line);

                    if (done) {
                        // early exit
                        goto end;
                    }
                }
                break;
            }
        }
    }

end:
    {
        int reg;
        for (reg = 0; reg < pCode->registersSize; reg++) {
            emitLocalCbIfLive (cnxt, reg, insnsSize, localInReg, localCb);
        }
    }
    return;

invalid_stream:
    if(1) {
        char* methodDescriptor = dexProtoCopyMethodDescriptor(&proto);
        printf("Invalid debug info stream. class %s; proto %s",classDescriptor, methodDescriptor);
        free(methodDescriptor);
    }
}
const char* Cdex::readStringIdx(const DexFile* pDexFile,const u1** pStream)
{
	u4 stringIdx = readUnsignedLeb128(pStream);

    // Remember, encoded string indicies have 1 added to them.
    if (stringIdx == 0) {
        return NULL;
    } else {
        return dexStringById(pDexFile, stringIdx - 1);
    }
}
const char* Cdex::readTypeIdx(const DexFile* pDexFile,const u1** pStream)
{
	u4 typeIdx = readUnsignedLeb128(pStream);

    // Remember, encoded type indicies have 1 added to them.
    if (typeIdx == 0) {
        return NULL;
    } else {
        return dexStringByTypeIdx(pDexFile, typeIdx - 1);
    }
}

void Cdex::emitLocalCbIfLive (void *cnxt, int reg, u4 endAddress,std::vector<LocalInfo> localInReg, DexDebugNewLocalCb localCb)
{
	if (localCb != NULL && localInReg[reg].live) {
        localCb(cnxt, reg, localInReg[reg].startAddress, endAddress,
                localInReg[reg].name, 
                localInReg[reg].descriptor, 
                localInReg[reg].signature == NULL 
                ? "" : localInReg[reg].signature );
    }
}
int Cdex::dumpPositionsCb(void *cnxt, u4 address, u4 lineNum)
{
	printf("        0x%04x line=%d\n", address, lineNum);
    return 0;
}
Cdex::~Cdex(void)
{
	  BOOL bFlag;           // a result holder
	  bFlag = UnmapViewOfFile(lpMapAddress);
	  bFlag = CloseHandle(hMapFile); // close the file mapping object
	  free(gInstrWidth);
	  free(gInstrFormat);
	  if(!bFlag) 
	  {
		printf("\nError %ld occurred closing the mapping object!",
			   GetLastError());
	  }
	  bFlag = CloseHandle(hFile);   // close the file itself

	  if(!bFlag) 
	  {
		printf("\nError %ld occurred closing the file!",
			   GetLastError());
	  }
}
