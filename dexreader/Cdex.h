#include "DexFile.h"
#include "DexClass.h"
#include "InstrUtils.h"
#include <vector>

using std::vector;
#pragma once

typedef struct FieldMethodInfo {
    const char* classDescriptor;
    const char* name;
    const char* signature;
} FieldMethodInfo;

class Cdex
{
public:
	DexFile* pDexFile;
	HANDLE hMapFile;
	HANDLE hFile;
	LPVOID lpMapAddress;
	DWORD dexsize;
	InstructionWidth* gInstrWidth;
	InstructionFormat* gInstrFormat;
	void initDexStructure(void);
	void showStringIds(void);
	void showTypeIds(void);
	void showProtoIds(void);
	void showFiledIds(void);
	void showMethodIds(void);
	void showClassDefs(void);
	void showAnnotations(int,u4,u1*);
	void showInterfaces(int,u4,u1*);
	void showDataOff(int,u4,char*);

	u1*  getStrByStringId(u1*,u4);
	u1*  getStrByTypeId(u1*,u4);
	bool getMethodInfo(DexFile* pDexFile, u4 methodIdx, FieldMethodInfo* pMethInfo);
	void dumpClass(DexFile* pDexFile, int idx);
	void dumpMethod(DexFile* pDexFile, const char* fileName,const DexMethod* pDexMethod, int i);
	void dumpCode(DexFile* pDexFile, const DexMethod* pDexMethod);
	void dumpBytecodes(DexFile* pDexFile, const DexMethod* pDexMethod);
	void dumpCatches(DexFile* pDexFile, const DexCode* pCode);
	void dumpPositions(DexFile* pDexFile, const DexCode* pCode,const DexMethod *pDexMethod);
	void dumpLocals(DexFile* pDexFile, const DexCode* pCode,const DexMethod *pDexMethod);
	void dumpInstruction(DexFile* pDexFile, const DexCode* pCode, int insnIdx,int insnWidth, const DecodedInstruction* pDecInsn);
	static char* descriptorToDot(const char* str);
	static inline u2 get2LE(unsigned char const* pSrc);
	const char* getClassDescriptor(DexFile* pDexFile, u4 classIdx);
	bool getFieldInfo(DexFile* pDexFile, u4 fieldIdx, FieldMethodInfo* pFieldInfo);
	static void dumpLocalsCb(void *cnxt, u2 reg, u4 startAddress,u4 endAddress, const char *name, const char *descriptor,const char *signature);
	void dexDecodeDebugInfo(const DexFile* pDexFile,const DexCode* pCode,const char* classDescriptor,u4 protoIdx,u4 accessFlags,DexDebugNewPositionCb posCb, DexDebugNewLocalCb localCb,void* cnxt);
	static const char* primitiveTypeLabel(char typeChar);
	static const char* readStringIdx(const DexFile* pDexFile,const u1** pStream);
	static const char* readTypeIdx(const DexFile* pDexFile,const u1** pStream);
	static void emitLocalCbIfLive (void *cnxt, int reg, u4 endAddress,std::vector<LocalInfo> localInReg, DexDebugNewLocalCb localCb);
	static int dumpPositionsCb(void *cnxt, u4 address, u4 lineNum);

public:
	Cdex(TCHAR *);
	~Cdex(void);
};
