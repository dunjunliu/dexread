// dexreader.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "Cdex.h"
#include "InstrUtils.h"
void usage(void)
{
    fprintf(stderr, "Dex format reader--written by Dunjun Liu\n\n");
    fprintf(stderr, "dexreader sample.dex\n");
}
int _tmain(int argc, _TCHAR* argv[])
{
	
	Cdex dex(_T("E:\\code\\c\\dexreader\\classes.dex"));
	dex.showClassDefs();
	if(argc ==2)
	{
		Cdex dex(argv[1]);
		dex.showStringIds();  //显示dex中字符串表
		dex.showProtoIds();	  //所有的Proto	
		dex.showMethodIds();  //所有的方法	
		dex.showClassDefs();  //所有的class，包括Dalvikcode的解析	
	}else
	{
		usage();
	}
	return 0;
}

