// dexreader.cpp : �������̨Ӧ�ó������ڵ㡣
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
		dex.showStringIds();  //��ʾdex���ַ�����
		dex.showProtoIds();	  //���е�Proto	
		dex.showMethodIds();  //���еķ���	
		dex.showClassDefs();  //���е�class������Dalvikcode�Ľ���	
	}else
	{
		usage();
	}
	return 0;
}

