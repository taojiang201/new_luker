// osisList.h: interface for the osisList class.
//
//////////////////////////////////////////////////////////////////////

#ifndef AFX_OSISLIST_H__EFDABF3F_3135_4F2F_B803_FB7461C2A9E5__INCLUDED_
#define AFX_OSISLIST_H__EFDABF3F_3135_4F2F_B803_FB7461C2A9E5__INCLUDED_

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include<string>
#include "SCS.h"
class osisArry
{
public:
	osisArry();
	virtual ~osisArry();
    
	volatile int sidVal;
	volatile int stat;
    volatile int flag;	
	
};
class osisList  
{
public:
	osisList();
	virtual ~osisList();
	long  lcount;
	bool  bStat;
	long newArry(int icount);
	int GetNewSid();
	int putoldSid(int pisid);
	osisArry** mArry;
	volatile int nSid;
	volatile int inNsid;
    volatile int outNsid;

};

#endif 
