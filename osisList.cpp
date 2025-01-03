// osisList.cpp: implementation of the osisList class.
//
//////////////////////////////////////////////////////////////////////

#include "osisList.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
osisArry::osisArry()
{

	this->stat = false;
	this->sidVal=0;
	this->flag=-1;
	//this->nSid = 0;

}

osisArry::~osisArry()
 {
 }
osisList::osisList()
{
//	this->mArry = new osisArry[i];
	this->lcount = 0;
	this->bStat = false;
	this->mArry = NULL;
	this->nSid=0;
	this->inNsid=0;
	this->outNsid =-1;

}

long osisList::newArry(int icount)
{
	//m_SockArray = new OJSocket* [serversocksize];

	if(icount<1||icount>50000)
		return 10037;
	mArry = new osisArry* [icount];
	for(int i=0;i<icount;i++)
	{
		//i++;
	//	mArry
		mArry[i] =new osisArry;
		mArry[i]->sidVal=i;
		mArry[i]->stat=false;

	}
	this->lcount=icount;
	return 0;
}
int osisList::GetNewSid()
 {
	 if(this->mArry==NULL)
	   return -1;
	 if(this->outNsid >lcount)
		 return -2;
	 if(this-> outNsid==(lcount-1))
		this-> outNsid=-1;
	 int tSid =this-> outNsid+ 1;
	 int i =0 ;
	 for( i =tSid;i<lcount;i++)
	{
		//i++;
	//	mArry
	//	mArry[i] =new osisArry;
		
	    if(mArry[i]->stat==false)
		{
			mArry[i]->stat=true;
			this->outNsid =i;
		  return i;
		}

	}
	  for( i =0;i<tSid;i++)
	{

		
	    if(mArry[i]->stat==false)
		{
			mArry[i]->stat=true;
			this->outNsid =i;
		  	return i;
		}

	}
    return -3;
 }
int osisList::putoldSid(int pisid)
{
	if(this->mArry==NULL)
	   return -1;
	if(pisid<0||pisid>lcount-1)
		return -2;
	mArry[pisid]->stat =false;
	return 0;
}

osisList::~osisList()
{

}
