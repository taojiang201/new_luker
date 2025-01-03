/*
 * Created on Mon Dec 23 2024
 *
 *               Copyright (c) 2024 Owen Jiang
 * 
 * This program is free software. You may use, modify, and redistribute it 
 * under the terms of the GNU General Public License as published by the   
 * Free Software Foundation, either version 3 or (at your option) any      
 * later version. This program is distributed without any warranty.  See   
 * the file COPYING.gpl-v3 for details.                                    
 *
 */

#ifndef __SCS_H__
#define __SCS_H__


#include <exception>
#include <pthread.h>
#include <semaphore.h>

class sem
{
public:
	sem();

	~sem();
	
	bool wait();
	
	bool post();


private:
	sem_t m_sem;
};

class locker
{
public:
	locker();

		~locker();

		int Lock();

		int lock();

		bool unlock();

		bool UnLock();


private:
	pthread_mutex_t m_mutex;
};

class cond
{
public:
	cond();
		
	~cond();

		bool wait();

		bool signal();

private:
	pthread_mutex_t m_mutex;
	pthread_cond_t m_cond;
};

#endif
