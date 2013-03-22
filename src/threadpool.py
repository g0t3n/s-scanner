#!/usr/bin/env python
#-*- coding:utf-8 -*-
import threading
import Queue
import time
import traceback
import sys
thread_num = 20
thread_sleep = 3
__doc__ = '''
usage:
	s = threadpool.ThreadPool()
	s.addjob(worker_fun,arg_list)		# function with argument
	s.addjob(worker_fun,None)
	s.cancel_all_thread()
'''
try:
	import config
	if config.config.has_key('thread_num'):
		thread_num = config.config['thread_num']
except:
	pass

class ThreadPool:
	#put fun,arg in, remember to return thread_job.put((fun,[arg1,arg2]))
	thread_job = Queue.Queue()
	def __init__(self, thread_num=20, setdeamon=1):
		self.tid_list = []
		self.thread_num = thread_num
		# setting thread stack to 
		#threading.stack_size(32768*8)
		for i in range(thread_num):
			tid = threading.Thread(target=self.working)
			self.tid_list.append(tid)
			if setdeamon == 1:
				#print "setting Daemon..."
				tid.setDaemon(True)
			tid.start()

	def working(self):
		#print "thread stack size "+str(threading.stack_size())
		while True:
			try:
				(worker,arglist) = self.thread_job.get()
				if type(worker) == type(1):
					break
				self.thread_job.task_done()
				#print "thread_pool : "+str(arglist)
				if arglist == None:
					worker()
				else:
					worker(arglist)
				time.sleep(thread_sleep)
			except:
				print traceback.format_exc()

	def addjob(self, func, arglist):
		self.thread_job.put((func,arglist))
	# cancel num thread.just self.thread_job.put((0,0))	
	# for dynamic cancel thread num
	def cancel_thread(self,num=20):
		if num <= 0:
			return False
		if num > self.thread_num:
			num = self.thread_num
		for i in xrange(num):
			self.thread_job.put((0,0))
		self.thread_num = self.thread_num - num

	def cancel_all_thread(self):
		self.cancel_thread(self.thread_num)
	
	def wait_jobs(self):
		while (not s.empty()):
			time.sleep(1)

if __name__ == '__main__':
	test = ThreadPool(20)
	while True:
		time.sleep(10)

