#!/usr/bin/env python
#-*- coding:utf-8 -*-
import threadpool
import time
def fun(arglist):
	for i in arglist:
		print i
		print "bye"

tp = threadpool.ThreadPool()
tp.thread_job.put((fun,(('123','345'))))
tp.thread_job.put((fun,(('123','345'))))
tp.thread_job.put((fun,(('123','345'))))
tp.thread_job.put((fun,(('123','345'))))
print "ok?"
time.sleep(5)
tp.cancel_all_thread()
