#!/usr/bin/env python
#-*- coding:utf-8 -*-
import sqlite3
import traceback
import os

__doc__ = 'not consider for insert duplicate host:port'

initdb_create_result = '''
		CREATE TABLE IF NOT EXISTS result(
		article_id integer PRIMARY KEY,
		host_ip text not null,
		host_port integer not null,
		banner text not null);
	'''
initdb_info = '''
		CREATE TABLE IF NOT EXISTS db_info(
		total_host integer,
		update_time integer);
	'''	
class db:
	def __init__(self,db_path='./output/datas.db'):
		self.con = sqlite3.connect(db_path)
		cur = self.con.cursor()
		if sqlite3.threadsafety != 1:
			print "warning! your sqlite is not threadsafe"
		try:
			cur.execute(initdb_create_result)
			cur.execute(initdb_info)

		except Exception as E:
			print traceback.format_exc()
			print "db_init() error,exception: " + str(E)
			os.exit(1)
		self.con.commit()
		cur.close()
	
	inert_str = 'insert into '
	def insert(self, host, port, banner):
		cur = self.con.cursor()
		try:
			cur.execute('insert into result values(Null,"' + str(host)+'",'+str(port)+',"'+str(banner)+ '")')
			#print 'insert into result values(Null,' + str(host)+','+str(port)+','+str(banner) +')'
		except:
			print traceback.format_exc()
		finally:
			cur.close()
		self.con.commit()
	def kill(self):
		self.con.close()
