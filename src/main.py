#!/usr/bin/env python
#-*- coding:utf-8 -*-

import socket
import passer
import re
import traceback
import select
import time
import threading
import db
import Queue
# 一次仅允许 20 个job 传给 threadpool
max_scan_host = 20

# port_pointer = { 80:[1,2,4]}
port_pointer = {}
# {"ProbeName":ProbeName, "ProbeStr":ProbeStr, "Type":Type, "Port":PortArray, "Rarity":Rarity, "TimeOut":TimeOut, "MatchTuple":MatchTuple}

#passer.LoadNmapServiceProbe('./nmap-service-probes.little')
print "AllProbe len:"+str(len(passer.AllProbe))
#print passer.AllProbe[0]

ips = '10.10.159.106'
ports = [80, 3389]

# (ip,port,respond)
payload = []

start_time = ""
uptime_time = ""
total_port = total_host = 0
total_thread = 0
complete_percent = 0
# print start time,uptime,total_host,total_port,complete_percent
def prn_debug_info():
	uptime = time.time() - start_time
	print "===> start at:" + start_time + ", uptime: "+uptime_time+", total_host: "+str(total_host)+", total_port:"+str(total_port)+". complete_percent:"+str(complete_percent)

# define a worker to send Probe by ThreadPool
# return :  False => port possible close
#			respond_data => len(respond_data)=0 means no data recv
def worker( ip, port, Probe, timeout=10000):
	connected = 0
	#respond_data_len = 0
	respond_data = ""
	try:
		sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sk.settimeout(3)					# 必须加上 timeout, 否着connect 到一个不存在的地址会block
		sk.connect((str(ip),int(port)))	
		#connected = 1
		sk.send(Probe)
	except:						# possible to be port close
		#print "refuse.."
		#print str(ip)+":"+str(port)+traceback.format_exc()
		return respond_data
	for i in xrange(10):
		readable, writable, exceptional = select.select((sk,), (), (), timeout/1000)
		if not readable:		# timeout with no data recive
			print "worker.. timeout"
			break
		try:
			datas = readable[0].recv(100)
			#print "recv datas.."
		except:
			#print "connect reset by peer.."
			return respond_data
		if len(datas) == 0:
			break
		#respond_data_len += len(datas)
		respond_data += datas
	if len(respond_data) == 0:
		print "no date respond"

	#payload.append((ip,port,respond_data))
	# delete me
	return respond_data


# 为每个port计算全局 probe_pointer
# @port => int, port number 
# ex port_pointer{80: [0,1,2,3,4,5,6,7,8,9..71]}  这样只需要按照顺序scan 就ok
def prepare_probe(port):
	on = 0
	unport_list = []
	if port_pointer.has_key(port):
		#print "exist ports?"
		return
	port_pointer[port]	= []
	for i in range(len(passer.AllProbe)):
		#print "Prot:"+str(passer.AllProbe[i]['Port'])
		#print "="*20
		if passer.AllProbe[i]['Port'] == []:
			port_pointer[port].append(i)
			#print "one"
		for tmpport in passer.AllProbe[i]['Port']:
			if tmpport == port:						# found port in current Probe
				port_pointer[port].append(i)
				on = 1
				break
		if on == 1:			# possible bad judgement..
			on = 0
			continue
		else:
			unport_list.append(i)
	port_pointer[port].extend(unport_list)

class save2result:
	def __init__(self):

		self.goodbye = False
		self.jobs = Queue.Queue()
		self.tid = threading.Thread(target=self.loop)
		self.tid.start()
	def loop(self):
		self.ptr = db.db()
		while True:
			if self.goodbye and self.jobs.empty():
				break
			time.sleep(1)
			try:
				result = self.jobs.get_nowait()
				self.ptr.insert(result[0],result[1],result[2])
			except Queue.Empty:
				continue
			except:
				print traceback.format_exc()
				pass
		self.ptr.kill()

	def addjob(self, ip,port,banner = 'unknow?'):
		self.jobs.put((ip,port,banner))
	def killall(self):
		self.goodbye = True
		self.tid.join()									# 如果对 thread daemon后，改为loop


def main(host_list, port_list):			# main :

	print "1723 scanner not support..."
	#print "len of ProbeString"+str(probe['MatchTuple'])	
		# [(<_sre.SRE_Pattern object at 0x1e57ad8>, 'kumo-server://p/Kumofs/ v/$1/'), (<_sre.SRE_Pattern object at 0x1e61dd8>, 'kumo-manager://p/Kumofs/')]
	for ports in port_list:
		print "ports is:"+str(ports)
		prepare_probe(ports)		# 
	
	global max_scan_host
	start_time = time.time()
	print "start at " + time.ctime()
	
	# start a thread to save result into db!
	# 用 save2result+thread 是怕把result存在内存中数据量过大
	# 开多个线程为了防止处理串的时间过大而影响扫描速度
	s2r = save2result()

	#########	main loop here	#############
	# fixme: 
	#    应该设计个更好的 扫描引擎阿...比如 random_host,对每个host先发送rarity高的 Probe
	#########################################
	tmp_scan_cnt = 0
	for host in host_list:									# traval host_list
		tmp_scan_cnt += 1
		for scanport in port_list:						# traval all port which need to scan
			found = 0
			is_port_open = 0
			garbage = ""						# store data if i can't detect it's banner
			for ProbeNum in port_pointer[scanport]:		# traver AllProbe	
				
				if tmp_scan_cnt == max_scan_host:	# stop and wait previ job finish
					pass							# 伪 socket Pool 哈
				#print "sending ProbeStr"+repr(passer.AllProbe[ProbeNum]['ProbeStr'])
				datas = worker(host, scanport, passer.AllProbe[ProbeNum]['ProbeStr'], passer.AllProbe[ProbeNum]['TimeOut'])		# send a Probe
				print "respond?"
				
				if datas:
					is_port_open = 1
					garbage = datas				# save the garbage
					for i in passer.AllProbe[ProbeNum]['MatchTuple']:
						p = i[0].match(datas)							# MatchTuple : (re.compile,'http://p/server v/$1/')
						if p:					# found !!
							found = 1
							banner = str(i[1])
							#print banner
							#print p.groups()
							#print len(p.groups())
							for glen in range(len(p.groups())):
								print '$'+str(glen+1)
								banner = banner.replace('$'+str(glen+1), p.groups()[glen])
							banner1,banner2 = banner.split('://')
							keywords = ['p/','v/','h/','o/','i/']
							for keyword in keywords:			#p/Kerio MailServer Webmail/ v/$1/ i/PHP $2/i o/11/ cpe:/o:microsoft:windows/a
								field = banner2.find(keyword)
								if field != -1:
									if keyword == 'h/':
										banner2 = banner2.replace(keyword,'Service Info:"Host:',1).replace('/','"',1)
									elif keyword == 'o/':
										banner2 = banner2.replace(keyword,'OS:"',1).replace('/','"',1)
									else:
										banner2 = banner2.replace(keyword,'',1).replace('/','',1)

							banner = banner1 +"://"+banner2
							print banner
							#i[1]  xxxxx!
							#s2r.addjob(host,scanport,banner)
							break
							pass			# store import data,like version,we will say goodbye in this process ;-)
						# need process 'http://p/Kerio MailServer Webmail/ v/$1/ i/PHP $2/i o/11/ cpe:/o:microsoft:windows/a'
						#               xxx://i/asdfadi/		
						else:
							pass				# not  match~
					if found == 1:
						break
				else:					# send Probe but has no respond,or maybe socket False,network down,the socket was block by peer
					pass
			if found == 1:
				print "found!! "+str(banner)
			else:						# what else to do while i can't match a server
				#if is_port_open:		# port open but i can't detect which server she send to me
				#	s2r.addjob(host,scanport)		# saveas 'unknow'
				pass				# saveas unknow, i have garbage previ
				#else:					# port close
				#	s2r.addjob(host,scanport,'close')		# saveas 'unknow'
				#	pass
	s2r.killall()
if __name__ == '__main__':
	main('127.0.0.1',[80])
