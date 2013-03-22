#!/usr/bin/env python
#-*- coding:utf-8 -*-

config = {
		'ips' : "60.244.103.5/24",			# suport / -
		#'ips' : ['60.244.103.5/24','10.10.240.24-10.10.241.80']
		# NOT SUPPORT FOR '10.10.240.28-30'	;-(
		'ports' : [21, 22, 80, 8080, 3306, 1433],
		'report' : '../output/report',
		'ban_gather.so' : './bin/ban_gather.so',
		'thread_num' : 20
		}

def process_config():
	myconfig = config()
	# proc ip list
	def checkip(ipstring):
		iplist = []				# each ip will fill in list
		if myconfig['ips'].find('/') != -1:
			pass
		elif myconfig['ips'].find('-') != -1:
			pass
	iplist = []
	if type(myconfig['ips']) == type([]):
		for ip in myconfig['ips']:
			iplist.extend(checkip(ip))
	elif type(myconfig['ips']) == type(''):
		iplist = checkip(myconfig['ips'])
	else:
		print '[-]bad config.py in field "ips"'
		os.exit(1)

if __name__ == '__main__':
	myconfig = process_config()
	version_Probe
