#!/usr/bin/env python
#-*- coding:utf-8 -*-
import os
import sys
import traceback
import re

AllProbe = [ ]
 # { 'ProbeName' = "",
 #  'Port' = []							| 'NULL PROBE' Port=>[]
 #	'Type'		= 'tcp',				| 
 #	'Rarity'	= 0,  # default			|rarity
 #	'TimeOut'	= 6,  # 1s = 1000ms		|totalwaitms
 #	'MatchTuple' = []}
 # forget about fallback 


# translate r'\x01\0\x23' to bin string
def raw2bin(strs):
	tmplen = 0
	newstr = ""
	while (len(strs) != tmplen):
		if (strs[tmplen] == '\\'):
			tmplen+=1
			if strs[tmplen] == '0':
				newstr += '\0'
			elif strs[tmplen] == 'a':
				newstr += '\a'
			elif strs[tmplen] == 'b':
				newstr += '\b'
			elif strs[tmplen] == 'f':
				newstr += '\f'
			elif strs[tmplen] == 'n':
				newstr += '\n'
			elif strs[tmplen] == 'r':
				newstr += '\r'
			elif strs[tmplen] == 't':
				newstr += '\t'
			elif strs[tmplen] == 'v':
				newstr += '\v'
			elif strs[tmplen] == 'x':
				tmplen += 1

				newstr += strs[tmplen:tmplen+2].decode('hex')
				tmplen += 1				# only inc 1,cause it will add 1 up next
			else:					# \\ \* \.
				newstr += strs[tmplen]
		else:
			newstr += strs[tmplen]
		tmplen+=1
	return newstr

def LoadNmapServiceProbe(NmapSPFile):		# nmap-service-probe
	# Load  nmap-service-probes, File format details at http://nmap.org/vscan/vscan-fileformat.html
	
	CompileSuccess = 0
	CompileFail = 0
	LineNum = 0
	PortArray = [ ]
	ProbeName = ""
	ProbeStr = ""
	Rarity = 0
	tmpProbe = []
	if os.path.isfile(NmapSPFile):
		try:
			print "Loading Nmap-FingerPrint"
			fd = open(NmapSPFile, "r")
			init = 0
			for line in fd:
				LineNum += 1
				line = line.strip()
				if (line[0:1] == '#') or (line[0:9] == "sslports "):   # or (line[0:9] == 'softmatch'):
					continue
				if (len(line) >= 9) and (line[0:10] == "softmatch "):
					continue
					#softmatches look very weak at the moment;  Skip for the moment.
				if (line[0:6] == "Probe "):			# sample line:   Probe TCP metasploit-msgrpc q|GET /api HTTP/1.0\r\n\r\n|
					#print "==== READ Probe ===="
					if init == 0:
						init = 1
					else:
						if TimeOut == 0:
							TimeOut = 6000					# default timeout is 6000ms
						AllProbe.append({"ProbeName":ProbeName, "ProbeStr":ProbeStr, "Type":Type, "Port":PortArray, "Rarity":Rarity, "TimeOut":TimeOut, "MatchTuple":MatchTuple})
						pass
					MatchTuple = []
					PortArray = []
					Rarity,TimeOut = 0,0
					tmp = line.split(' ')
					Type, ProbeName, ProbeStr = tmp[1:4]
					ProbeStr = line[line.find('q|')+2:-1]
					# print "ProbeStr "+ ProbeStr				# exm: q|GET /api HTTP/1.0\r\n\r\n|   q|123|
					ProbeStr = raw2bin(ProbeStr)
					#print "one ProbeStr"+str(ProbeStr)

				elif (line[:6] == 'rarity'):
					Rarity = int( line[line.find(' ')+1:])
					#print "rarity" + str(Rarity)

				elif (len(line) >= 5) and (line[0:6] == "match "):
					InformationPresent = True
																				# sample line:  match srun m|^X\0\0\0$| p/Caucho Resin JSP Engine srun/
					Remainder=line[6:].strip()									#  srun m|^X\0\0\0$| p/Caucho Resin JSP Engine srun/
					MatchStart=Remainder.find(" m")								#      4
					ProtoString=Remainder[:MatchStart].replace(',', ';')		#  srun
					#At the moment, nmap-service-probes uses these separators:
					#3 m%, 2 m+, 126 m/, 29 m=, 2 m@, and 3509 m|
					#No flags on %, +, 
					#Only flags should be "i" (case-insensitive) and "s" ("." can match newline)
					Separator=Remainder[MatchStart+2:MatchStart+3]			#        |
					MatchEnd=Remainder.find(Separator,MatchStart+3)			#                  16
					MatchString=Remainder[MatchStart+3:MatchEnd]			#         ^X\0\0\0$

					#Handle an "i" or "s" flag after separator
					if MatchEnd + 1 == len(Remainder):
						InformationPresent = False
					elif (Remainder[MatchEnd+1:MatchEnd+2] == " "):
						PPointer=MatchEnd + 2
						MatchFlags = re.M
					elif (Remainder[MatchEnd+1:MatchEnd+3] == "i "):
						PPointer=MatchEnd + 3
						MatchFlags = re.M | re.I
					elif (Remainder[MatchEnd+1:MatchEnd+3] == "s "):
						PPointer=MatchEnd + 3
						MatchFlags = re.M | re.S
					elif (Remainder[MatchEnd+1:MatchEnd+4] == "is ") or (Remainder[MatchEnd+1:MatchEnd+4] == "si "):
						PPointer=MatchEnd + 4
						MatchFlags = re.M | re.I | re.S
					else:
						#Debug("Unrecognized nmap-service-probes flag combination")
						print MatchEnd + 1, len(Remainder)
						print Remainder + ", unknown flags"
						#quit()

					#Substitute ; for , in ProtoString and ServerDescription since we're using commas as field delimiters in output
					ServerDescription = Remainder[PPointer:].replace(',', ';')	#                    p/Caucho Resin JSP Engine srun/
					
					#The nmap-service-probes file uses a character set ("[...]") issue that python doesn't like.
					#If a "-" is used inside a character set, it should either be in the first or last position,
					#or used in a character range ("[.....a-z.....]").  The following move any dashes to first or 
					#last position so re.compile is happy.
					MatchString=MatchString.replace("[\w-","[-\w")			#The dash needs to be at the end or it's treated as a range specifier
					MatchString=MatchString.replace("[\d-","[-\d")			#same
					MatchString=MatchString.replace("[\w\d-_.]","[\w\d_.-]")	#and so on...
					MatchString=MatchString.replace("[\w\d-_]","[\w\d_-]")
					MatchString=MatchString.replace("[.-\w]","[.\w-]")
					MatchString=MatchString.replace("[\s-\w.,]","[\s\w.,-]")
					MatchString=MatchString.replace("[\w\d-.]","[\w\d.-]")
					MatchString=MatchString.replace("[\d\.-\w]","[\d\.\w-]")
					MatchString=MatchString.replace("[^-_A-Z0-9]","[^_A-Z0-9-]")
					MatchString=MatchString.replace("[^-A-Z0-9]","[^A-Z0-9-]")

					if (ServerDescription.find('Skype VoIP data channel') > -1):
						#This "14 bytes of random stuff" signature way misfires.
						print "t"
						pass
					#elif (ServerDescription.find('Microsoft Distributed Transaction Coordinator') > -1):
						#This "ERROR" signature matches other protocols.
					#	print "t"
					#	pass
					#elif (InformationPresent == False):
						#There's a regex match, but no information about, skip.
					#	print "false"
					#	pass
					else:
						try:
							#We try to compile the MatchString now before inserting into ServiceFPs so the work only needs to be 
							# 在插入 ServiceFPs 前 compile MatchString
							#done once.  If this fails we fall down to the except and simply don't use the tuple.a
							# 如果compile fail we don't use tuple
							#Originally 413 out of 3671 match lines failed to compile because of "-" placement in character sets.
							#The problem, and a fixed version, have been reported to the nmap developers.
							#The use of "str" seems redundant, but we have occasionally gotten:
							#line 511: OutputDescription = OneTuple[1]
							#TypeError: expected a character buffer object

							#print str(ProtoString + "://" + ServerDescription)	  telnet://p/Windows qotd/ i/English/ o/Windows/ cpe:/o:microsoft:qotd::::en/ 
							SearchTuple=(re.compile(MatchString, MatchFlags), str(ProtoString + "://" + ServerDescription))
							CompileSuccess += 1
							MatchTuple.append(SearchTuple)
				#				if (len(PortArray) == 0):
				#					#No ports declared yet; we'll place this search pair under the special port "all"
				#					if (not(ServiceFPs.has_key('all'))):
				#						ServiceFPs['all'] = [ ]
				#					ServiceFPs['all'].append(SearchTuple)
				#					LoadCount += 1
				#				else:
				#					#Register this search pair for every port requested
				#					for OnePort in PortArray:
				#						if (not(ServiceFPs.has_key(int(OnePort)))):
				#							ServiceFPs[int(OnePort)] = [ ]
				#						ServiceFPs[int(OnePort)].append(SearchTuple)
				#						LoadCount += 1
						except:
							print "Failed to compile line:" + str(LineNum) + " => " + MatchString
							print traceback.format_exc()
							CompileFail += 1
					
				elif (len(line) >= 5) and (line[0:6] == "ports "):
					PortArray = []
					RawPortsString=line[6:].strip()
					#print "ports are ", RawPortsString
					for PortBlock in RawPortsString.split(","):		#Each PortBlock is either an individual port or port range
						if (PortBlock.find("-") > -1):
							#We have a port range
							PortRange=PortBlock.split("-")
							for OnePort in range(int(PortRange[0]), int(PortRange[1]) + 1):
								PortArray.append(int(OnePort))
						else:
							PortArray.append(int(PortBlock))
					#print len(PortArray), PortArray
				elif (line[0:11] == "totalwaitms"):
					TimeOut = int(line[12:])

			fd.close()

			if (CompileFail == 0):
				print str(CompileSuccess) + " match string successfully loaded"
			else:
				print str(CompileSuccess) + " match string successfully loaded, unable to parse " + str(CompileFail)
			print "ok..."
			#print AllProbe
			return True
		except:
			fd.close()
			print "failed to load " + NmapSPFile + " .line:"+str(LineNum)
			print traceback.format_exc()
			return False
	else:
		print "unable to open " + NmapSPFile
		return False


if __name__ == '__main__':
	LoadNmapServiceProbe('./nmap-service-probes.little')
