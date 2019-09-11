import colorama
from colorama import init
init()
from colorama import Fore, Back, Style
import os
import re
import subprocess
import filecmp
import re

debian = '/etc/debian_version'
redhat = '/etc/redhat-release'

def TestIntegrity(File):
	
	if os.path.exists(redhat) : 
	
		command = 'rpm -Vf "'+File+'"' 
					
		processrpm = subprocess.Popen([command], stdout=subprocess.PIPE,shell=True)
		outputrpm = processrpm.communicate()[0]
					
		if outputrpm :
						
			print(Back.RESET + Fore.RED + "Integrity compromised\n")
								
		
		else:
			
			print(Back.RESET + Fore.GREEN + "Integrity OK\n")

	else :	
		
		commandDPKG = 'dpkg -S "'+File+'"'
						
						
		DEVNULL = open(os.devnull, 'wb')
		processdpkg = subprocess.Popen([commandDPKG], stdout=subprocess.PIPE,shell=True, stderr=DEVNULL)
		outputdpkg = processdpkg.communicate()[0]
						
		if processdpkg.returncode == 1:
							
			#dpkg is buggy to find package files 
							
			fixdpkgbug= re.sub('/usr',  '',    File)
							
			commandDPKG2 = 'dpkg -S "'+fixdpkgbug+'"'
						
							
			DEVNULL = open(os.devnull, 'wb')
			processdpkg2 = subprocess.Popen([commandDPKG2], stdout=subprocess.PIPE,shell=True, stderr=DEVNULL)
			outputdpkg2 = processdpkg2.communicate()[0]
							
			outputdpkg = outputdpkg2
							
			if processdpkg2.returncode == 1:
							
				print(Back.RESET + Fore.RED + "Integrity compromised\n")
				return(0)
								
				
		packagename = outputdpkg.split(":")
						
		commandDEBSUM = 'dpkg --verify "'+packagename[0]+'"'
						
							
		processdebsum = subprocess.Popen([commandDEBSUM], stdout=subprocess.PIPE,shell=True)
		outputdebsum = processdebsum.communicate()[0]
		
		print outputdebsum
						
		if outputdebsum :
			
			print(Back.RESET + Fore.RED + "Integrity compromised\n")
						
		else:
			print(Back.RESET + Fore.GREEN + "Integrity OK\n")
						
		

def OpenAndPrint(File) :
	
	filetoprint = open(File, "r")

	print(Back.RESET + Fore.CYAN + "\t%s content :\n" % File)

	for lines in filetoprint.readlines():
	
		print(Back.RESET + Fore.GREEN + "%s" % lines)
	

def WalkAndTest(Dir, Int=False):
	
	print(Back.RESET + Fore.CYAN + "\t%s content: \n" % Dir)
	
	filesdir = []
	
	for r, d, f in os.walk(Dir):
		for file in f:
			
			filesdir.append(os.path.join(r, file))
		
		for f in filesdir:
			
			filereal = os.path.realpath(f)
			
			if os.path.isfile(filereal): 
		
				print(Back.RESET + Fore.CYAN + "%s: \n" % filereal)
		
				filedir= open(filereal, "r")
		
				for lines in filedir.readlines():

					print(Back.RESET + Fore.GREEN + "%s" % lines)

				if Int:
					print(Back.RESET + Fore.CYAN + "\tTesting %s integrity\n" % f)
			
					TestIntegrity(filereal)


def CompareRC(File, DestFile):
	
	if os.path.isfile(File):
	
		if not filecmp.cmp(File, DestFile):
				
			print "Changes detected in %s\n" % File
		
			OpenAndPrint(File)
		
	

print(Back.RESET + Fore.GREEN + "RcLocals 1.0")
print(Back.RESET + Fore.GREEN + "www.security-projects.com/?RcLocals\n")
		

print(Back.RESET + Fore.YELLOW + "[*Listing GPG keys*]\n")

if os.path.exists(debian) :
	commandDEBKEY = 'apt-key list'
							
	processdebkey = subprocess.Popen([commandDEBKEY], stdout=subprocess.PIPE,shell=True)
	outputdebkey = processdebkey.communicate()[0]
	
	print(Back.RESET + Fore.GREEN + "%s" % outputdebkey)
	
else:
	
	commandRPMKEY = 'rpm -q --queryformat "%{SUMMARY}\n" $(rpm -q gpg-pubkey)'
							
	processrpmkey = subprocess.Popen([commandRPMKEY], stdout=subprocess.PIPE,shell=True)
	outputrpmkey = processrpmkey.communicate()[0]
	
	print(Back.RESET + Fore.GREEN + "%s" % outputrpmkey)
	

print(Back.RESET + Fore.YELLOW + "[*Installed Packages*]\n")

if os.path.exists(debian) :
	commandDEBPACK= "dpkg-query -W -f=\'${binary:Package} ${Version}\\t${Maintainer}\\n\'"
							
	processdebpack = subprocess.Popen([commandDEBPACK], stdout=subprocess.PIPE,shell=True)
	outputdebpack = processdebpack.communicate()[0]
	
	print(Back.RESET + Fore.GREEN + "%s" % outputdebpack)
	
else:
	
	commandRPMPACK = r'rpm -qa --qf "%{name}-%{version}-%{release}.%{arch} %|DSAHEADER?{%{DSAHEADER:pgpsig}}:{%|RSAHEADER?{%{RSAHEADER:pgpsig}}:{%|SIGGPG?{%{SIGGPG:pgpsig}}:{%|SIGPGP?{%{SIGPGP:pgpsig}}:{(none)}|}|}|}|\n"'
									
	processrpmpack = subprocess.Popen([commandRPMPACK], stdout=subprocess.PIPE,shell=True)
	outputrpmpack = processrpmpack.communicate()[0]
	
	print(Back.RESET + Fore.GREEN + "%s" % outputrpmpack)


print(Back.RESET + Fore.YELLOW + "[*Checking file integrity*]\n")


if os.path.exists(debian) :
	commandDEBFILE = r'debsums -c'
							
	processdebfile = subprocess.Popen([commandDEBFILE], stdout=subprocess.PIPE,shell=True)
	outputdebfile = processdebfile.communicate()[0]
	
	print(Back.RESET + Fore.RED + "%s" % outputdebfile)
	
else:
	
	commandRPMFILE = r'rpm -Va'
									
	processrpmfile = subprocess.Popen([commandRPMFILE], stdout=subprocess.PIPE,shell=True)
	outputrpmfile = processrpmfile.communicate()[0]
	
	print(Back.RESET + Fore.RED + "%s" % outputrpmfile)

print(Back.RESET + Fore.YELLOW + "[*Checking process integrity*]\n")

for processPid in os.listdir("/proc"):
	
	maps = '/proc/'+processPid+'/maps'
	
	if os.path.exists(maps) : 
		
		file = open(maps, "r")

		for libs in file.readlines():
			
			match = re.search(r'\s[\w-][\w-]([\w-])[\w-].*\s\s\s\s*([\w\/].*)' , libs)
			
			if  match and match.group(1) == 'x':
	
				isdeleted = re.search(r'\(deleted\)' , match.group(2))
				
				if not isdeleted:
					
					if os.path.exists(redhat) : 
						command = 'rpm -Vf "'+match.group(2)+'"' 
					
						processrpm = subprocess.Popen([command], stdout=subprocess.PIPE,shell=True)
						outputrpm = processrpm.communicate()[0]
					
						if outputrpm :
						
							thisfile = re.search(match.group(2) , outputrpm)
						
							if thisfile:
								print(Back.RESET + Fore.RED + "Suspicious lib or process %s in PID %s" % (match.group(2), processPid))
								
								exefile = '/proc/'+processPid+'/exe'
								exepath = os.path.realpath(exefile)
								print(Fore.RED + "Exefile %s\n" % exepath)
								
					if os.path.exists(debian) :
						
						commandDPKG = 'dpkg -S "'+match.group(2)+'"'
						
						
						DEVNULL = open(os.devnull, 'wb')
						processdpkg = subprocess.Popen([commandDPKG], stdout=subprocess.PIPE,shell=True, stderr=DEVNULL)
						outputdpkg = processdpkg.communicate()[0]
						
						
						if processdpkg.returncode == 1:
							
							#dpkg is buggy to find package files 
							
							fixdpkgbug= re.sub('/usr',  '',    match.group(2))
							
							commandDPKG2 = 'dpkg -S "'+fixdpkgbug+'"'
						
							
							DEVNULL = open(os.devnull, 'wb')
							processdpkg2 = subprocess.Popen([commandDPKG2], stdout=subprocess.PIPE,shell=True, stderr=DEVNULL)
							outputdpkg2 = processdpkg2.communicate()[0]
							
							outputdpkg = outputdpkg2
							
							if processdpkg2.returncode == 1:
							
								print(Back.RESET + Fore.RED + "Suspicious lib or process %s in PID %s" % (match.group(2), processPid))
								
								exefile = '/proc/'+processPid+'/exe'
								exepath = os.path.realpath(exefile)
								print(Fore.RED + "Exefile %s\n" % exepath)
						
							else:
								
								packagename = outputdpkg.split(":")
						
								commandDEBSUM = 'dpkg --verify "'+packagename[0]+'"'
						
							
								processdebsum = subprocess.Popen([commandDEBSUM], stdout=subprocess.PIPE,shell=True)
								outputdebsum = processdebsum.communicate()[0]
						
								if outputdebsum :
						
									print(Back.RESET + Fore.RED + "Suspicious lib or process %s in PID %s" % (match.group(2), processPid))
										
									exefile = '/proc/'+processPid+'/exe'
									exepath = os.path.realpath(exefile)
									print(Fore.RED +  "Exefile %s\n" % exepath)
							
							
						elif processdpkg.returncode == 0: 	
								
							packagename = outputdpkg.split(":")
						
							commandDEBSUM = 'dpkg --verify "'+packagename[0]+'"'
						
							
							processdebsum = subprocess.Popen([commandDEBSUM], stdout=subprocess.PIPE,shell=True)
							outputdebsum = processdebsum.communicate()[0]
						
							if outputdebsum :
						
								print(Back.RESET + Fore.RED + "Suspicious lib or process %s in PID %s" % (match.group(2), processPid))
										
								exefile = '/proc/'+processPid+'/exe'
								exepath = os.path.realpath(exefile)
								print(Fore.RED +  "Exefile %s\n" % exepath)
								
										
print(Back.RESET + Fore.YELLOW + "[*Searching CRON entries*]\n")

anacron = "/etc/anacrontab"
crontab = "/etc/crontab"
crondir = "/etc/cron.d/"
cronspool = "/var/spool/cron"
cronspooldebian = "/var/spool/cron/crontabs/"

if os.path.exists(anacron) : 

	OpenAndPrint(anacron)

	print(Back.RESET + Fore.CYAN + "\tTesting %s integrity" % anacron)
	
	TestIntegrity(anacron)
	

OpenAndPrint(crontab)
	
print(Back.RESET + Fore.CYAN + "\tTesting %s integrity" % crontab)

TestIntegrity(crontab)


if os.path.exists(crondir) :  
	
	WalkAndTest(crondir, True)

if os.path.exists(cronspool) :  
	
	WalkAndTest(cronspool)
			
if os.path.exists(cronspooldebian) :  
	
	WalkAndTest(cronspooldebian)
	
print(Back.RESET + Fore.YELLOW + "[*Searching RC files*]\n")

profile = "/etc/profile"
bashrc = "/etc/bashrc"
bashrcdebian = "/etc/bash.bashrc"
profiledir = "/etc/profile.d/"
skeldir ="/etc/skel/"
homedir = "/home/"

OpenAndPrint(profile)
	
print(Back.RESET + Fore.CYAN + "\tTesting %s integrity" % profile)

TestIntegrity(profile)

if os.path.exists(redhat) :

	OpenAndPrint(bashrc)

	print(Back.RESET + Fore.CYAN + "\tTesting %s integrity" % bashrc)

	TestIntegrity(bashrc)

else:
	
	OpenAndPrint(bashrcdebian)

	print(Back.RESET + Fore.CYAN + "\tTesting %s integrity" % bashrcdebian)

	TestIntegrity(bashrcdebian)

WalkAndTest(profiledir, True)

WalkAndTest(skeldir, True)			

print(Back.RESET + Fore.YELLOW + "\tTesting if /home's rc files are equal than skel dir")

listOfFile = os.listdir("/home/")
allFiles = list()

for entry in listOfFile:
	fullPath = os.path.join("/home/", entry)
	if os.path.isdir(fullPath):
		
		rcfile = fullPath+"/.bashrc"
		rcprofile = fullPath + "/.bash_profile"
		rclogout = fullPath + "/.bash_logout"
		
		if os.path.isfile(rcfile):
			
			CompareRC(rcfile, '/etc/skel/.bashrc')
		
		if os.path.isfile(rcprofile):
			
			CompareRC(rcprofile, '/etc/skel/.bash_profile')
				
		if os.path.isfile(rclogout):
			
			CompareRC(rclogout, '/etc/skel/.bash_logout')

CompareRC('/root/.bashrc', '/etc/skel/.bashrc')
CompareRC('/root/.bash_profile', '/etc/skel/.bash_profile')
CompareRC('/root/.bash_logout', '/etc/skel/.bash_logout')


print(Back.RESET + Fore.YELLOW + "[*Searching X system startup files*]\n")		

listOfFile = os.listdir("/home/")
allFiles = list()

for entry in listOfFile:
	fullPath = os.path.join("/home/", entry)
	if os.path.isdir(fullPath):
		
		xstartup = fullPath+"/.config/autostart/"
		xinitrcs = fullPath+"/.xinitrc"
		
		if os.path.isfile(xinitrcs):
			
			OpenAndPrint(xinitrcs)
		
		if os.path.isdir(xstartup):
			
			WalkAndTest(xstartup)
			
if os.path.isfile("/root/.xinitrc/"):
			
	OpenAndPrint("/root/.xinitrc/")
		
if os.path.isdir("/root/.config/autostart/"):
			
	WalkAndTest("/root/.config/autostart/")
			
			
print(Back.RESET + Fore.YELLOW + "[*Listing active Systemd Units*]\n")			

systemdmulti = "/lib/systemd/system/multi-user.target.wants/"
systemdmulti2 = "/etc/systemd/system/multi-user.target.wants/"

systemdgrap = "/lib/systemd/system/graphical.target.wants/"
systemdgrap2 = "/etc/systemd/system/graphical.target.wants/"

systemdlogoffRH = "/usr/lib/systemd/system-shutdown/"
systemdlogoffDeb = "/lib/systemd/system-shutdown/"

WalkAndTest(systemdmulti, True)
WalkAndTest(systemdmulti2, True)

WalkAndTest(systemdgrap, True)
WalkAndTest(systemdgrap2, True)

if os.path.exists(debian) :
	
	WalkAndTest(systemdlogoffDeb, True)
	
else :
	
	WalkAndTest(systemdlogoffRH, True)			
			

listOfFile = os.listdir("/home/")
allFiles = list()

for entry in listOfFile:
	fullPath = os.path.join("/home/", entry)
	if os.path.isdir(fullPath):
		
		usersystemd = fullPath+"/.config/systemd/user/"
		
		if os.path.isdir(usersystemd):
			
			WalkAndTest(usersystemd)

if os.path.isdir("/root/.config/systemd/user/"):	
				 
	WalkAndTest("/root/.config/systemd/user/")
			
print(Back.RESET + Fore.YELLOW + "[*Listing Systemd Timer Units*]\n")		

timerdir = '/usr/lib/systemd/system/'
timerdir2 = '/lib/systemd/system/' 

if os.path.isdir(timerdir):
	
	for file in os.listdir(timerdir):
    	
		if file.endswith(".timer"):
        
			servicech = re.sub('timer', 'service', file)
		
			servicech = timerdir+servicech
		
			OpenAndPrint(servicech)
			TestIntegrity(servicech)			

if os.path.isdir(timerdir2):

	for file in os.listdir(timerdir2):
    	
		if file.endswith(".timer"):
        
			servicech = re.sub('timer', 'service', file)
		
			servicech = timerdir2+servicech
		
			OpenAndPrint(servicech)
			TestIntegrity(servicech)			









