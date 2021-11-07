import colorama
from colorama import init
init()
from colorama import Fore, Back, Style
import os
import re
import subprocess
import filecmp
import re
import argparse
from os import walk



ap = argparse.ArgumentParser()

ap.add_argument('--triage', dest='triage', action='store_true')
ap.add_argument("--all", dest='allinfo', action='store_true')

args = ap.parse_args()

debian = '/etc/debian_version'
redhat = '/etc/redhat-release'

def TestIntegrity(File):
	
	if os.path.exists(redhat) : 
	
		command = 'rpm -Vf "'+File+'"' 
					
		processrpm = subprocess.Popen([command], stdout=subprocess.PIPE,shell=True)
		outputrpm = processrpm.communicate()[0]
					
		if outputrpm :
			
			print(Back.RESET + Fore.CYAN + "\tTesting %s integrity\n" % File)			
			print(Back.RESET + Fore.RED + "Integrity compromised\n")
								
		
		if not outputrpm and args.allinfo:
			
			print(Back.RESET + Fore.CYAN + "\tTesting %s integrity\n" % File)
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
				
				print(Back.RESET + Fore.CYAN + "\tTesting %s integrity\n" % File)			
				print(Back.RESET + Fore.RED + "Integrity compromised\n")
				return(0)
								
				
		packagename = outputdpkg.split(":")
						
		commandDEBSUM = 'dpkg --verify "'+packagename[0]+'"'
						
							
		processdebsum = subprocess.Popen([commandDEBSUM], stdout=subprocess.PIPE,shell=True)
		outputdebsum = processdebsum.communicate()[0]
		
		print (outputdebsum)
						
		if outputdebsum :
			
			print(Back.RESET + Fore.CYAN + "\tTesting %s integrity\n" % File)
			print(Back.RESET + Fore.RED + "Integrity compromised\n")
						
		if not outputdebsum and args.allinfo:
			
			print(Back.RESET + Fore.CYAN + "\tTesting %s integrity\n" % File)
			print(Back.RESET + Fore.GREEN + "Integrity OK\n")
						
		

def OpenAndPrint(File) :
	
	filetoprint = open(File, "r")

	print(Back.RESET + Fore.CYAN + "\t%s content :\n" % File)

	for lines in filetoprint.readlines():
	
		print(Back.RESET + Fore.GREEN + "%s" % lines)
	

def WalkAndTest(Dir, Int=False, Print=False):
	
	filesdir = []
	
	for r, d, f in os.walk(Dir):
		for file in f:
			
			filesdir.append(os.path.join(r, file))
		
		for f in filesdir:
			
			filereal = os.path.realpath(f)
			
			if os.path.isfile(filereal): 
		
				if Print:
					
					OpenAndPrint(filereal)	

				if Int:
					
					TestIntegrity(filereal)


def CompareRC(File, DestFile):
	
	if os.path.isfile(File):
	
		if not filecmp.cmp(File, DestFile):
				
			print(Back.RESET + Fore.RED + "%s Integrity compromised\n" % File)
		
			if args.allinfo :
				OpenAndPrint(File)
		
	

print(Back.RESET + Fore.GREEN + "RcLocals 2.0")
print(Back.RESET + Fore.GREEN + "https://github.com/YJesus/RCLocals\n")
		

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
	
	commandRPMPACK = r'rpm -qa --qf "%{INSTALLTIME:date} %{name}-%{version}-%{release}.%{arch} %|DSAHEADER?{%{DSAHEADER:pgpsig}}:{%|RSAHEADER?{%{RSAHEADER:pgpsig}}:{%|SIGGPG?{%{SIGGPG:pgpsig}}:{%|SIGPGP?{%{SIGPGP:pgpsig}}:{(none)}|}|}|}|\n"'
									
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
			
			match = re.search(r'.*\d\s(.{4})\s\d.*\s*\s(\/.*)' , libs)
            
			if match:
                
				matchexe = re.search(r'.*x.*', match.group(1))
				matchrwx = re.search(r'rwx.*', match.group(1))
                
			if  match and matchrwx:
                
				print(Back.RESET + Fore.RED + "Suspicious memory region in process %s in PID %s" % (match.group(2), processPid))
								
				exefile = '/proc/'+processPid+'/exe'
				exepath = os.path.realpath(exefile)
				print(Fore.RED + "Exefile %s\n" % exepath)
				continue 
            
			if  match and matchexe:

				isdeleted = re.search(r'\(deleted\)' , match.group(2))
				
				if not isdeleted:
                    
					if os.path.exists(redhat) : 
						command = 'rpm -Vf "'+match.group(2)+'"' 
					
						processrpm = subprocess.Popen([command], stdout=subprocess.PIPE,shell=True)
						outputrpm = processrpm.communicate()[0]
					
						if outputrpm :

							thisfile = re.search(match.group(2), outputrpm.decode('utf-8'))
						
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
								

print(Back.RESET + Fore.YELLOW + "[*Searching process with name spoofed*]\n")
				
for processPid in os.listdir("/proc"):
	
	comm = '/proc/'+processPid+'/comm'
	
	if os.path.exists(comm) : 
		
		file = open(comm, "r")
		
		commbin = file.read().replace('\n', '')
		
		exefile = '/proc/'+processPid+'/exe'
		try:
			exepath = os.path.realpath(exefile)
		
		except:
			pass
			
		else:
			
			exetest = os.path.basename(exepath)
			
			if commbin !=  exetest[0:15] :
				
				print(Back.RESET + Fore.RED + "Process name [%s]  it's not equal than exe name [%s] PID: %s \n" % (commbin, exepath, processPid) )

										
print(Back.RESET + Fore.YELLOW + "[*Searching CRON entries*]\n")

anacron = "/etc/anacrontab"
crontab = "/etc/crontab"
crondir = "/etc/cron.d/"
cronspool = "/var/spool/cron"
cronspooldebian = "/var/spool/cron/crontabs/"

if os.path.exists(anacron) : 

	if args.allinfo :
		OpenAndPrint(anacron)
	
	TestIntegrity(anacron)
	
if args.allinfo :
	OpenAndPrint(crontab)
	

TestIntegrity(crontab)


if os.path.exists(crondir) :  
	
	WalkAndTest(crondir, True, args.allinfo)

if os.path.exists(cronspool) :  
	
	WalkAndTest(cronspool, False, True)
			
if os.path.exists(cronspooldebian) :  
	
	WalkAndTest(cronspooldebian, False, True)
	
print(Back.RESET + Fore.YELLOW + "[*Searching RC files*]\n")

profile = "/etc/profile"
bashrc = "/etc/bashrc"
bashrcdebian = "/etc/bash.bashrc"
profiledir = "/etc/profile.d/"
skeldir ="/etc/skel/"
homedir = "/home/"

if args.allinfo :
	OpenAndPrint(profile)
	
TestIntegrity(profile)

if os.path.exists(redhat) :

	if args.allinfo :
		OpenAndPrint(bashrc)

	TestIntegrity(bashrc)

else:
	
	if args.allinfo :
		OpenAndPrint(bashrcdebian)

	TestIntegrity(bashrcdebian)

WalkAndTest(profiledir, True, args.allinfo)

WalkAndTest(skeldir, True, args.allinfo)			

print(Back.RESET + Fore.YELLOW + "\tTesting if /home's rc files are equal than skel dir\n")

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
			
			WalkAndTest(xstartup, False, True)
			
if os.path.isfile("/root/.xinitrc/"):
			
	OpenAndPrint("/root/.xinitrc/")
		
if os.path.isdir("/root/.config/autostart/"):
			
	WalkAndTest("/root/.config/autostart/", False, True)
			
			
print(Back.RESET + Fore.YELLOW + "[*Listing active Systemd Units*]\n")			

systemdmulti = "/lib/systemd/system/multi-user.target.wants/"
systemdmulti2 = "/etc/systemd/system/multi-user.target.wants/"

systemdgrap = "/lib/systemd/system/graphical.target.wants/"
systemdgrap2 = "/etc/systemd/system/graphical.target.wants/"

systemdlogoffRH = "/usr/lib/systemd/system-shutdown/"
systemdlogoffDeb = "/lib/systemd/system-shutdown/"

WalkAndTest(systemdmulti, True, args.allinfo)
WalkAndTest(systemdmulti2, True, args.allinfo)

WalkAndTest(systemdgrap, True, args.allinfo)
WalkAndTest(systemdgrap2, True, args.allinfo)

if os.path.exists(debian) :
	
	WalkAndTest(systemdlogoffDeb, True, args.allinfo)
	
else :
	
	WalkAndTest(systemdlogoffRH, True, args.allinfo)			
			

listOfFile = os.listdir("/home/")
allFiles = list()

for entry in listOfFile:
	fullPath = os.path.join("/home/", entry)
	if os.path.isdir(fullPath):
		
		usersystemd = fullPath+"/.config/systemd/user/"
		
		if os.path.isdir(usersystemd):
			
			WalkAndTest(usersystemd, False, True)

if os.path.isdir("/root/.config/systemd/user/"):	
				 
	WalkAndTest("/root/.config/systemd/user/", False, True)
			
print(Back.RESET + Fore.YELLOW + "[*Listing Systemd Timer Units*]\n")		

timerdir = '/usr/lib/systemd/system/'
timerdir2 = '/lib/systemd/system/' 

if os.path.isdir(timerdir):
	
	for file in os.listdir(timerdir):
    	
		if file.endswith(".timer"):
        
			servicech = re.sub('timer', 'service', file)
		
			servicech = timerdir+servicech
		
			if args.allinfo :
				OpenAndPrint(servicech)
			
			TestIntegrity(servicech)			

if os.path.isdir(timerdir2):

	for file in os.listdir(timerdir2):
    	
		if file.endswith(".timer"):
        
			servicech = re.sub('timer', 'service', file)
		
			servicech = timerdir2+servicech
		
			if args.allinfo :
				OpenAndPrint(servicech)
			
			TestIntegrity(servicech)			


print(Back.RESET + Fore.YELLOW + "[*Searching tmpfiles.d*]\n")

etctmpfile = "/etc/tmpfiles.d/"
runtmpfile = "/run/tmpfiles.d/"
usertmpfile = "/usr/lib/tmpfiles.d/"

WalkAndTest(etctmpfile, True, args.allinfo)
WalkAndTest(runtmpfile, True, args.allinfo)
WalkAndTest(usertmpfile, True, args.allinfo)

listOfFile = os.listdir("/home/")
allFiles = list()

for entry in listOfFile:
	fullPath = os.path.join("/home/", entry)
	if os.path.isdir(fullPath):
		
		usertmpfiles = fullPath+"/.config/user-tmpfiles.d/"
		usertmpfiles2 = fullPath+"/.local/share/user-tmpfiles.d/"
		
		if os.path.isdir(usertmpfiles):
			
			WalkAndTest(usertmpfiles, False, True)
			
		if os.path.isdir(usertmpfiles2):
			
			WalkAndTest(usertmpfiles2, False, True)
			
	
print(Back.RESET + Fore.YELLOW + "[*Searching linger users*]\n")

lingerpath= "/var/lib/systemd/linger"

if os.path.exists(lingerpath):
    
	lingerusers = next(walk(lingerpath), (None, None, []))[2]
	print(Back.RESET + Fore.RED + "Linger users: %s\n" % lingerusers)    







