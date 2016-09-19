######################################################
## Python script to get Zertificate out of emails
## Protocol: IMAP
## Python 2.7.3

import imaplib
import ConfigParser
import os
import re
import email
import subprocess
import random
import MySQLdb
import sys
import datetime

#PATH TO CONFIG:
path_to_config = "~/Desktop/config.conf"


list_response_pattern = re.compile(r'\((?P<flags>.*?)\) "(?P<delimiter>.*)" (?P<name>.*)')

#make response of mail server pretty

def parse_list_response(line):
    flags, delimiter, mailbox_name = list_response_pattern.match(line).groups()
    mailbox_name = mailbox_name.strip('"')
    return (flags, delimiter, mailbox_name)

def log_file():
    # Read the config file
    config = ConfigParser.ConfigParser()
    config.read([os.path.expanduser(path_to_config)])

    writepath = config.get('loging','log_file')
    log_level = config.get('loging','log_level')
    try:
	file=open(writepath, 'a')
	file.close()
	state=True
    except:
	print "No file or permission problem"

    return (state)


def write_log(mtype,msg):
    if(log_file()):
    	# Read the config file
    	config = ConfigParser.ConfigParser()
    	config.read([os.path.expanduser(path_to_config)])

    	writepath = config.get('loging','log_file')
    	log_level = config.get('loging','log_level')
    	time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    	if(int(mtype)<=int(log_level)):
		f=open(writepath,'a')
		f.write(time+":  " + msg+"\n")
		f.close()
    		#print time,msg
    return (True)

def open_connection(verbose=False):
    # Read the config file
    config = ConfigParser.ConfigParser()
    config.read([os.path.expanduser(path_to_config)])

    # Connect to the server
    hostname = config.get('server', 'hostname')
    write_log(2,"Connecting to, "+hostname)
    try:
        connection = imaplib.IMAP4_SSL(hostname)
    except:
	write_log(1,"Problem with name: "+hostname)
	sys.exit()

    # Login to our account
    username = config.get('account', 'username')
    password = config.get('account', 'password')
    write_log(2,"Connecting to Email account")
    try:
     	connection.login(username, password)
    except:
	write_log(1,"Problem with login: username/password  ")
	sys.exit()
    return connection


def read_conf(part,item):
    # Read the config file
    config = ConfigParser.ConfigParser()
    config.read([os.path.expanduser(path_to_config)])
    val=config.get(part,item)
    return val


def open_DB_connection(verbose=False):
    # Read the config file
    config = ConfigParser.ConfigParser()
    config.read([os.path.expanduser(path_to_config)])

    write_log(2,"Opening DB connection")
    host=config.get('mysql', 'server')
    user=config.get('mysql', 'user')
    passwd=config.get('mysql', 'pw')
    db=config.get('mysql', 'db')

    try:
	db = MySQLdb.connect(host,user,passwd,db)
	return db
    except:
	write_log(1,"Problem with login: username/password/server/database  ")
	sys.exit()





def getAttachment(msg,check,x):
	# go though every Part of the mail
 	for part in msg.walk():
		#print part
		#compare with filetype we need
		if x=="pgp":
			if (part.get_content_type() == 'application/pgp-keys') or (part.get_content_type() == 'application/octet-stream') or (part.get_content_type() == 'text/plain'):
				if str(part.get('Content-Disposition')).startswith("attachment",0,10):
					if len(part.get_payload()) <= read_conf("email","max_key_size"):
						if check(part.get_filename()):
							write_log(3,"Found PGP-like attachment ")
							#print "pgp: "+part.get_filename()
							return part.get_payload(decode=1)

		elif x=="smime":
			if part.get_content_type() == 'application/pkcs7-signature':
				if str(part.get('Content-Disposition')).startswith("attachment",0,10):
					if len(part.get_payload()) <= read_conf("email","max_key_size"):
						if check(part.get_filename()):
							write_log(3,"Found Smime-like attachment ")
							#print "smime: "+part.get_filename()
							return part.get_payload(decode=1)
		else:
			return ""


if __name__ == '__main__':
	log_file()
	write_log(1,"-----------------------------------------------------------")
	c = open_connection()
	try:
		fromMsg=[]
		pgpZertificate=[]
		smimeZertificate=[]
		Ztype=[]
		Zertificate=[]
		tmpf = read_conf("loging","temp_folder")
		write_log(3,"Looking through mailboxes")
		# get all from the INBOX
		mailbox=read_conf("server","mailbox")
		typ, mailbox_data = c.list(directory=mailbox)
		if(mailbox_data[0]==None):
			write_log(1,"No mailbox found with name: "+mailbox)
			sys.exit()
		# go though every response of INBOX
		for line in mailbox_data:
			flags, delimiter, mailbox_name = parse_list_response(line)
			c.select(mailbox_name, readonly=False)
			# only get mail id with subject "Config_defined_"
			subject=read_conf("email","subject")
			write_log(3,"Looking for unread mail with subject: "+subject)
			typ, msg_ids = c.search(None, '(SUBJECT "%s")' % subject,('UNSEEN'))
			#print typ[0]
			#print msg_ids[0]
			#split list into usable list to go tough found mail
			mail_ids=''.join(msg_ids)
			mail_ids=mail_ids.split()
			write_log(3,str(len(mail_ids)) + " Email(s) found")

			for number in mail_ids:
				write_log(3,"Processing Mail No. "+str(mail_ids.index(number)+1))
				count=0
	        		#print "---------------------------"+number+"---------------------------------------"
	    		   	typ, msg_data = c.fetch(number, '(RFC822)')
				msgg=email.message_from_string(msg_data[0][1])
				smime = getAttachment(msgg,lambda x: x.endswith('.p7s'),"smime")
				pgp = getAttachment(msgg,lambda x: x.endswith('.asc'),"pgp")
	 			#c.copy(number, 'Trash')
				if smime:
					tempSname =  str(random.getrandbits(32))+"TEMPZERT"

					tempfile=open(tmpf+tempSname,'wb')
					tempfile.write(smime)
					tempfile.flush()
					tempfile.close()
					tempSCname=tmpf+tempSname
					try:
						smime = subprocess.check_output('/usr/bin/openssl pkcs7 -inform der -print_certs -in %s' % tempSCname,shell=True)
						write_log(3,"Smimekey is Valid")
						count+=1
						Ztype.append("smimekey")
						Zertificate.append(smime)
						os.remove(tempSCname)
					except:
						write_log(3,"Smimekey not Valid")


				if pgp:
					tempPname =  str(random.getrandbits(32))+"TEMPZERT"

					tempPfile=open(tmpf+tempPname,'wb')
					tempPfile.write(pgp)
					tempPfile.flush()
					tempPfile.close()
					tempPCname=tmpf+tempPname
					try:
						gpg = subprocess.check_output('/usr/bin/gpg --with-fingerprint %s 2>/dev/null' % tempPCname,shell=True)
						testZertP= str(gpg).split()
						write_log(3,"PGPkey is Valid")
					except:
						write_log(3,"PGPkey not Valid")
						testZertP="NULL"

					if testZertP != "NULL":
						count+=1
						Ztype.append("pgpkey")
						Zertificate.append(pgp)
					os.remove(tempPCname)


				for ints in range(0,count):
		            		typ, msg_dataName = c.fetch(number, '(BODY.PEEK[HEADER])')
					for response_part in msg_dataName:
						if isinstance(response_part, tuple):
							msg = email.message_from_string(response_part[1])["from"]
							msg=msg.split()[-1].split(">")[0][1:].lower()

							#msg=msg.split()[-1].split("@")[0][1:].lower()
							fromMsg.append(msg)
			if mail_ids:
				typ, response = c.store(mail_ids[0], '+FLAGS', r'(\SEEN)')

			write_log(2,"Cleaning Up and closing Email account")

	finally:
		try:
	        	c.close()
		except:
	        	pass
		c.logout()
	##################################### MYSQL QUERRYS #####################################
	## fromMsg   -  Email address list
	## Zertificate  - Zertificate list
	if len(fromMsg)==0:
		sys.exit()

	db = open_DB_connection()
	cur = db.cursor()
	indx=0
	now = datetime.datetime.now()
	dbtable =read_conf("mysql","table")
	date = now.strftime("%Y-%m-%d")
	for items in fromMsg:
		write_log(3,"Building Querrys for %s" % items)
		if Ztype[indx]=="pgpkey":
			squery = ("Select count(email) from " + dbtable + " WHERE email='"+fromMsg[indx]+"';" )
			#print squery
			try:
				cur.execute(squery)
			except:
				write_log(1,"Problem with: "+squery)

			if cur.fetchone()[0] == 0:
				cur.execute("INSERT INTO "+read_conf("mysql","table")+" SET email='"+fromMsg[indx]+"',smimekey='',date='"+date+"',pgpkey=\'"+Zertificate[indx].encode('base64')+"\';")
			else:
				cur.execute("Update "+read_conf("mysql","table")+" SET pgpkey=\'"+Zertificate[indx].encode('base64')+"\' where email='"+fromMsg[indx]+"';")
		elif Ztype[indx]=="smimekey":
			squery = ("Select count(email) from zertifikat WHERE email='"+fromMsg[indx]+"';" )
			try:
				cur.execute(squery)
			except:
				write_log(1,"Problem with: "+squery)
			#print cur.fetchone()[0]
			if cur.fetchone()[0] == 0:
				cur.execute("INSERT INTO "+read_conf("mysql","table")+" SET email='"+fromMsg[indx]+"',pgpkey='',date='"+date+"',smimekey=\'"+Zertificate[indx].encode('base64')+"\';")
			else:
				cur.execute("Update "+read_conf("mysql","table")+" SET smimekey=\'"+Zertificate[indx].encode('base64')+"\' where email='"+fromMsg[indx]+"';")
		indx+=1
	write_log(2,"Commiting Querrys and closing connection")
	db.commit()
	cur.close()
	db.close()