#!/usr/bin/env python
import glob
import ldap
import cgi
import MySQLdb
import os,sys
import hashlib
import argparse
import configparser
from jinja2 import Template
from lxml import etree, objectify
from shutil import copyfile
from subprocess import call
from MySQLdb.cursors import DictCursor


class ConfigurationError(Exception):
	pass
		
main_parameters_keys = ["backend", "user_template_path", "storage_login_type", "storage_login", "storage_password", "storage_host", "user_pass_field", "user_template_path"]

param_dependencies = {
	"backend" : {
		"freepbx" : ["freepbx_mysql_host", "freepbx_mysql_user", "freepbx_mysql_pass", "freepbx_mysql_db"],
		"asterisk" : ["sip_filepath",]
	},
	"storage" : {
		"freeipa" : ["storage_domain",]
	},
	"create_autoprov" : {
		"1" : ["prov_data_file",]
	}
}

default_main_parameters = {
	"backend" : "asterisk",
	"reload" : True,
	"header_template_path" : "/home/project/sip_header_template",
	"user_template_path" : "/home/project/sip_user_template_asterisk",
	"sip_filepath" : "%s/sip.conf" % os.getcwd(),
	"freepbx_mysql_port" : None,
	"create_phonebooks" : 0,
	"phonebook_template_dir" : "%s/pb_templates" % os.getcwd() if os.path.isdir("%s/pb_templates" % os.getcwd()) else None,
	"phonebook_output_dir" : "%s/pb_out" % os.getcwd(),
	"create_autoprov" : 0,
	"autoprov_template_dir" : "%s/ap_templates" % os.getcwd() if os.path.isdir("%s/ap_templates" % os.getcwd()) else None,
	"autoprov_output_dir" : "%s/pb_out" % os.getcwd(),
	"users_pass_field" : "employeeNumber",
	"users_group" : None,
	"hosts_group" : None,
	"hbac_service_name" : None
}

default_pb_vars = {"accountindex" : 1, "group" : 1, "xver" : "1.0", "encoding" : "UTF-8"}

default_ap_name_mapping = {
	"grandstream" : "cfgMAC.xml",
	"d-link" : "MAC.cfg"
}
default_ap_vars = {
	"xver" : "1.0",
	"encoding" : "UTF-8",
	"admin_password" : "headshot",
	"conf_file_method" : "0",
	"config_server_address" : "config.address.ru",
	"display_language" : "ru",
	"sip_account1_server" : "172.23.6.100",
	"sip_account1_reg_expiration" : "60",
	"sip_account1_localsipport" : "5060",
	"time_format" : "1",
	"enable_phonebook" : "1",
	"phonebook_xml_server" : "172.23.6.100",
	"phonebook_source_path" : "",
	"phonebook_source_type" : "1",
	"phonebook_download_interval" : "5",
	"phonebook_remove_old" : "1"
}


def check_parameters(parameters, main_parameters_keys, param_dependencies, filepath):
	for mp in main_parameters_keys:
		if not parameters.get(mp):
			raise ConfigurationError("%s parameter is mandatory. You MUST specify it inside %s" % (mp, filepath))
	for p,p_dep in param_dependencies.iteritems():
		parameter = parameters.get(p)
		if not parameter:
			continue
		elif not parameter in p_dep.keys():
			raise ConfigurationError("%s is invalid value for %s parameter. Valid are %s. Correct them in %s" % (str(parameter), str(p), ",".join(p_dep.keys()), filepath))
		else:
			received_params = [ parameters[prm] for prm in p_dep.get(parameter) if parameters.get(prm)]
			if len(received_params) < len(p_dep.get(parameter)):
				raise ConfigurationError("If %s value for %s parameter was specified, additionally %s MUST be specified. Correct it in %s" % (str(parameter), str(p), ",".join(p_dep.get(parameter)), filepath))
	return

def get_ap_mappings(hosts, template_dir, default_ap_name_mapping, default_ap_vars, filepath=None):
	file_mapping = None
	if filepath:
		file_mapping = parse_mapping_file(filepath, template_dir)

	ap_dir_exists=False
	if template_dir and os.path.isdir(template_dir):
		ap_dir_exists=True

	mapping = {}
	data_mapping = {}
	for host in hosts:
		mac = host[3].replace(":","").lower()
		platform = host[4]

		host_template = None
		host_xml_filename = None
		host_data_filename = None
		if ap_dir_exists and os.path.exists("%s/%s.tpl" % (template_dir, mac)):
			host_template = "%s/%s.tpl" % (template_dir, mac)
		if ap_dir_exists and os.path.exists("%s/%s.data" % (template_dir, mac)):
			host_data_filename = "%s/%s.data" % (template_dir, mac)
		if (not host_template or not host_data_filename or not host_xml_filename) and file_mapping and file_mapping.get(platform):
			cur_mapping = file_mapping.get(platform)
			host_template = host_template if host_template else cur_mapping["template_file"]
			host_data_filename = host_data_filename if host_data_filename else cur_mapping["data_file"]
			host_xml_filename = cur_mapping["xmlfile"]
		if not host_xml_filename and default_ap_name_mapping and default_ap_name_mapping.get(platform):
			host_xml_filename = default_ap_name_mapping.get(platform)
		if not host_data_filename and default_ap_vars:
			host_data_filename = "def_script_data_hhh"
		if not host_template or not host_data_filename or not host_xml_filename:
			print "For device with mac-address %s, platform type %s template filename was not found. You should update mapping for autoprovisioning. Skipping..." % (mac, platform)
			continue
		mapping[mac] = {
			"template_file" : host_template,
			"xmlfile" : host_xml_filename,
			"data_file" : host_data_filename
		}
		if not host_data_filename in data_mapping.keys():
			if host_data_filename == "def_script_data_hhh":
				data_mapping["def_script_data_hhh"] = default_ap_vars
			data_mapping[host_data_filename] = parse_template(host_data_filename, True)

	return mapping,data_mapping

def generate_autoprov(hosts, template_dir, output_dir, default_ap_name_mapping, default_ap_vars, filepath):
	mapping,data_mapping = get_ap_mappings(hosts, template_dir, default_ap_name_mapping, default_ap_vars, filepath)
	common_tpl = glob.glob("%s/common*.tpl" % template_dir)
	for tpl in common_tpl:
		ofile = os.path.join(output_dir,"%s.xml" % os.path.splitext(tpl)[0])
		generate_xml_from_tpl(default_ap_vars, tpl, ofile)
	for hostdata in hosts:

		mac = hostdata[3].replace(":","").lower()
		map_data = mapping.get(mac)
		if not map_data:
			continue
		platform = hostdata[4]

		data_file = map_data["data_file"]
		data = data_mapping.get(data_file)
		data['sip_accoun1_userid'] = hostdata[0].decode("utf8")
		data['sip_accoun1_authid'] = hostdata[0].decode("utf8")
		data['sip_account1_password'] = hostdata[1].decode("utf8")
		data['sip_account1_display_name'] = hostdata[2].decode("utf8")

		ofilename = map_data.get("xmlfile").replace("MAC", mac)

		ofilepath = os.path.join(output_dir, ofilename)
		generate_xml_from_tpl(data, map_data["template_file"], ofilepath)
	return


def check_if_tpl_exists(filename, template_dir):
	if os.path.isabs(filename) and os.path.exists(filename):
		return filename
	elif os.path.exists("%s/%s" % (template_dir,filename)):
		return os.path.abspath("%s/%s" % (template_dir,filename))
	print "Template file for %s is absent" % filename
	return False

def parse_mapping_file(filepath, template_dir):
	valid_keys=["template_file", "xmlfile", "data_file"]
	mapping = {}
	with open(filepath, "r") as file:
		config =configparser.ConfigParser()
		config.read_file(file, filepath)
		for section_key in config.sections():
			section = config[section_key]
			map_elem = {}
			for key in section.keys():
				if not key in valid_keys:
					continue
				value = section.get(key)
				if key in ["template_file", "data_file"]:
					value = check_if_tpl_exists(value, template_dir)
				if value:
					map_elem[key] = value
			if set(valid_keys) == set(map_elem.keys()):
				mapping[section_key] = map_elem

	return mapping


def read_config(filepath):
	parameters = {}
	with open(filepath, "r") as file:
		for line in file.readlines():
			line_elem = line.split("=", 1)
			if line[0] in ["#", ";", "\n"]:
				continue
			elif len(line_elem) < 2:
				continue
			else:
				parameters[line_elem[0].strip()] = line_elem[1].strip("\n").strip()
	return parameters

def build_parameters(filepath, default_prm):
	prm = read_config(filepath)
	add_parameters = { k : v for k,v in default_prm.iteritems() if not k in prm.keys() }
	prm.update(add_parameters)
	return prm

def login_is_simple(login):
	return True if login.find("dc=") == -1 else False

def get_dn_fromdomain(ipa_domain):
	return "dc=" + ",dc=".join(ipa_domain.split(".")).strip(",")

def create_baseDN(ipa_domain):
	dpart = get_dn_fromdomain(ipa_domain)
	baseDN = "cn=users,cn=accounts,%s" % dpart 
	return baseDN

def connect_ipa(login, passw, ipa_domain, host, port=None, ssl=False):
	conn_str = "ldap://%s" % host if not port else "ldap://%s:%s" % (host, port)
	conn=ldap.initialize(conn_str)
	username="uid=%s,cn=users,cn=accounts,%s" % (login, get_dn_fromdomain(ipa_domain)) if login_is_simple(login) else login
	conn.simple_bind_s(username, passw)
	return conn


def ldap_search(conn, baseDN, scope=ldap.SCOPE_ONELEVEL, filterstr=None, attrs=None, attrkey = None):
	result_id = conn.search(baseDN,ldap.SCOPE_ONELEVEL, filterstr=filterstr, attrlist=attrs)
	results = []
	while True:
		type, datablock = conn.result(result_id, 0)
		if not datablock:
			break
		results.append(datablock)
	if attrkey == 'PRIMARY':
		data = { v[0][0]:v[0][1] for v in results}
	elif attrkey != None:
		data = { v[0][1][attrkey][0]:v[0][1] for v in results}
	else:
		data = results
	return data

def get_ipa_users(conn, ipa_domain, baseDN=None, group=None, pass_field='employeeNumber'):
	baseDN = "cn=users,cn=accounts,%s" % get_dn_fromdomain(ipa_domain) if not baseDN else baseDN
	groupfilter = "(memberOf=cn=%s,cn=groups,cn=accounts,%s)" % (group,get_dn_fromdomain(ipa_domain)) if group else ""
	filterstr="(&(objectClass=person)%s(!(nsaccountlock=TRUE)))" % groupfilter
	raw_users = ldap_search(conn,baseDN,ldap.SCOPE_ONELEVEL,filterstr,attrkey="PRIMARY")
	users = {}
	for user,udata in raw_users.iteritems():
		name = udata.get('displayName')[0] if udata.get('displayName') else udata.get('cn')[0]
		cn = udata.get('uid')[0]
		phone = udata.get('telephoneNumber')[0] if udata.get('telephoneNumber') else  None
		password = udata.get(pass_field)[0] if udata.get(pass_field) else  None
		usergroups = udata.get('memberOf')
		if phone and password:
			users[phone] = (cn,name,password,usergroups)
	return users

def get_ipa_hosts(conn, ipa_domain, baseDN=None, hostgroup=None):
	baseDN = "cn=computers,cn=accounts,%s" % get_dn_fromdomain(ipa_domain) if not baseDN else baseDN
	hg_filter = "(memberOf=cn=%s,cn=hostgroups,cn=accounts,%s)" % (hostgroup,get_dn_fromdomain(ipa_domain)) if hostgroup else ""
	filterstr="(&(objectClass=ipahost)%s)" % hg_filter
	hosts = ldap_search(conn,baseDN,ldap.SCOPE_ONELEVEL,filterstr,attrkey="fqdn", attrs=["fqdn","memberOf","macAddress","nsHardwarePlatform"])
	return hosts

def get_ipa_hbac_rules(conn, ipa_domain, baseDN=None, service_name=None):
	baseDN = "cn=hbac,%s" % get_dn_fromdomain(ipa_domain) if not baseDN else baseDN
	hbr_filter="(memberService=cn=%s,cn=hbacservices,cn=hbac,%s)" % (service_name,get_dn_fromdomain(ipa_domain)) if service_name else ""
	filterstr="(&(objectClass=ipahbacrule)(accessRuleType=allow)(ipaEnabledFlag=TRUE)%s)" % hbr_filter
	rules = ldap_search(conn,baseDN,ldap.SCOPE_ONELEVEL,filterstr,attrkey="PRIMARY", attrs=["ipaUniqueID","memberUser", "memberHost"])
	return rules

def get_data_from_ipa(login, passw, ipa_domain, host, port=None, baseDN=None, ssl=False):
	conn = connect_ipa(login, passw, ipa_domain, host)
	users = get_ipa_users(conn, ipa_domain, group=ipa_users_group, pass_field=ipa_user_pass_field)
	return users


def connect_mysql(login, password, db, host="localhost", port=3306):
	connector = MySQLdb.connect(host=host, user=login, password=password, port=port, db=db)
#	cursor = connector.cursor(Dictcutsor)
	cursor = connector.cursor()
	return connector, cursor


def mysql_user_exists(cursor, user):
	rez = cursor.execute("""SELECT extension from users where extension=%s""" % user)
	return True if rez else False

def delete_user_mysql(cursor, phone):
	cursor.execute("""DELETE FROM fax_users where user=%s""" % phone)
	cursor.execute("""DELETE FROM sip where id=%s""" % phone)
	cursor.execute("""DELETE FROM devices where id=%s""" % phone)
	cursor.execute("""DELETE FROM users where extension=%s""" % phone)
	return

def get_user_mysql(user, cursor):
	data = {}
	return data

def create_user_mysql(cursor, phone, cn, description, password, params):
	delete_user_mysql(cursor, phone)
	cursor.execute("""INSERT INTO users (extension,name,voicemail,ringtimer,mohclass) VALUES ('%s', '%s', 'novm', 0, 'default')""" % (phone, description))
	cursor.execute("""INSERT INTO devices (id,tech,dial,devicetype,user,description) VALUES ('%s', 'sip', 'SIP/%s', 'fixed', %s, '%s')""" % (phone, phone, phone, description))
	for k,v in params.iteritems():
		vv = v.replace("USR_VAR", phone)
		cursor.execute("""INSERT INTO sip (id,keyword,data) VALUES ('%s', '%s', '%s')""" % (phone, k, vv))
	cursor.execute("""INSERT INTO sip (id,keyword,data) VALUES ('%s', '%s', '%s')""" % (phone, 'md5secret', password))
	cursor.execute("""INSERT INTO sip (id,keyword,data) VALUES ('%s', '%s', '%s')""" % (phone, 'accountcode', cn))
	cursor.execute("""INSERT INTO fax_users (user) VALUES (%s)""" % phone)
	return

def update_user(cursor,phone,old_phone, description):
        cursor.execute("""UPDATE fax_users SET user = %s where user=%s""" % (phone, old_phone))
        cursor.execute("""UPDATE sip SET id = %s, data = %s where id=%s and keyword='account'""" % (phone, phone, old_phone))
        cursor.execute("""UPDATE sip SET id = %s, data = 'device <%s>' where id=%s and keyword='callerid'""" % (phone, phone, old_phone))
        cursor.execute("""UPDATE sip SET id = %s, data = 'SIP/%s' where id=%s and keyword='dial'""" % (phone, phone, old_phone))
        cursor.execute("""UPDATE sip SET id = %s, data = '%s@device' where id=%s and keyword='mailbox'""" % (phone, phone, old_phone))
        cursor.execute("""UPDATE sip SET id = %s where id=%s""" % (phone, old_phone))
        cursor.execute("""UPDATE devices SET id = %s, dial = 'SIP/%s', user = %s, description = '%s' where id=%s""" % (phone,phone,phone,description,old_phone))
        cursor.execute("""UPDATE users SET extension = %s, name = '%s' where extension=%s""" % (phone,description,old_phone))
	return

def get_created_users_mysql(cursor):
	cursor.execute("""SELECT data,id,keyword from sip where data!=''""")
	results = cursor.fetchall()
	accounts = { v[0]:{  vv[2] : vv[0] for vv in results if vv[1] == v[1] and not vv[2] in ['md5secret','accountcode']} for v in results if v[2] == 'accountcode'}
	for result in results:
		if result[2] == 'accountcode' and result[0] in accounts.keys():
			accounts[result[0]]["phone"] = result[1]
	print accounts
	return accounts

def import_data_tomysql(data, cursor, user_template_path):
	dict_data = {}
	if user_template_path and os.path.exists(user_template_path):
		dict_data = parse_template(user_template_path, True)
	dict_data.pop("template", "")
	temp_sip_storage = {}
	persist_users = get_created_users_mysql(cursor)
        for phone,values in data.iteritems():
		cn = values[0]
		description = values[1]
		password = generate_user_password(cn, phone, values[2])
		if cn in persist_users.keys():
			if phone != persist_users[cn]["phone"]:
				print "Pnonenumber %s changes" % phone
				if persist_users[cn]["phone"] not in data.keys():
					delete_user_mysql(cursor, phone)
					old_phone = persist_users[cn]["phone"]
					update_user(cursor,phone,old_phone, description)
#					temp_sip_storage.pop(phone,"")
#				elif phone in temp_sip_storage.keys() and len(temp_sip_storage['phone']) > 0:
#					for row in temp_sip_storage['phone']:
#						cursor.execute("""INSERT INTO sip (id,keyword,data) VALUES ('%s', '%s', '%s')""" % (phone, row[0], row[1]))
#					temp_sip_storage.pop(phone,"")
				else:
#					cursor.execute("""SELECT keyword,data FROM sip where id=%s""" % phone)
#					temp_sip_storage['phone'] = cursor.fetchall()
					delete_user_mysql(cursor, phone)
					create_user_mysql(cursor, phone, values[0], values[1], password, persist_users[cn])
			else:
				cursor.execute("""UPDATE users SET name = '%s' where extension=%s""" % (description,phone))
				cursor.execute("""UPDATE devices SET description = '%s' where id=%s""" % (description,phone))
			cursor.execute("""DELETE FROM sip where id=%s and keyword='md5secret'""" % phone)
			cursor.execute("""INSERT INTO sip (id,keyword,data) VALUES ('%s', '%s', '%s')""" % (phone, 'md5secret', password))
			persist_users.pop(cn,"")
		elif not mysql_user_exists(cursor,phone):
			create_user_mysql(cursor, phone, values[0], values[1], password, dict_data)
	if persist_users:
		for cn,phone in persist_users.iteritems():
			delete_user_mysql(cursor, phone)
						

def parse_template(template_path, strip=False):
	dict_data = {}
	template_found = False
	with open(template_path, 'r') as file:
		for line in file:
			if line[0] == '#' or line[0] == '\n':
				continue
			elif not template_found and line[0] == '[':
				if line.find('(') != -1:
					dict_data['template'] = line.split("]")[1]
				template_found = True
			else:
				values=line.split("=")
				dict_data[values[0]]=values[1] if not strip else values[1].strip("\n")
	return dict_data

def rewrite_file(filepath, source_path):
	if os.path.exists('filepath'):
		os.unlink(filepath)
	copyfile(source_path, filepath)
	return

def generate_user_password(cn, phone, salt, realm='asterisk'):
	passphraze = "%s:%s:%s%s" % (phone, realm, cn, salt)
	pass_hash = hashlib.md5(passphraze).hexdigest()
	return pass_hash

def generate_sip_file(filepath, header_template_path, user_template_path, data):
	if header_template_path and os.path.exists(header_template_path):
		rewrite_file(filepath,header_template_path)
	with open(filepath, 'a') as res_file:
		dict_data = {}
		if user_template_path and os.path.exists(user_template_path):
			dict_data = parse_template(user_template_path)
		res_file.write("\n")
		for phone,values in data.iteritems():
			sip_template = dict_data.get("template")
			user_fields = "[%s]%s\n" % (phone, sip_template or "")
			dict_data.pop("template", "")
			user_fields += "".join([ "%s=%s" % (k, v) for k,v in dict_data.iteritems() ])
			user_fields += "md5secret=%s \n" % generate_user_password(values[0], phone, values[2])
			user_fields += "callerid=%s %s\n" % (values[1], phone)
			user_fields += "\n"
			if sip_template:
				dict_data["template"] = sip_template
			res_file.write(user_fields)
	return

def compare_users_to_hosts(users,hosts,hbac_rules):
	hbacs = hbac_rules.keys()
	host_hbacs = {}
	for host, h_values in hosts.iteritems():
		if not h_values.get('memberOf') or not h_values.get('macAddress') or not h_values.get('nsHardwarePlatform'):
			continue
		chosen_hbac = [ rule for rule in h_values.get('memberOf') if rule in hbacs]
		if not chosen_hbac:
			continue
		host_hbacs[chosen_hbac[0]] = [h_values.get('macAddress')[0],h_values.get('nsHardwarePlatform')[0]]
	
	autoprov_hosts = []
	for phone,u_prm in users.iteritems():
		if not u_prm[3]:
			continuie
		chosen_hbac = [ rule for rule in u_prm[3] if rule in host_hbacs.keys()]
		if chosen_hbac:
			autoprov_host = [phone, "%s%s" % (u_prm[0], u_prm[2]), u_prm[1]]
			autoprov_host.extend(host_hbacs.get(chosen_hbac[0]))
			autoprov_hosts.append(autoprov_host)
	return autoprov_hosts

def create_phonebook_gs(users):
	xml = '''<?xml version="1.0" encoding="UTF-8"?><AddressBook></AddressBook>'''
	root = objectify.fromstring(xml)
	for phone,u_prm in users.iteritems():
		contact = objectify.Element("Contact")
		contact.FirstName = u_prm[1].decode('utf8')
		xml_phone = objectify.Element("Phone")
		xml_phone.phonenumber = phone
		xml_phone.accountindex = 1
		contact.append(xml_phone)
		xml_group = objectify.Element("Groups")
		xml_group.groupid = 0
		contact.append(xml_group)
		root.append(contact)
	objectify.deannotate(root)
	etree.cleanup_namespaces(root)
	obj_xml = etree.tostring(root, pretty_print=True, xml_declaration=True, encoding='utf8')
	return obj_xml

def generate_phonebooks(data, template_dir, output_dir=os.getcwd()):
	for file in os.listdir(template_dir):
		filepath = os.path.join(template_dir,file)
		ofile = os.path.join(output_dir,"%s.xml" % os.path.splitext(file)[0])
		generate_xml_from_tpl(data, filepath, ofile)
	return



def generate_xml_from_tpl(data, template_file, output_file=os.getcwd()):
	with open(template_file) as tfile:
		tdata = tfile.read()
		tdata = tdata.decode("utf8")
		try:
			template = Template(tdata)
		except Exception as e:
			print "Bad template %s" % template_file
			print "The error was %s" % e
			return
		try:
			xml = template.render(data=data)
#		except Exception as e:
		except OSError:
			print "Error while rendering template %s" % template_file
			print "The error was %s" % e
			return
		else:
			dest_path = output_file
			xmlfile = open(dest_path, "w")
			xmlfile.write(xml.encode("utf8"))
			xmlfile.close()
			print "Succesfully created xml from template %s to destination %s" % (os.path.basename(template_file), dest_path)
	return

def get_parameters(received_args,default_main_parameters,main_parameters_keys,param_dependencies):
	parser = argparse.ArgumentParser(description="Asterisk config creation tool")
	parser.add_argument('-f', '--config-file', action='store', dest='main_conf_file', help='path to config file', required=True)
	args = parser.parse_args(received_args)
	args = vars(args)
	main_conf_file = args["main_conf_file"]
	parameters = build_parameters(main_conf_file, default_main_parameters)
	check_parameters(parameters, main_parameters_keys, param_dependencies, main_conf_file)
	return parameters

def main(args):
        main_parameters = get_parameters(args,default_main_parameters,main_parameters_keys,param_dependencies)
        if main_parameters.get("prov_data_file") and main_parameters.get("create_autoprov"):
            autoprov_parameters = build_parameters(main_parameters.get("prov_data_file"), default_ap_vars)
        conn = connect_ipa(main_parameters["storage_login"], main_parameters["storage_password"], main_parameters["storage_domain"], main_parameters["storage_host"])
        users = get_ipa_users(conn, main_parameters["storage_domain"], group=main_parameters["users_group"], pass_field=main_parameters["user_pass_field"])
        backend = main_parameters["backend"]
	if backend == 'freepbx':
		con,cursor = connect_mysql(main_parameters["freepbx_mysql_user"], main_parameters["freepbx_mysql_pass"], main_parameters["freepbx_mysql_db"], main_parameters["freepbx_mysql_host"])
		import_data_tomysql(users, cursor, main_parameters["user_template_path"])
		cursor.close()
		con.close()
	elif backend == 'asterisk':
		generate_sip_file(main_parameters["sip_filepath"], main_parameters["header_template_path"], main_parameters["user_template_path"], results)
	if reload:
		reload_string = '/var/lib/asterisk/bin/module_admin reload' if backend == 'freepbx' else 'asterisk -rx "sip reload"'
		call(reload_string, shell=True)
	print users

	if main_parameters["create_autoprov"] and main_parameters["autoprov_template_dir"] != "":
		hosts=get_ipa_hosts(conn, main_parameters["storage_domain"], hostgroup=main_parameters["hosts_group"])
		print hosts
		hbac_rules=get_ipa_hbac_rules(conn, main_parameters["storage_domain"],service_name=main_parameters["hbac_service_name"])
		print hbac_rules
	
		autoprov_hosts = compare_users_to_hosts(users,hosts,hbac_rules)

		print autoprov_hosts

		print "Generating autoprovisioning files..."
#		ap_data = default_ap_vars
		ap_data = { k : cgi.escape(v).decode("utf8") for k,v in default_ap_vars.iteritems() }
		generate_autoprov(autoprov_hosts, main_parameters["autoprov_template_dir"], main_parameters["autoprov_output_dir"], default_ap_name_mapping, default_ap_vars, main_parameters.get("ap_mappings_file"))
		print "Finished generating autoprovisioning files."

	if main_parameters["create_phonebooks"] and main_parameters["phonebook_template_dir"] != "":
		print "Generating phonebooks..."
		pb_data = default_pb_vars
		pb_data['users'] = { phone : cgi.escape(v[1]).decode("utf8") for phone,v in users.iteritems() }
		generate_phonebooks(pb_data, main_parameters["phonebook_template_dir"], main_parameters["phonebook_output_dir"])
		print "Finished generating phonebooks."

	return

if __name__ == "__main__":
#	args = sys.argv[1:]
	args = ['-f', '/home/project/config']
	main(args)

