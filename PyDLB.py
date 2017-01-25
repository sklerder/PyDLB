#!/usr/bin/env python
# -*- coding: iso8859-15 -*-

# Portage par JoeKer pour FONO sur la base de :
# - rene-d/sysbus (https://github.com/rene-d/sysbus)
# - fccagou/pylivebox (https://github.com/fccagou/pylivebox/blob/master/livebox/livebox.py)
# Merci de votre indulgence, je découvre Python ...

import urllib.request, urllib.parse, urllib.error
import json
import requests
# import requests.utils
import time

import sys
import getpass



VERSION_LIVEBOX = 'lb3'
USER_LIVEBOX = 'admin'
URL_LIVEBOX = 'http://livebox'
password = 'admin'

class Livebox:

	def __init__(self,url_prefix=URL_LIVEBOX):
		self._url_prefix = url_prefix

	def login(self):
		PASSWORD_LIVEBOX = password
		if PASSWORD_LIVEBOX == 'admin':
			PASSWORD_LIVEBOX=getpass.getpass()
		session = requests.Session()
		
		url_login = "%s/authenticate?username=admin&password=%s" % (self._url_prefix,password)

		values = {'username' : 'admin', 'password' : password }
		if VERSION_LIVEBOX != 'lb3' and VERSION_LIVEBOX != 'lb4':
			# On est probablement sur l'ancienne méthode d'authentification (avant décembre 2016)
			auth = { 'username':USER_LIVEBOX, 'password':PASSWORD_LIVEBOX }
			r = session.post(URL_LIVEBOX + '/authenticate', params=auth)
		else:
			# Cette méthode fonctionne avec les firmwares récents (fin décembre 2016) de la LB3 et de la LB4
			auth = '{"service":"sah.Device.Information","method":"createContext","parameters":{"applicationName":"so_sdkut","username":"%s","password":"%s"}}' % (USER_LIVEBOX, PASSWORD_LIVEBOX)
			sah_headers = { 'Content-Type':'application/x-sah-ws-1-call+json', 'Authorization':'X-Sah-Login' }
			r = session.post(URL_LIVEBOX + '/ws', data=auth, headers=sah_headers)

		if not 'contextID' in r.json()['data']:
			print("auth error", str(r.text))
			exit(1)

		self._lb_id=r.headers['Set-Cookie']
		self._sessid=(r.headers['Set-Cookie'].split('=',1)[1]).rsplit(';',1)[0]

		self._context_id=r.json()['data']['contextID']

	def _sysbus(self,question):
		return self._request("%s/sysbus/%s" % (self._url_prefix,question)
			, '{"parameters":{}}' )


	def _sysbus2(self,question):
		return self._request2("%s/sysbus/%s" % (self._url_prefix,question))

	def _ws(self, params):
		return self._request("%s/ws" % (self._url_prefix)
			, params , 'application/x-sah-ws-4-call+json')

	def _request(self,url, params, content_type='application/json'):

		en_params = params.encode('utf-8')
		req = urllib.request.Request(url, en_params)
		req.add_header('Cookie', self._lb_id)
		req.add_header('X-Context', self._context_id)
		req.add_header('X-Sah-Request-Type', 'idle')
		req.add_header('Content-Type', content_type)
		req.add_header('X-Requested-With', 'XMLHttpRequest')
	
		response = urllib.request.urlopen(req)
		the_page = response.readall().decode('utf-8')
		resp = json.loads(the_page)
		return resp

	
	def _request2(self,url, content_type='application/json'):
			
		req = urllib.request.Request(url)
		req.add_header('Cookie', self._lb_id)
		req.add_header('X-Context', self._context_id)
		req.add_header('X-Sah-Request-Type', 'idle')
		req.add_header('X-Requested-With', 'XMLHttpRequest')

		response = urllib.request.urlopen(req)
		the_page = response.readall().decode('utf-8')
		resp = str(json.loads(the_page))
		return resp

	def logout(self):
		urllib.request.urlopen("%s/logout" % (self._url_prefix))
		return ""
		
	def voip_config(self):
		j = self._ws('{"service":"NMC","method":"getVoIPConfig","parameters":{}}')
		return j['status']

	def list_trunks(self):
		'''Information téléphonie IP'''
		j = self._sysbus('VoiceService/VoiceApplication:listTrunks')
		return j['result']

	def ip_tv_status(self):
		'''Etat IP TV'''
		return self._sysbus('NMC/OrangeTV:getIPTVStatus')

	def device_info(self):
		''' Infos device '''
		j = self._ws('{"service":"DeviceInfo","method":"get","parameters":{}}')
		return j['status']

	def DSLStats(self):
		'''Information lien dsl'''
		j = self._ws('{"service":"NeMo.Intf.dsl0","method":"getDSLStats","parameters":{}}')
		return j['status']

	def wifi_com_status(self):
		'''Information Wifi public Orange)'''
		return self._sysbus('Wificom/OpenMode:getStatus')

	def wifi_mibs(self):
		'''Information Wifi'''
		j = self._ws('{"service":"NeMo.Intf.lan","method":"getMIBs","parameters":{"mibs":"wlanvap || wlanradio"}}')
		return j['status']

	def wan_status(self):
		'''Etat de la connexion WAN'''
		j = self._ws('{"service":"NMC","method":"getWANStatus","parameters":{}}')
		return j['data']

	def orange_services(self):
		j = self._ws(str('{"service":"OrangeServices","method":"getSubscriptionStatus","parameters":{"refresh":true}}'))
		return j

	def mtu(self):
		j = self._ws('{"service":"NeMo.Intf.data","method":"getFirstParameter","parameters":{"name":"MTU"}}')
		return j['status']

	def vlan_id(self):
		j = self._ws('{"service":"NeMo.Intf.data","method":"getFirstParameter","parameters":{"name":"VLANID"}}')
		return j['status']

	def ws_channel_id(self):
		j = self._ws('{"events":[{"handler":"sah.hgw.models"}]}')
		return j['channelid']

	def ws_get_devices(self, channel_id):
		j = self._ws('{"events":[{"handler":"sah.hgw.models"}],"channelid":%s}' % channel_id)
		return j


if __name__ == '__main__':
	lb = Livebox()
	lb.login()


	# Calculer le temps en secondes depuis EPOCH
	reftime = int(time.mktime(time.localtime()))
	DevInfo = lb.device_info()
	uptime = DevInfo['UpTime']
	starttime= reftime - uptime
	StartTime = time.ctime(starttime)
	Date_Demarrage = time.strftime("%d/%m/%Y %H:%M:%S", time.localtime(starttime))
	jours = str(int(uptime / 86400))
	heures =  str(int(uptime % 86400 / 3600))
	minutes = str(int(uptime % 86400 % 3600 / 60))
	secondes = str(int(uptime % 86400 % 3600 % 60))
	Start = jours + " j. " + heures + " h. " + minutes + " mn. " + secondes + " s." 

	# # Début de DeviceInfo
	DeviceInfo =  " Device Info" + "\n"
	DeviceInfo += "    Manufacturer          : " + DevInfo['Manufacturer'] + "\n"
	DeviceInfo += "    ManufacturerOUI       : " + DevInfo['ManufacturerOUI'] + "\n"
	DeviceInfo += "    ModelName             : " + DevInfo['ModelName'] + "\n"
	DeviceInfo += "    ProductClass          : " + DevInfo['ProductClass'] + "\n"
	DeviceInfo += "    SerialNumber          : " + DevInfo['SerialNumber'] + "\n"
	DeviceInfo += "    HardwareVersion       : " + DevInfo['HardwareVersion'] + "\n"
	DeviceInfo += "    SoftwareVersion       : " + DevInfo['SoftwareVersion'] + "\n"
	DeviceInfo += "    HardwareVersion 2     : " + DevInfo['AdditionalHardwareVersion'] + "\n"
	DeviceInfo += "    SoftwareVersion 2     : " + DevInfo['AdditionalSoftwareVersion'] + "\n"
	DeviceInfo += "    EnabledOptions        : " + DevInfo['EnabledOptions'] + "\n"
	DeviceInfo += "    SpecVersion           : " + DevInfo['SpecVersion'] + "\n"
	DeviceInfo += "    ProvisioningCode      : " + DevInfo['ProvisioningCode'] + "\n"
	DeviceInfo += "    UpTime                : " + str(DevInfo['UpTime']) + "\n"
	DeviceInfo += "      Démarrée depuis le  : " + Date_Demarrage + "\n"
	DeviceInfo += "      Démarrée depuis     : " + Start + "\n"
	DeviceInfo += "    Country               : " + DevInfo['Country'] + "\n"
	DeviceInfo += "    NumberOfReboots       : " + str(DevInfo['NumberOfReboots']) + "\n"
	print(DeviceInfo)
	# # Fin de DeviceInfo
	
	# # Début de WanStatus
	mtu = str(lb.mtu())
	vlanid = str(lb.vlan_id())
	wanstatus = lb.wan_status()
	
	# On aura besoin plus loin de tester le type de lien
	LinkType = wanstatus['LinkType']
	
	WanStatus  = " WAN Status" + "\n"
	WanStatus += "    LinkType            : " + wanstatus['LinkType'] + "\n"
	WanStatus += "    LinkState           : " + wanstatus['LinkState'] + "\n"
	WanStatus += "    MACAddress          : " + wanstatus['MACAddress'] + "\n"
	WanStatus += "    Protocol            : " + wanstatus['Protocol'] + "\n"
	WanStatus += "    ConnectionState     : " + wanstatus['ConnectionState'] + "\n"
	WanStatus += "    LastConnectionError : " + wanstatus['LastConnectionError'] + "\n"
	WanStatus += "    IPAddress           : " + wanstatus['IPAddress'] + "\n"
	WanStatus += "    RemoteGateway       : " + wanstatus['RemoteGateway'] + "\n"
	WanStatus += "    DNSServers          : " + wanstatus['DNSServers'] + "\n"
	WanStatus += "    IPv6Address         : " + wanstatus['IPv6Address'] + "\n"
	WanStatus += "    Vlan ID             : " + vlanid + "\n"
	WanStatus += "    MTU                 : " + mtu + "\n"
	print(WanStatus)
	# # Fin de WanStatus
	
	# # Début de VoipConfig
	
	voip_config = lb.voip_config()
	
	trunks_list = lb.list_trunks()
	trunks_result = trunks_list['status']

	SIP_Trunk = {str(trunks_result[0])}
	H323_trunk = {str(trunks_result[1])}
	VOIPConfig  = " Téléphonie IP" + "\n"
	VOIPConfig += "  Name                   : " + voip_config[0]['Name'] + "\n"
	VOIPConfig += "    Enable                   : " + voip_config[0]['Enable'] + "\n"
	VOIPConfig += "    Protocol                 : " + voip_config[0]['Protocol'] + "\n"
	VOIPConfig += "    Encapsulation            : " + voip_config[0]['Encapsulation'] + "\n"
	VOIPConfig += "    InterfaceId              : " + voip_config[0]['InterfaceId'] + "\n"
	VOIPConfig += "    Interface                : " + voip_config[0]['Interface'] + "\n"
	VOIPConfig += "    PhysInterface            : " + voip_config[0]['PhysInterface'] + "\n"
	VOIPConfig += "    Etat SIP                 : " + str(trunks_result[0]['trunk_lines'][0]['status']) + "\n"
	VOIPConfig += "    Activation SIP           : " + str(trunks_result[0]['trunk_lines'][0]['enable']) + "\n"
	VOIPConfig += "    Numéro d'annuaire SIP    : " + str(trunks_result[0]['trunk_lines'][0]['directoryNumber']) + "\n"
	VOIPConfig += "\n"
	VOIPConfig += "  Name                   : " + voip_config[1]['Name'] + "\n"
	VOIPConfig += "    Enable                   : " + voip_config[1]['Enable'] + "\n"
	VOIPConfig += "    Protocol                 : " + voip_config[1]['Protocol'] + "\n"
	VOIPConfig += "    Encapsulation            : " + voip_config[1]['Encapsulation'] + "\n"
	VOIPConfig += "    InterfaceId              : " + voip_config[1]['InterfaceId'] + "\n"
	VOIPConfig += "    Interface                : " + voip_config[1]['Interface'] + "\n"
	VOIPConfig += "    PhysInterface            : " + voip_config[1]['PhysInterface'] + "\n"
	VOIPConfig += "    Etat H323                : " + str(trunks_result[1]['trunk_lines'][0]['status']) + "\n"
	VOIPConfig += "    Activation H323          : " + str(trunks_result[1]['trunk_lines'][0]['enable']) + "\n"
	VOIPConfig += "    Numéro d'annuaire H323   : " + str(trunks_result[1]['trunk_lines'][0]['directoryNumber']) + "\n"
	print(VOIPConfig)
	# # Fin de VoipConfig
	
	# # Début de Wi-Fi
	WifiData = lb.wifi_mibs()
	WifiConf  = " Etat Wi-Fi" + "\n"
	WifiConf += "  Fréquence        : " + WifiData['wlanradio']['wifi0_ath']['OperatingFrequencyBand'] + "\n"
	WifiConf += "    SupportedBands     : " + WifiData['wlanradio']['wifi0_ath']['SupportedFrequencyBands'] + "\n"
	WifiConf += "    OperatingStandards : " + WifiData['wlanradio']['wifi0_ath']['OperatingStandards'] + "\n"
	WifiConf += "    Channel            : " + str(WifiData['wlanradio']['wifi0_ath']['Channel']) + "\n"
	WifiConf += "    SSID               : " + str(WifiData['wlanvap']['wl0']['SSID']) + "\n"
	WifiConf += "    SSID visible       : " + str(WifiData['wlanvap']['wl0']['SSIDAdvertisementEnabled']) + "\n"
	WifiConf += "    BSSID              : " + WifiData['wlanvap']['wl0']['BSSID'] + "\n"
	WifiConf += "    WEPKey             : " + WifiData['wlanvap']['wl0']['Security']['WEPKey'] + "\n"
	WifiConf += "    PreSharedKey       : " + WifiData['wlanvap']['wl0']['Security']['PreSharedKey'] + "\n"
	WifiConf += "    KeyPassPhrase      : " + WifiData['wlanvap']['wl0']['Security']['KeyPassPhrase'] + "\n"
	WifiConf += "    ModeEnabled        : " + WifiData['wlanvap']['wl0']['Security']['ModeEnabled'] + "\n"
	WifiConf += "    MACFiltering       : " + WifiData['wlanvap']['wl0']['MACFiltering']['Mode'] + "\n"
	WifiConf += "    SelfPIN            : " + WifiData['wlanvap']['wl0']['WPS']['SelfPIN'] + "\n"
	WifiConf += "\n"
	WifiConf += "  Fréquence        : " + WifiData['wlanradio']['wifi1_ath']['OperatingFrequencyBand'] + "\n"
	WifiConf += "    SupportedBands     : " + WifiData['wlanradio']['wifi1_ath']['SupportedFrequencyBands'] + "\n"
	WifiConf += "    OperatingStandards : " + WifiData['wlanradio']['wifi1_ath']['OperatingStandards'] + "\n"
	WifiConf += "    Channel            : " + str(WifiData['wlanradio']['wifi1_ath']['Channel']) + "\n"
	WifiConf += "    SSID               : " + WifiData['wlanvap']['wl1']['SSID'] + "\n"
	WifiConf += "    SSID visible       : " + str(WifiData['wlanvap']['wl1']['SSIDAdvertisementEnabled']) + "\n"
	WifiConf += "    BSSID              : " + WifiData['wlanvap']['wl1']['BSSID'] + "\n"
	WifiConf += "    WEPKey             : " + WifiData['wlanvap']['wl1']['Security']['WEPKey'] + "\n"
	WifiConf += "    PreSharedKey       : " + WifiData['wlanvap']['wl1']['Security']['PreSharedKey'] + "\n"
	WifiConf += "    KeyPassPhrase      : " + WifiData['wlanvap']['wl1']['Security']['KeyPassPhrase'] + "\n"
	WifiConf += "    ModeEnabled        : " + WifiData['wlanvap']['wl1']['Security']['ModeEnabled'] + "\n"
	WifiConf += "    MACFiltering       : " + WifiData['wlanvap']['wl1']['MACFiltering']['Mode'] + "\n"
	WifiConf += "    SelfPIN            : " + WifiData['wlanvap']['wl1']['WPS']['SelfPIN'] + "\n"
	print (WifiConf)
	
	WifiCom = lb.wifi_com_status()
	WifiComm  = "  Wi-Fi partagé" + "\n"
	WifiComm += "    SSID                : " + WifiCom['result']['data']['SSID'] + "\n"
	WifiComm += "    Status              : " + WifiCom['result']['data']['Status'] + "\n"
	WifiComm += "    Enable              : " + str(WifiCom['result']['data']['Enable']) + "\n"
	print (WifiComm)
	# # Fin de Wi-Fi
	
	
	
	# # Début de getDSLStats
	dslstats = lb.DSLStats()
	initTimeouts = dslstats['InitTimeouts']
	if initTimeouts == 4294967295:
		initTimeouts = -1
		
	DSLStats  = " Statistiques de la ligne" + "\n" 
	if LinkType == "ethernet":
		DSLStats += "  /!\ Résultats non significatifs avec un WAN EThernet" + "\n"
	
	DSLStats += "     ReceiveBlocks        : " + str(dslstats['ReceiveBlocks']) + "\n" 
	DSLStats += "     TransmitBlocks       : " + str(dslstats['TransmitBlocks']) + "\n" 
	DSLStats += "     CellDelin            : " + str(dslstats['CellDelin']) + "\n" 
	DSLStats += "     LinkRetrain          : " + str(dslstats['LinkRetrain']) + "\n" 
	DSLStats += "     InitErrors           : " + str(dslstats['InitErrors']) + "\n" 
	DSLStats += "     InitTimeouts         : " + str(initTimeouts) + "\n" 
	DSLStats += "     LossOfFraming        : " + str(dslstats['LossOfFraming']) + "\n" 
	DSLStats += "     ErroredSecs          : " + str(dslstats['ErroredSecs']) + "\n" 
	DSLStats += "     SeverelyErroredSecs  : " + str(dslstats['SeverelyErroredSecs']) + "\n" 
	DSLStats += "     FECErrors            : " + str(dslstats['FECErrors']) + "\n" 
	DSLStats += "     ATUCFECErrors        : " + str(dslstats['ATUCFECErrors']) + "\n" 
	DSLStats += "     HECErrors            : " + str(dslstats['HECErrors']) + "\n" 
	DSLStats += "     ATUCHECErrors        : " + str(dslstats['ATUCHECErrors']) + "\n" 
	DSLStats += "     CRCErrors            : " + str(dslstats['CRCErrors']) + "\n" 
	DSLStats += "     ATUCCRCErrors        : " + str(dslstats['ATUCCRCErrors']) + "\n" 
	print(DSLStats)
	# # Fin de getDSLStats
	
	# # Début de IPTVStatus
	iptvstatus = lb.ip_tv_status()['result']
	IPTV_Status  = " Etat des services TV" + "\n"
	IPTV_Status += "    IPTVStatus          : " + iptvstatus['data']['IPTVStatus'] + "\n"
	print(IPTV_Status)
	# # Fin de IPTVStatus
	
	# # Début de OrangeServices
	# Ne fonctionne pas sur LB3 et antérieures en janvier 2017
	# print((lb.orange_services()))
	# # Fin de OrangeServices
	
	# # Début de ConnectedDevices
	# Pas implémenté
	# print((lb.ws_get_devices(lb.ws_channel_id())))
	# # Fin de ConnectedDevices
	
	## Déconnexion
	print((lb.logout()))




	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	