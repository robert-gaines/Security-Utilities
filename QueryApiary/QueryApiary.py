import requests
import time

def QueryApiary(addr):
    #
    url       = "https://api.bgpview.io/ip/{0}".format(addr)
    request   = requests.get(url=url,timeout=3)
    response  = request.json()
    ip        = response['data']['ip']
    ptr       = response['data']['ptr_record']
    prefixes  = response['data']['prefixes'][0]
    rir       = response['data']['rir_allocation']
    iana      = response['data']['iana_assignment']
    maxmind   = response['data']['maxmind']
    #
    filename  = addr+'.txt'
    fileObj   = open(filename,'w')
    #
    print("[QUERY RESULTS]")
    print("[IP]          %s  " % ip)
    print("[PTR]         %s " % ptr )
    fileObj.write("[QUERY RESULTS]\n")
    fileObj.write("[IP]          %s  \n" % ip)
    fileObj.write("[PTR]         %s  \n" % ptr)
    print("[PREFIX DATA]")
    fileObj.write("[PREFIX DATA] \n")
    prefix = prefixes['prefix']
    prf_ip = prefixes['ip']
    cidr_blk = prefixes['cidr']
    asn_data = prefixes['asn']
    asn      = asn_data['asn']
    name     = asn_data['name']
    desc     = asn_data['description']
    ctr_code = asn_data['country_code']
    print("[PREFIX]      %s " % prefix)
    print("[PREFIX IP]   %s " % prf_ip)
    print("[CIDR BLOCK]  %s " % cidr_blk)
    print("[ASN]         %s " % asn)
    print("[NAME]        %s " % name)
    print("[DESCRIPTION] %s " % desc)
    print("[DESCRIPTION] %s " % desc)
    fileObj.write("[PREFIX]      %s \n" % prefix)
    fileObj.write("[PREFIX IP]   %s \n" % prf_ip)
    fileObj.write("[CIDR BLOCK]  %s \n" % cidr_blk)
    fileObj.write("[ASN]         %s \n" % asn)
    fileObj.write("[NAME]        %s \n" % name)
    fileObj.write("[DESCRIPTION] %s \n" % desc)
    fileObj.write("[DESCRIPTION] %s \n" % desc)
    print("[RIR DATA]")
    fileObj.write("[RIR DATA]\n")
    rir_name   = rir['rir_name']
    rir_ctr    = rir['country_code']
    rir_ip     = rir['ip']
    rir_cidr   = rir['cidr']
    rir_pfx    = rir['prefix']
    rir_date   = rir['date_allocated']
    rir_status = rir['allocation_status']
    print("[NAME]        %s " % rir_name)
    print("[COUNTRY]     %s " % rir_ctr)
    print("[IP]          %s " % rir_ip)
    print("[CIDR]        %s " % rir_cidr)
    print("[PREFIX]      %s " % rir_pfx)
    print("[ALLOCATED]   %s " % rir_date)
    print("[STATUS]      %s " % rir_status)
    fileObj.write("[NAME]        %s \n" % rir_name)
    fileObj.write("[COUNTRY]     %s \n" % rir_ctr)
    fileObj.write("[IP]          %s \n" % rir_ip)
    fileObj.write("[CIDR]        %s \n" % rir_cidr)
    fileObj.write("[PREFIX]      %s \n" % rir_pfx)
    fileObj.write("[ALLOCATED]   %s \n" % rir_date)
    fileObj.write("[STATUS]      %s \n" % rir_status)
    print("[IANA DATA]")
    fileObj.write("[IANA DATA]\n")
    iana_status = iana['assignment_status']
    iana_descr  = iana['description']
    iana_whois  = iana['whois_server']
    iana_date   = iana['date_assigned']
    print("[STATUS]      %s " % iana_status)
    print("[DESCRIPTION] %s " % iana_descr)
    print("[WHOIS]       %s " % iana_whois)
    print("[DATE]        %s " % iana_date)
    fileObj.write("[STATUS]      %s \n" % iana_status)
    fileObj.write("[DESCRIPTION] %s \n" % iana_descr)
    fileObj.write("[WHOIS]       %s \n" % iana_whois)
    fileObj.write("[DATE]        %s \n" % iana_date)
    print("[MAXMIND DATA]")
    fileObj.write("[MAXMIND DATA]\n")
    mm_ctr_code = maxmind['country_code']
    mm_city     = maxmind['city']
    print("[COUNTRY]     %s " % mm_ctr_code)
    print("[CITY]        %s " % mm_city)
    fileObj.write("[COUNTRY]     %s \n" % mm_ctr_code)
    fileObj.write("[CITY]        %s \n" % mm_city)
    fileObj.close()
    time.sleep(3)

print("[*] Apiary IP Data Query Utility ")

addr = input("[+] Enter the IP address-> ")

try:
    QueryApiary(addr)
except:
    print("[!] Error")