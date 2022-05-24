#!/usr/bin/env python3

from shodan import Shodan
from fpdf import FPDF 
import requests
import time
import json
import sys
import os

def GenReportName(addr):
    #
    report_name = ''
    #
    report_name = addr+"_"
    #
    timestamp = time.ctime()
    #
    replace_colons = timestamp.replace(":",'_')
    #
    final_timestamp = replace_colons.replace(" ","_")
    #
    final_timestamp += ".pdf"
    #
    report_name += final_timestamp
    #
    return report_name

def QueryAbuseIPDB(addr,key):
    #
    abuse_ip_db_data = {}
    #
    print("[~] Querying AbuseIPDB for %s ..." % addr)
    #
    addr_query = {
                    'ipAddress': addr,
                    'maxAgeInDays': '180'
    }
    #
    headers    = {
                    'Accept': 'application/json',
                    'Key': key
    }
    #
    query_string = "https://api.abuseipdb.com/api/v2/check"
    #
    try:
        request = requests.get(url=query_string,headers=headers,params=addr_query,timeout=3)
        if(request.status_code == 200):
            print("[*] AbuseIP DB Query success")
            query_data = request.json()
            query_data = query_data['data']
            abuse_ip_db_data['IP']            = query_data['ipAddress']
            abuse_ip_db_data['Country']       = query_data['countryCode'] 
            abuse_ip_db_data['Usage']         = query_data['usageType'] 
            abuse_ip_db_data['ISP']           = query_data['isp']
            abuse_ip_db_data['Domain']        = query_data['domain']
            abuse_ip_db_data['Abuse Score']   = query_data['abuseConfidenceScore']
            abuse_ip_db_data['Total Reports'] = query_data['totalReports']
            abuse_ip_db_data['Last Reported'] = query_data['lastReportedAt']
            return abuse_ip_db_data
        else:
            print("[!] Query failure ")
            return None
    except Exception as e:
        print("[!] Abuse IP DB query failed ", e)
        return None

def QueryVirusTotal(addr,key):
    #
    virus_total_data = {}
    #
    print("[~] Querying Virus Total for %s ..." % addr)
    #
    headers    = {
                    'Accept': 'application/json',
                    'x-apikey': key
    }
    #
    query_string = "https://www.virustotal.com/api/v3/ip_addresses/{0}".format(addr)
    #
    try:
        request = requests.get(url=query_string,headers=headers,timeout=3) 
        if(request.status_code == 200):
            query_data    = request.json()
            query_data    = query_data['data']
            #  
            ip_attributes = query_data['attributes']
            #
            network              = ip_attributes['network']  
            country              = ip_attributes['country'] 
            asn_owner            = ip_attributes['as_owner'] 
            analysis_results     = ip_attributes['last_analysis_results'] 
            analysis_stats       = ip_attributes['last_analysis_stats'] 
            reputation           = ip_attributes['reputation'] 
            asn                  = ip_attributes['asn'] 
            rir                  = ip_attributes['regional_internet_registry'] 
            continent            = ip_attributes['continent'] 
            #
            virus_total_data['IP']                         = addr 
            virus_total_data['Network']                    = network
            virus_total_data['Country']                    = country
            virus_total_data['Continent']                  = continent
            virus_total_data['ASN']                        = asn
            virus_total_data['ASN Owner']                  = asn_owner
            virus_total_data['Statistics']                 = analysis_stats
            virus_total_data['Reputation']                 = reputation
            virus_total_data['Regional Internet Registry'] = rir
            #
            result_list = []
            #
            for item in analysis_results.keys():
                #
                engine_name = analysis_results[item]['engine_name']
                category    = analysis_results[item]['category']
                result      = analysis_results[item]['result']
                method      = analysis_results[item]['method']
                #
                result_list.append({engine_name,category,method,result})
            virus_total_data['Results'] = result_list
            return virus_total_data
        else:
            print("[!] Query failure ")
            return None
    except Exception as e:
        print("[!] Abuse IP DB query failed ", e)
        return None

def QueryShodan(addr,key):
    #
    shodan_query_data = {}
    #
    print("[~] Querying Shodan for %s ... " % addr)
    #
    shodanObj = Shodan(key)
    #
    try:
        #
        ip_query  = shodanObj.host(addr) 
        #
        if(ip_query):
            #
            print("[*] Shodan query success..")
            #
    except Exception as e:
        #
        print("[!] Shodan query error ", e)
        #
        return None
        #
    for item in ip_query.keys():
        if(item != 'data'):
            try:
                #
                shodan_query_data['IP']                       = ip_query['ip_str']
                shodan_query_data['Ports']                    = ip_query['ports']
                shodan_query_data['Domains']                  = ip_query['domains']
                shodan_query_data['Hostname']                 = ip_query['hostnames']
                shodan_query_data['City']                     = ip_query['city']
                shodan_query_data['Region']                   = ip_query['region_code']
                shodan_query_data['Country']                  = ip_query['country_code']
                shodan_query_data['Organization']             = ip_query['org']
                shodan_query_data['ASN']                      = ip_query['asn']
                shodan_query_data['ISP']                      = ip_query['isp'] 
                shodan_query_data['Latitude']                 = ip_query['latitude']
                shodan_query_data['Longitude']                = ip_query['longitude']
                shodan_query_data['PotentialVulnerabilities'] = ip_query['vulns']
            except:
                pass
        return shodan_query_data

def CreateReport(addr,results):
    #
    print("[~] Creating report...")
    #
    report_name = GenReportName(addr)
    #
    pdf = FPDF(orientation='P',unit='mm',format='A4')
    #
    pdf.set_font('Arial', 'B', 14)
    #
    pdf.add_page()
    #
    report_title = "IP Reputation Data for: %s " % addr
    #
    pdf.ln()
    #
    pdf.cell(0,5,report_title)
    #
    pdf.ln() ; pdf.ln()
    #
    for service in results.keys():
        #
        pdf.set_font('Arial', 'U', 16)
        #
        if(service == 'AbuseIP'):
            #
            pdf.image('abuseipdb.PNG', x = 160, y = 25, w = 30, h = 10, type = 'PNG')
            #
        if(service == 'Shodan'):
            #
            pdf.image('shodan.PNG', x = 160, y = 25, w = 30, h = 10, type = 'PNG')
            #
        if(service == 'Virustotal'):
            #
            pdf.image('virustotal.PNG', x = 160, y = 25, w = 30, h = 10, type = 'PNG')
            #
        service_data = results[service]
        #
        title_string = "%s Results: " % service 
        #
        pdf.ln()
        #
        pdf.cell(0,5,title_string)
        #
        pdf.ln() ; pdf.ln()
        #
        pdf.set_font('Arial', 'B', 12)
        #
        if(service_data == None):
            #
            pdf.cell(0,10,'No Data')
            #
            pdf.ln()
            #
            pdf.add_page()
            #
        else:
            #
            for value in service_data:
                #
                service_data_value = service_data[value]
                #
                if(type(service_data_value) == str):
                    #
                    write_entry = str(value) + ":" + service_data_value
                    #
                    pdf.cell(0,10,write_entry)
                    #
                elif(type(service_data_value) == int):
                    #
                    service_data_value = str(service_data_value)
                    #
                    write_entry = str(value) + ":" + str(service_data_value)
                    #
                    pdf.cell(0,10,write_entry)
                    #
                elif(type(service_data_value) == float):
                    #
                    service_data_value = str(service_data_value)
                    #
                    write_entry = str(value) + ":" + str(service_data_value)
                    #
                    pdf.cell(0,10,write_entry)
                    #
                elif(type(service_data_value) == dict and value == 'Results'):
                    #
                    write_entry = value + ":"
                    #
                    pdf.cell(0,10,write_entry)
                    #
                    pdf.ln() ; pdf.ln()
                    #
                    for dict_value in service_data_value.keys():
                        #
                        pdf.ln() 
                        #
                        current_value = str(service_data_value[dict_value])
                        #
                        pdf.cell(0,5,current_value)
                        #
                        pdf.ln()
                        #
                elif(type(service_data_value) == list):
                    #
                    write_entry = value + ":"
                    #
                    pdf.cell(0,10,write_entry)
                    #
                    pdf.ln()
                    #
                    for entry in service_data_value:
                        #
                        pdf.cell(0,5,str(entry))
                        #
                        pdf.ln()
                        #
                else:
                    #
                    write_entry = str(value) + ":" + str(service_data_value)
                    #
                    pdf.cell(0,10,write_entry)
                    #
                    pdf.ln()
                    #
                pdf.ln()
                #
            pdf.add_page()
            #
    pdf.output(report_name,'F')
    #
    return report_name

def main():
    #
    report_data = {}
    #
    print("""
    [*] IP Reputation Data Script
    -----------------------------
    """)
    #
    addr = input("[+] Enter the subject IP-> ")
    #
    check_directory = os.listdir()
    #
    keys_located = False
    #
    for item in check_directory:
        #
        if(item == 'keys.json'):
            #
            print("[*] Located key file ")
            #
            keys_located = True
            #
            key_file = item
            #
    if(keys_located == False):
        #
        print("[!] Failed to locate key file, departing ")
        #
        sys.exit(1)
        # 
    else:
        #
        fileObject = open(key_file,'r')
        #
        fileData   = fileObject.read()
        #
        key_data   = json.loads(fileData)
        #
        for key in key_data.keys():
            #
            service      = key 
            #
            service_key  = key_data[key]
            #
            if('abuseipdb' in service):
                #
                abuseip_data = QueryAbuseIPDB(addr,service_key) 
                #
                results['AbuseIP'] = abuseip_data
                #
            if('shodan' in service):
                #
                shodan_data = QueryShodan(addr,service_key)
                #
                results['Shodan'] = shodan_data
                #
            if('virustotal' in service):
                #
                virustotal_data = QueryVirusTotal(addr,service_key)
                #
                results['Virustotal'] = virustotal_data
                #
        if(len('test') > 0):
            #
            report_name = CreateReport(addr,results)
            #
            print("[*] Report may be located at: %s " % report_name)

if(__name__ == '__main__'):
    #
    results = {}
    #
    main()
