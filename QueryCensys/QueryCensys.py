#!/usr/bin/env python3

from enum import auto
from censys.search import CensysHosts
import time
import os

def QueryCensys():
    print("[*] Python - Censys API - IP Query Utility ")
    query_subject = input("[+] Enter the IP address -> ")
    try:
        print("[~] Querying the API for -> %s " % query_subject)
        hostObject                = CensysHosts()
        hostData                  = hostObject.view(query_subject)
        ip                        = hostData['ip']
        services                  = hostData['services']
        location                  = hostData['location']
        location_updated          = hostData['location_updated_at']
        autonomous_system         = hostData['autonomous_system']
        autonomous_system_updated = hostData['autonomous_system_updated_at']
        operating_system          = hostData['operating_system']
        dns_data                  = hostData['dns']
        last_updated              = hostData['last_updated_at']
        #
        fileName   = 'censys-'+ip+'.txt'
        fileObject = open(fileName,'w')
        #
        print("IP Address")
        print("----------")
        print("[ADDRESS] %s " % ip)
        fileObject.write("IP Address\n")
        fileObject.write("----------\n")
        fileObject.write("[ADDRESS] %s \n" % ip)
        fileObject.write("\n")
        time.sleep(1)
        print()
        print("Services")
        print("--------")
        fileObject.write("Services\n")
        fileObject.write("--------\n")
        fileObject.write("\n")
        for service in services:
            for value in service.keys():
                if(type(service[value]) ==dict):
                    for item in service[value].keys():
                        print("[%s]\n[%s]" % (item,service[value][item]))
                        print()
                        fileObject.write("[%s]\n[%s]\n" % (item,service[value][item]))
                        fileObject.write("\n")
                        time.sleep(1)
                else:
                    print("[%s]\n[%s]" % (service,service[value]))
                    print()
                    fileObject.write("[%s]\n[%s]\n" % (service,service[value]))
                    fileObject.write("\n")
                    time.sleep(1)
        print("Location data")
        print("-------------")
        fileObject.write("Location data\n")
        fileObject.write("-------------\n")
        fileObject.write("\n")
        for entry in location.keys():
            print("[%s]:[%s]" % (entry,location[entry]))
            fileObject.write("[%s]:[%s]\n" % (entry,location[entry]))
            time.sleep(1)
        fileObject.write("\n")
        print()
        print("Autonomous System Data")
        print("----------------------")
        fileObject.write("Autonomous System Data\n")
        fileObject.write("----------------------\n")
        fileObject.write("\n")
        for entry in autonomous_system.keys():
            print("[%s]:[%s]" % (entry,autonomous_system[entry]))
            fileObject.write("[%s]:[%s]\n" % (entry,autonomous_system[entry]))
            time.sleep(1)
        fileObject.write("\n")
        print()
        print("Operating System")
        print("----------------")
        fileObject.write("Operating System\n")
        fileObject.write("----------------\n")
        fileObject.write("\n")
        for entry in operating_system.keys():
            print("[%s]:[%s]" % (entry,operating_system[entry]))
            fileObject.write("[%s]:[%s]\n" % (entry,operating_system[entry]))
            time.sleep(1)
        fileObject.write("\n")
        print()
        print("DNS Data")
        print("--------")
        fileObject.write("DNS Data\n")
        fileObject.write("--------\n")
        fileObject.write("\n")
        for entry in dns_data.keys():
            print("[%s]:[%s]" % (entry,dns_data[entry]))
            fileObject.write("[%s]:[%s]\n" % (entry,dns_data[entry]))
            time.sleep(1)
        fileObject.write("\n")
        print()
        print("Record Last Updated")
        print("-------------------")
        print("[RECORD DATE]       %s " % last_updated)
        fileObject.write("Record Last Updated\n")
        fileObject.write("-------------------\n")
        fileObject.write("\n")
        fileObject.write("[RECORD DATE]       %s \n" % last_updated)
        fileObject.close()
        time.sleep(3)
    except Exception as e:
        print("[!] Query failure:   %s " % e)

if(__name__ == '__main__'):
    #
    api_id  = "e4ea7495-d112-4442-a872-842b6d2381f0"
    api_sec = "jBNJJ5iZyIMUzouyBoGX2mE7ExjVlk1s"
    #
    os.environ['CENSYS_API_ID']     = api_id
    os.environ['CENSYS_API_SECRET'] = api_sec
    #
    QueryCensys()

