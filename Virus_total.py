import urllib
import urllib2
import json
def scan_virustotal(hash) :
    url = "http://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": hash,
                 "apikey": "4e809d5fe175928263b371c9582398925ec5a239badb63243818fd5dbf559325"}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    internet_connect = True
    try :

        while True :
            try :
                response = urllib2.urlopen(req)
                json_response = response.read()
                data_dict = json.loads(json_response)
                break
            except ValueError :
                pass

    except urllib2.URLError :
        print "Connectivity Issue !"
        internet_connect = False



    is_virus = False
    virus_name = None
    if internet_connect :
        try :
            positive_result = data_dict['positives']
            if positive_result > 0:
                is_virus = True
                for key in data_dict["scans"]:
                    if data_dict["scans"][key][u'detected'] == True:
                        virus_name = data_dict["scans"][key][u'result']
                        break
        except KeyError :
            pass





    return is_virus,virus_name



