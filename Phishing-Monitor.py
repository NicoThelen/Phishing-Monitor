################################################
## Author: Nico Thelen                        ##
## MIT License                                ##
## www.linkedin.com/in/nico-thelen-5bbb6a289  ##
################################################

import logging
import datetime
import certstream
import os
import yaml 
import glob
import csv
from Levenshtein import distance
import idna 
import requests
from concurrent.futures import ThreadPoolExecutor
import sendmail

# Generate list with suspicous domains
def get_watchlists():
    watchlistsYML = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'watchlists')      # Specify the folder with all yml files
        
    watchlist_content = {}

    for watchlist in glob.glob(os.path.join(watchlistsYML, '*.yml')):               # Reading all yml files from the directory 
        logging.info(f'Loading domain variations from {watchlist}')
        with open(watchlist, 'r') as wl:                            
            content = yaml.safe_load(wl)                                    # Reading yml file content
            watchlist_content[content['title']] = content['variations']     # Save the variations according to their original domain in a dictionary

    logging.info(f'Domain variations loaded: {sum(len(values) for values in watchlist_content.values())}')

    return watchlist_content


# Generate list with known falsepositives, original domains and the levenshtein threshold
def get_analyzeconfig():
    analyzeYML = os.path.join(os.path.dirname(os.path.realpath(__file__)),'analyze_config.yml')    # Specify path to the yml file

    logging.info(f'Loading analysis config from {analyzeYML}')

    with open(analyzeYML, 'r') as kw:
        analyze = yaml.safe_load(kw)                                                    # Reading yml file content

    logging.info(f'Original domains loaded: {len(analyze["legit_domains"])} ')
    logging.info(f'Falsepositives loaded: {len(analyze["falsepositives"])} ')
    logging.info(f'Levenshtein threshold: {analyze["levenshtein_score"]}')
    logging.info(f'Checking domainname for phishing keywords: {analyze["check_phishing_domainname"]}')
    if analyze["check_phishing_domainname"]:
        logging.info(f'Phishing keywords loaded: {len(analyze["phishing_keywords"])}')
    logging.info(f'Contacting the suspicious website: {analyze["check_website_content"]}')
    if analyze["check_website_content"]:
        logging.info(f'Website content keywords loaded: {len(analyze["content_keywords"])}')
    logging.info(f'Enrich alert with VT Intel: {analyze["check_VT"]}')
    
    return analyze


# Callback function acting as eventlistener
def print_callback(message, context):
    if message['message_type'] == "heartbeat":
        logging.info("Heartbeat received")
        return
    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']       # Get all domains from CTL event
        executor.submit(check_domain, all_domains, message)


# Check if domain matches with our watchlists
def check_domain(all_domains, message):
    for domain in all_domains:
        try:
            if "xn--" in domain:                                    # Check for punycode domains and translate them to unicode      
                parts = domain.split('.')
                decoded_domain = []
                for part in parts:
                    decoded_domain.append(idna.decode(part))
                domain = '.'.join(decoded_domain)                   # Overwriting punycode domain with translated domain
        except:                                                     # In case of malformed punycode domain, domain translation will be ignored
            pass
        for key in watchlist_content:                               # Iterate through every original domain (key)
            for variation in watchlist_content[key]:                # Iterate through every suspicious domainnames of each original domain (key)
                if variation in domain:                             # Comparison of the certstream domains with the list of suspicious domainnames
                    analyze_domain(domain, message, variation, key)      # If the domainname is suspicious, further analyzes are started 
                    return
                    

# Analyzing suspicious domain and prepare alarm
def analyze_domain(sus_domain, message, variation, target_domain):
    # Sanitize domain from wildcard
    if sus_domain.startswith('*.'):                 
        sus_domain = sus_domain[2:]
    
    # Check if the domain has already alerted
    global processed_alarm
    
    if sus_domain in processed_alarm:                               # If the domain has already been alerted the analysis is terminated
        logging.info(f'SUSPICIOUS DOMAIN | {sus_domain} | Alarm already processed')
        return
    
    # Check if the domain is a legitimate subdomain
    for original_domain in analyze["legit_domains"]:
        if sus_domain.endswith(f'.{original_domain}') or sus_domain == original_domain:     # If the domain is a legtitimate (sub)domain the analysis is terminated
            logging.info(f'LEGITIMATE (SUB)DOMAIN | {sus_domain} | No report or alarm')
            return
    
    # Check for known false positives
    for fp in analyze['falsepositives']:       
        if sus_domain.endswith(f'.{fp}') or sus_domain == fp:       # If the domain is a known FP the analysis is terminated
            logging.info(f'KNOWN FALSEPOSITIVE DOMAIN | {sus_domain} | No report or alarm')
            return    
    
    # Calculate levenshtein distance
    levenshtein_score = distance(target_domain, sus_domain)         # Calculate levenshtein distance between sus domain and original domain whose variation was detected
    if levenshtein_score > analyze["levenshtein_score"]:            # If the levenshtein score is > the threshold the analysis is terminated
        logging.info(f'SUSPICIOUS DOMAIN | {sus_domain} | No report or alarm Levenshtein threshold not reached') 
        return
    
    # If its enabled, check if domain contains suspicious phishing keyword
    if analyze["check_phishing_domainname"]:
        phishing_keyword_found = False
        if len(sus_domain) > (len(variation) + 4):                          # Keywords are only checked if the sus domain has a certain length compared to the detected domain variation 
            for keyword in analyze['phishing_keywords']:
                if keyword in sus_domain:                                   # If the domain contains a suspicious phishing keyword the analysis continues
                    phishing_keyword_found = True
                    break
            if phishing_keyword_found == False:                             # If there was no suspicious phishing keyword found the analysis is terminated
                logging.info(f'SUSPICIOUS DOMAIN | {sus_domain} | No report or alarm Domain doesnt contain suspicious keyword')
                return
    
    # If its enabled, contact and check the suspicious websites content for given keywords
    if analyze["check_website_content"]: 
        content_keyword_found = False
        content_keyword_found = check_content(sus_domain)           # Returns True if websites content contain a keyword or if requests failed

        if content_keyword_found == False:                          # If there was no suspicious phishing keyword found the analysis is terminated
            logging.info(f'SUSPICIOUS DOMAIN | {sus_domain} | No report or alarm Website doesnt contain suspicious keyword')
            return
    
    # If no reason for termination was found the domain is considered a hit
    processed_alarm.append(sus_domain)                          # Store domain to prevent repeated alarms
    if len(processed_alarm) > 10:                               # Buffer for recent alarms = 10, delete oldest if new alarm gets stored
        processed_alarm.pop(0)       
    
    # If its enabled, enrich the the alert with intel from VT
    if analyze["check_VT"]: 
        vt_intel = vt_threatintel(sus_domain)                       # Call function to enrich alarm/report with VT threat intel
    else: 
        vt_intel = None                                             # Set variable to None to adjust the notification in the alarm
    
    # Prepare alarm data
    timestamp = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    alarm_reason = f'"{variation}" found in Domain or SAN'
    all_domains = message['data']['leaf_cert']['all_domains']
    aggregated_issuer = message['data']['leaf_cert']['issuer']['aggregated']
    fingerprint = message['data']['leaf_cert']['fingerprint']
    serial_number = message['data']['leaf_cert']['serial_number']
    source = message['data']['source']['name']
    
    # send alarm or generate report
    mail_sent = send_alarm(timestamp, alarm_reason, sus_domain, all_domains, aggregated_issuer, fingerprint, serial_number, source, vt_intel)    # If mail sent successfull = true, all done
    if mail_sent == False:
        generate_report(timestamp, alarm_reason, target_domain, sus_domain, all_domains, aggregated_issuer, fingerprint, serial_number, source, vt_intel)       # If mail sent failed = generate report                    


def check_content(sus_domain):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'
    }

    https_sus_domain = f'https://{sus_domain}'
    http_sus_domain = f'http://{sus_domain}'

    # First try: Request with https
    try:   
        response = requests.get(https_sus_domain, timeout=5, headers=headers)
        response.raise_for_status()                                 # Ensure the request was successful
    except requests.exceptions.RequestException as e:                                
        # Second try: Request with http
        try:
            response = requests.get(http_sus_domain, timeout=5, headers=headers)
            response.raise_for_status()                             # Ensure the request was successful
        except requests.exceptions.RequestException as e:               
            logging.error(f'SUSPICIOUS DOMAIN | {sus_domain} | Error fetching website: {e}')
            return True                                             # If both requests fail, the analysis continues even though no keyword was found, just to be sure

    raw_body = response.text.lower()                           
    for keyword in analyze["content_keywords"]:
        if keyword.lower() in raw_body:
            return True                                             # If the requests were successful and the content does contain a keyword, the analysis continues
        
    return False                                                    # If the requests were successful and the content does not contain a keyword, the analysis is terminated
            

# Get Threat Intel for domain to enrich alarm/report
def vt_threatintel(sus_domain):
    url = f'https://www.virustotal.com/api/v3/domains/{sus_domain}'         # API URL to get domain threat intel
    headers = {                                                             # Request headers with content type and api key
        "accept": "application/json",
        "x-apikey": analyze["VT_API_Key"]
    }

    try:
        response = requests.get(url, headers=headers).json()                # API request

        vt_a_records = []                                                   
        # Get specific classifications from response
        vt_malicious = response["data"]["attributes"]["last_analysis_stats"]["malicious"]                             
        vt_suspicious = response["data"]["attributes"]["last_analysis_stats"]["suspicious"]                             
        vt_undetected = response["data"]["attributes"]["last_analysis_stats"]["undetected"]                             
        vt_harmless = response["data"]["attributes"]["last_analysis_stats"]["harmless"]                             
        for type in response["data"]["attributes"]["last_dns_records"]:                             
            if type["type"] == "A":
                vt_a_records.append(type["value"])
        vt_whois = response["data"]["attributes"]["whois"]

        return vt_malicious, vt_suspicious, vt_undetected, vt_harmless, vt_a_records, vt_whois  
    except Exception as e:
        logging.info(f'SUSPICIOUS DOMAIN | {sus_domain} | No VT Threat Intel available {e}') 
        return None


# Sending the alarm via mail
def send_alarm(timestamp, alarm_reason, sus_domain, all_domains, aggregated_issuer, fingerprint, serial_number, source, vt_intel):
    
    # Crafting specific VT message
    if vt_intel:                        # If the VT api delivered data
        vt_msg = f'''   
        Malicious: {vt_intel[0]}
        Suspicious: {vt_intel[1]}
        Undetected: {vt_intel[2]}
        Harmless {vt_intel[3]}
        A Records: {", ".join(vt_intel[4])}
        
        Whois: {vt_intel[5]}
        '''
    else:
        vt_msg = "No Data Available"                   

    # Crafting Mail body
    msg = f'''
    Timestamp: {timestamp}
    Suspicious Domain: {sus_domain}
    Alarm reason: {alarm_reason}

    CTL Informations: 
    Domain: {all_domains[0]}
    SAN: {", ".join(all_domains[1:])}
    Issuer: {aggregated_issuer}
    Fingerprint: {fingerprint}
    Serial Number: {serial_number}
    Source: {source}

    VT Threat Intel: {vt_msg}
    '''
    try:       
        server = sendmail.connect_server()          # Establish mail server connection
        if server:
            sendmail.send_email(server, msg)        # Send alarm via email
            logging.info(f'SUSPICIOUS DOMAIN | {sus_domain} | Alarm sent')
            return True                                                         # If successful, return true
        else:
            logging.error(f'SUSPICIOUS DOMAIN | {sus_domain} | Alarm couldnt be sent')                                                                   
            return False                                                        # Backup if mail doenst work, return false
    except:  
        logging.error(f'SUSPICIOUS DOMAIN | {sus_domain} | Alarm couldnt be sent')                                                                    
        return False                                                            # Backup if mail doenst work, return false
            

# Add suspicious domain to report list
def generate_report(timestamp, alarm_reason, target_domain, sus_domain, all_domains, aggregated_issuer, fingerprint, serial_number, source, vt_intel):
    report = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'suspicious_domains.csv')     # Check if file is present
    file_exists = os.path.isfile(report)

    with open(report, "a", newline='') as sus:
        writer = csv.writer(sus)
        if not file_exists:                                                             # If file is present, the header will be skipped
            writer.writerow(['Timestamp', 'Alarm Reason', 'Target Domain', 'Suspicious Domain', 'CTL Domain', 'CTL SAN', 'CTL Issuer', 'CTL Fingerprint', 'CTL Serial Number', 'CTL Source', 'VT Malicious', 'VT Suspicious', 'VT Undetected', 'VT Harmless', 'VT A Records'])
        if vt_intel:
            writer.writerow([timestamp, alarm_reason, target_domain, sus_domain, all_domains[0], ", ".join(all_domains[1:]), aggregated_issuer, fingerprint, serial_number, source, vt_intel[0], vt_intel[1], vt_intel[2], vt_intel[3], ", ".join(vt_intel[4])])
        else:
            writer.writerow([timestamp, alarm_reason, target_domain, sus_domain, all_domains[0], ", ".join(all_domains[1:]), aggregated_issuer, fingerprint, serial_number, source])
    logging.info(f'SUSPICIOUS DOMAIN | {sus_domain} | Domain added to report list')    


# Start ThreadPoolExecutor to handle threads
executor = ThreadPoolExecutor()

# Source for the CTL stream
certstream_URL = "wss://certstream.calidog.io/"

# Configure Logging
logging.basicConfig(filename=os.path.join(os.path.dirname(os.path.realpath(__file__)),'certstream.log'), format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%d.%m.%Y %H:%M:%S', level=logging.INFO)

# Prevent logs of the websocket lib used in certstream from being passed on to our logger
loggerC = logging.getLogger('websocket')
loggerC.propagate = False

# List to store last processed alarm - prevent duplicates
processed_alarm = []

# Generate dict with suspicous domains
watchlist_content = get_watchlists()

# Generate list with known falsepositives, original domains, levenshtein threshold and keywords
analyze = get_analyzeconfig()

# Start the wss connection and listen for event from the CTL
certstream.listen_for_events(print_callback, url=certstream_URL)
