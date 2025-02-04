# Phishing Monitor

## Description
CertStream is a data stream providing real-time updates from the `Certificate Transparency Log (CTL)` - Source: https://certstream.calidog.io/.
It enables real-time reactions to issued TLS certificates. 

This script uses the CertStream library to monitor domains from the CTL for suspicious naming conventions, allowing real-time detection of potential phishing attempts. 

Data throughput of the CertStream library: https://p.datadoghq.com/sb/e72980047-c37b10c02bf48fa80b013416ac899d15?fromUser=false&refresh_mode=sliding&theme=dark&from_ts=1732815180222&to_ts=1733419980222&live=true


## Notes and Preparations

The tool cannot be used out-of-the-box and requires initial customization, particularly regarding the so-called `"Watchlists"`. 

The tool was developed with the goal of monitoring various custom company domains. For this purpose, two lists must be initialized: `"longdomains.txt"` or `"shortdomains.txt"`.
If only one type of domain is to be monitored, small adjustments may be necessary to optimize the program logic.

### Watchlists

Using the `ail-typo-squatting` tool, lists of potential phishing domains can be generated. 
\
Domains to be monitored are entered into either the `"longdomains.txt"` or `"shortdomains.txt"` file, depending on their character length - recommendation:  
* \< 6 characters = `"shortdomains.txt"`
* \> 6 characters = `"longdomains.txt"`

Subsequently, the following commands are used to write the lists of potential phishing domains to the `"watchlists"` folder: 

* `typo.py` -fdn longdomains.txt -om -repe -repl -cho -add -md -sd -vs -ada -hg -cm -wsld -sub -o watchlists -fo yaml 
* `typo.py` -fdn shortdomains.txt -md -sd -ada -hg -cm -wsld -sub -o watchlists -fo yaml

**Explanation:** Depending on whether the domains are long or short, different algorithms are used to generate potential phishing domains. This aims to improve the quality of entries and reduce false positives. 

**Note:** The generated .yml files should subsequently be manually refined to enhance detection quality and performance.

### analyze_config.yml

The `"analyze_config.yml"` configuration file stores the following information: 
* legit domains: List of original domains to be monitored
* false positives: Domains known to be false positives
* levenshtein score: Numeric threshold for the maximum number of insert, delete, and replace operations to determine similarity between two strings (domains)
* Content Keywords: List of terms that must be part of the websites content (optional)
* VT API Key: Key for the Virustotal API to verify domains during alerts (optional)
* Phishing Keywords: List of terms that must be included in the domain name (optional)

**Note:** The configurations regarding 'Content Keywords', 'VT API Key' and 'Phishing Keywords' are optional and can be activated / deactivated using a switch (true or false). This is meant to offer maximum flexibility in the use of the tool and increase detection precision.

### Sendmail
The script uses its own `"sendmail"` Python module, which is imported in the Phishing-Monitor.
How it works is explained in more detail here: https://github.com/NicoThelen/sendmail \
The script requires its own config file `"mail_config.yml"` which must be filled accordingly.


## Functionality

Criteria for triggering an alarm/message - depending on the settings in the config file:

1. The domain name matches a suspicious phishing domain from the watchlists
2. The domain has not been reported in the last 10 alerts
3. The domain is not one of the legitimate original (sub)domains
4. The domain is not known as a false positive
5. The Levenshtein distance between the suspicious and the original domain is < 25
6. The domain name does contain a suspicious phishing keyword from the list (optional)
7. The content of the website contains a suspicious term from the list (optional)

If an alarm is triggered, the detected domain is enriched with information from VT (optional). \
If the E-Mail transmission fails, the alarm is written to an extra local report file as csv.

### Certstream.log

All relevant events, informations and errors are logged in the `"certstream.log"` file.

