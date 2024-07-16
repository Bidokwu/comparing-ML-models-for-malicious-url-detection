from flask import Flask, render_template, request 
import pickle 
import numpy as np 
import sklearn
import pandas as pd

data = pd.read_csv('./malicious_phish.csv')


app = Flask(__name__)
mod = pickle.load(open('model.pkl', 'rb'))

import re

def use_of_ip_address(url):
    match = re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match: 
        return 1
    else:
        return 0

data['use_of_ip'] = data['url'].apply(lambda i: use_of_ip_address(i))

from urllib.parse import urlparse

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        return 1
    else:
        return 0

data['abnormal_url'] = data['url'].apply(lambda i: abnormal_url(i))

# !pip install googlesearch-python

from googlesearch import search

def google_index(url):
    site = search(url, 5)
    return 1 if site else 0

data['google_index'] = data['url'].apply(lambda i: google_index(i))

def count_url(url):
    count_of_dots = url.count('.')
    return count_of_dots 

data['count_of_dots'] = data['url'].apply(lambda i: count_url(i))

def count_www(url):
    url.count('www')
    return url.count('www')

data['count_www'] = data['url'].apply(lambda i: count_www(i))

def count_at(url):
    return url.count('@')

data['count_of_@'] = data['url'].apply(lambda i: count_at(i))

def count_of_dir(url):
    count_of_dir = urlparse(url).path
    return count_of_dir.count('/')

data['count_of_/'] = data['url'].apply(lambda i: count_of_dir(i))

def count_of_domains(url):
    count_of_domains = urlparse(url).path
    return count_of_domains.count('//')

data['count_of_//'] = data['url'].apply(lambda i: count_of_domains(i))

def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0

data['short_url'] = data['url'].apply(lambda i: shortening_service(i))

def count_https(url):
    return url.count('https')

data['count_https'] = data['url'].apply(lambda i: count_https(i))

def count_http(url):
    return url.count('http')

data['count_http'] = data['url'].apply(lambda i: count_http(i))

def count_per(url):
    return url.count('%')

data['count_of_%'] = data['url'].apply(lambda i: count_per(i))

def count_ques(url):
    return url.count('?')

data['count_of_?'] = data['url'].apply(lambda i: count_ques(i))

def count_hyphen(url):
    return url.count('-')

data['count-'] = data['url'].apply(lambda i: count_hyphen(i))

def count_equal(url):
    return url.count('=')

data['count='] = data['url'].apply(lambda i: count_equal(i))

def count_length(url):
    return len(str(url))

data['count_of_length'] = data['url'].apply(lambda i: count_length(i))

def hostname_length(url):
    return len(urlparse(url).netloc)

data['hostname_length'] = data['url'].apply(lambda i: hostname_length(i))

def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match: 
        return 1
    else:
        return 0

data['susp_words'] = data['url'].apply(lambda i: suspicious_words(i))

def count_digits(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
        return digits

data['count_of_digits'] = data['url'].apply(lambda i: count_digits(i))

def count_alphabets(url):
    alphabets = 0
    for i in url:
        if i.isalpha():
            alphabets = alphabets + 1
        return alphabets

data['count_of_alphabets'] = data['url'].apply(lambda i: count_alphabets(i))

# !pip install tld 

from urllib.parse import urlparse
from tld import get_tld
import os.path 

def length_fd(url):
    url_directory = urlparse(url).path
    try:
        return len(url_directory.split('/')[1])
    except:
        return 0

data['length_of_fd'] = data['url'].apply(lambda i: length_fd(i))

data['tld'] = data['url'].apply(lambda i: get_tld(i, fail_silently=True))

def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1

data['tld_length'] = data['tld'].apply(lambda i: tld_length(i))

data = data.drop('tld', axis=1)

def main(url):
    
    status = []
    
    status.append(use_of_ip_address(url))
    status.append(abnormal_url(url))
    status.append(count_url(url))
    status.append(count_www(url))
    status.append(count_at(url))
    status.append(count_of_dir(url))
    status.append(count_of_domains(url))
    
    status.append(shortening_service(url))
    status.append(count_https(url))
    status.append(count_http(url))
    
    status.append(count_per(url))
    status.append(count_ques(url))
    status.append(count_hyphen(url))
    status.append(count_equal(url))
    
    status.append(count_length(url))
    status.append(hostname_length(url))
    status.append(suspicious_words(url))
    status.append(count_digits(url))
    status.append(count_alphabets(url))
    status.append(length_fd(url))
    tld = get_tld(url,fail_silently=True)
      
    status.append(tld_length(tld))
    
    
    

    return status


def get_prediction_from_url(test_url):
    features_test = main(test_url)
    # Due to updates to scikit-learn, we now need a 2D array as a parameter to the predict function.
    features_test = np.array(features_test).reshape((1, -1))
    

    pred = mod.predict(features_test)
    if int(pred[0]) == 0:
        
        res="SAFE"
        return res
    elif int(pred[0]) == 1.0:
        
        res="DEFACEMENT"
        return res
    elif int(pred[0]) == 2.0:
        res="PHISHING"
        return res
        
    elif int(pred[0]) == 3.0:
        
        res="MALWARE"
        return res

@app.route('/')
def home():
    result = ''
    return render_template('index.html', **locals())

@app.route('/predict', methods=['POST', 'GET'])
def predict():
    a = request.form["a"]
    result = get_prediction_from_url(a)
    return render_template('index.html', **locals())

if __name__ =='__main__':
    app.run(debug=True)