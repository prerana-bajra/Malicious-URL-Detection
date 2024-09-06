from flask import Flask, request, jsonify
import pandas as pd
import matplotlib
import re
from googlesearch import search
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn import svm
from sklearn import metrics
from sklearn.preprocessing import LabelEncoder
import tkinter
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import warnings
from flask_cors import CORS

warnings.filterwarnings("ignore", category=UserWarning)

app = Flask(__name__)
CORS(app)


df = pd.read_csv('malicious_phish.csv', nrows=20000)

def contains_ip_address(url):
    match = re.search(r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'
                      r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)'
                      r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
    if match:
        return 1
    else:
        return 0

df['use_of_ip'] = df['url'].apply(contains_ip_address)


def abnormal_url(url):
    hostname = urlparse(url).hostname
    if hostname:
        match = re.search(re.escape(hostname), url)
        if match:
            return 1
    return 0

df['abnormal_url'] = df['url'].apply(abnormal_url)


def google_index(url):
    site = search(url, 5)
    return 1 if site else 0

df['google_index'] = df['url'].apply(google_index)


def count_dot(url):
    count_dot = url.count('.')
    return count_dot


df['count.'] = df['url'].apply(lambda i: count_dot(i))
df.head()


def count_www(url):
    url.count('www')
    return url.count('www')


df['count-www'] = df['url'].apply(lambda i: count_www(i))


def count_atrate(url):
    return url.count('@')


df['count@'] = df['url'].apply(lambda i: count_atrate(i))


def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')


df['count_dir'] = df['url'].apply(lambda i: no_of_dir(i))


def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')


df['count_embed_domian'] = df['url'].apply(lambda i: no_of_embed(i))


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


df['short_url'] = df['url'].apply(lambda i: shortening_service(i))


def count_https(url):
    return url.count('https')


df['count-https'] = df['url'].apply(lambda i: count_https(i))


def count_http(url):
    return url.count('http')


df['count-http'] = df['url'].apply(lambda i: count_http(i))


def count_per(url):
    return url.count('%')


df['count%'] = df['url'].apply(lambda i: count_per(i))


def count_ques(url):
    return url.count('?')


df['count?'] = df['url'].apply(lambda i: count_ques(i))


def count_hyphen(url):
    return url.count('-')


df['count-'] = df['url'].apply(lambda i: count_hyphen(i))


def count_equal(url):
    return url.count('=')


df['count='] = df['url'].apply(lambda i: count_equal(i))


def url_length(url):
    return len(str(url))



df['url_length'] = df['url'].apply(lambda i: url_length(i))



def hostname_length(url):
    return len(urlparse(url).netloc)


df['hostname_length'] = df['url'].apply(lambda i: hostname_length(i))

df.head()


def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        return 1
    else:
        return 0


df['sus_url'] = df['url'].apply(lambda i: suspicious_words(i))


def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits


df['count-digits'] = df['url'].apply(lambda i: digit_count(i))


def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters


df['count-letters'] = df['url'].apply(lambda i: letter_count(i))

df.head()



def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0


df['fd_length'] = df['url'].apply(lambda i: fd_length(i))


df['type'].value_counts()


lb_make = LabelEncoder()
df["url_type"] = lb_make.fit_transform(df["type"])
df["url_type"].value_counts()


X = df[['use_of_ip', 'abnormal_url', 'count.', 'count-www', 'count@',
        'count_dir', 'count_embed_domian', 'short_url', 'count-https',
        'count-http', 'count%', 'count?', 'count-', 'count=', 'url_length',
        'hostname_length', 'sus_url', 'fd_length', 'count-digits',
        'count-letters']]


y = df['url_type']


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

clf_svm = svm.SVC(kernel='linear')
clf_svm.fit(X_train, y_train)


clf_rf = RandomForestClassifier(n_estimators=100, random_state=42)
clf_rf.fit(X_train, y_train)


def extract_features(url):
    features = [
        contains_ip_address(url),
        abnormal_url(url),
        count_dot(url),
        count_www(url),
        count_atrate(url),
        no_of_dir(url),
        no_of_embed(url),
        shortening_service(url),
        count_https(url),
        count_http(url),
        count_per(url),
        count_ques(url),
        count_hyphen(url),
        count_equal(url),
        url_length(url),
        hostname_length(url),
        suspicious_words(url),
        fd_length(url),
        digit_count(url),
        letter_count(url)
    ]
    return features

def predict_url_type(url):
    features = extract_features(url)
    prediction_rf = clf_rf.predict([features])[0]
    prediction_svm = clf_svm.predict([features])[0]
    return lb_make.inverse_transform([prediction_rf])[0], lb_make.inverse_transform([prediction_svm])[0]

# Define a function to add CSP headers to responses
def add_csp_headers(response):
    response.headers['Content-Security-Policy'] = "script-src 'self' 'unsafe-inline'; object-src 'self'"
    return response

# Register the `add_csp_headers` function to be called before every response is sent
app.after_request(add_csp_headers)

def google_search(url):
    results = search(url, num=5, stop=5, pause=2)
    return list(results)

# Define the API endpoint for prediction
@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    url = data['url']
    prediction_rf, prediction_svm = predict_url_type(url)
    if prediction_rf in ['benign', 'defacement']:
        result_str = "URL IS SAFE!"
        google_results = google_search(url)
    else:
        result_str = "URL IS MALICIOUS!"
        google_results = google_search(url)
    return jsonify({
        'prediction_rf': prediction_rf,
        'prediction_svm': prediction_svm,
        'result_str': result_str,
        'google_results': google_results
    })

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)

