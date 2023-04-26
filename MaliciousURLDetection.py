import pandas as pd
import matplotlib
import re
from googlesearch import search
from urllib.parse import urlparse
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn import svm
from sklearn import metrics
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt

matplotlib.use('TkAgg')

df = pd.read_csv('Dataset/malicious_phish.csv', nrows=20000)

phishing_URLs = df[df.type == 'phishing']
Benign_URLs = df[df.type == 'benign']
Defacement_URLs = df[df.type == 'defacement']
Malware_URLs = df[df.type == 'malware']


# Feature Engineering
def contains_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'
        # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0


df['use_of_ip'] = df['url'].apply(lambda i: contains_ip_address(i))


# This feature can be extracted from the WHOIS database.
# For a legitimate website, identity is typically part of its URL.
def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0


df['abnormal_url'] = df['url'].apply(lambda i: abnormal_url(i))


def google_index(url):
    site = search(url, 5)
    return 1 if site else 0


df['google_index'] = df['url'].apply(lambda i: google_index(i))


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


# Length of URL
df['url_length'] = df['url'].apply(lambda i: url_length(i))


# Hostname Length
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


# First Directory Length
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

# Predictor Variables
# filtering out google_index as it has only 1 value
X = df[['use_of_ip', 'abnormal_url', 'count.', 'count-www', 'count@',
        'count_dir', 'count_embed_domian', 'short_url', 'count-https',
        'count-http', 'count%', 'count?', 'count-', 'count=', 'url_length',
        'hostname_length', 'sus_url', 'fd_length', 'count-digits',
        'count-letters']]

# Target Variable
y = df['url_type']

print(df.head(3))


X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, shuffle=True, random_state=5)

# create an SVM classifier
clf = svm.SVC(kernel='linear')

# train the classifier on the train set
clf.fit(X_train, y_train)

# predict on the test set
y_pred = clf.predict(X_test)

""" The absolute values of the coefficients are taken, since the sign of the coefficients depends on whether 
the corresponding feature is positively or negatively correlated with the target variable. 
Finally, the feature importances are plotted using a bar chart with the feature names on the x-axis."""

importances = abs(clf.coef_)

# plot the feature importances
plt.bar(range(X.shape[1]), importances[0])
plt.xticks(range(X.shape[1]), ['use_of_ip', 'abnormal_url', 'count.', 'count-www', 'count@',
        'count_dir', 'count_embed_domian', 'short_url', 'count-https',
        'count-http', 'count%', 'count?', 'count-', 'count=', 'url_length',
        'hostname_length', 'sus_url', 'fd_length', 'count-digits',
        'count-letters'], rotation=90)
plt.show()

# print the accuracy score of the classifier
print("SVM Accuracy:", metrics.accuracy_score(y_test, y_pred))


# Initialize Random Forest classifier
rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)

# Fit the model to the training data
rf_classifier.fit(X_train, y_train)

# Predict on the test data
y_pred = rf_classifier.predict(X_test)

# Evaluate model performance
accuracy = rf_classifier.score(X_test, y_test)
print("Random Forest accuracy:", accuracy)


# Initialize XGBoost classifier
xgb_classifier = xgb.XGBClassifier(learning_rate=0.1, max_depth=3, n_estimators=100)

# Fit the model to the training data
xgb_classifier.fit(X_train, y_train)

# Predict on the test data
y_pred_xgb = xgb_classifier.predict(X_test)

# Evaluate model performance
accuracy = accuracy_score(y_test, y_pred_xgb)
print("XGBoost accuracy:", accuracy)