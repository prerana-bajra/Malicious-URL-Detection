import pandas as pd
from autoviz.classify_method import data_cleaning_suggestions, data_suggestions
import matplotlib
import matplotlib.pyplot as plt
from wordcloud import WordCloud, STOPWORDS

matplotlib.use('TkAgg')

data = pd.read_csv('Dataset/malicious_phish.csv')
print(data.shape)
print(data.head())
print(data.tail())
print(data.info())
print(data.dtypes)
print("---")
data_cleaning_suggestions(data)


phishing_URLs = data[data.type == 'phishing']
Benign_URLs = data[data.type == 'benign']
Defacement_URLs = data[data.type == 'defacement']
Malware_URLs = data[data.type == 'malware']


# --- Wordcloud --- #

ben = " ".join(i for i in Benign_URLs.url)
wordcloud = WordCloud(width=1600, height=800,colormap='Paired').generate(ben)
plt.figure( figsize=(12,14),facecolor='k')
plt.title("Benign_URLs")
plt.imshow(wordcloud, interpolation='bilinear')
plt.axis("off")
plt.tight_layout(pad=0)
plt.show()


phish = " ".join(i for i in phishing_URLs.url)
wordcloud = WordCloud(width=1600, height=800,colormap='Paired').generate(phish)
plt.figure( figsize=(12,14),facecolor='k')
plt.title("phishing_URLs")
plt.imshow(wordcloud, interpolation='bilinear')
plt.axis("off")
plt.tight_layout(pad=0)
plt.show()

deface = " ".join(i for i in Defacement_URLs.url)
wordcloud = WordCloud(width=1600, height=800,colormap='Paired').generate(deface)
plt.figure( figsize=(12,14),facecolor='k')
plt.title("Defacement_URLs")
plt.imshow(wordcloud, interpolation='bilinear')
plt.axis("off")
plt.tight_layout(pad=0)
plt.show()

mal = " ".join(i for i in Malware_URLs.url)
wordcloud = WordCloud(width=1600, height=800,colormap='Paired').generate(mal)
plt.figure( figsize=(12,14),facecolor='k')
plt.title("Malware_URLs")
plt.imshow(wordcloud, interpolation='bilinear')
plt.axis("off")
plt.tight_layout(pad=0)
plt.show()

