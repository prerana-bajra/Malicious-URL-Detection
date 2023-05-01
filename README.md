# Malicious-URL-Detection

## Intoduction
The use of the internet is growing at an exponential rate. With the increasing availability of internet-enabled devices and the proliferation of internet- based services, people around the world are relying on the internet for everything from communication and entertainment to education and commerce. While the growth of the internet has brought many benefits, it has also created new challenges, particularly around cybersecurity. With more people and devices connected to the internet, the risk of cyber attacks such as phishing, malware, and data breaches has increased, making it more important than ever to ensure that online activities are conducted safely and securely.

A **URL (Uniform Resource Locator)** is a string of characters that provides a way to access a resource on the internet. It is essentially an address for a web page, file, or other resource that can be accessed through the internet. The risk of malicious URLs lies in the fact that they can be used by attackers to carry out a wide range of cyber attacks, including phishing attacks, malware distribution, and credential harvesting.

Detection of malicious URLs is necessary to prevent these attacks from occurring and to protect individuals and organizations from the harmful effects of cybercrime. By using machine learning, it is possible to identify and classify malicious URLs, enabling security professionals to block them before they can cause harm.

This project will focus on Detection of malicious URLs using machine learning.

## Methodology
The project has been divided into 4 parts:
<details>
  <summary> 1. Data Acquisition: </summary>

The source of the dataset is https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset?resource=download
This file consists of 651,191 URLs, out of which 428103 benign or safe URLs, 96457 defacement URLs, 94111 phishing URLs, and 32520 malware URLs. It has two columns comprising of url and a type which signifies the class of maliciousness.

    * Defacement URLs are URLs of websites that have been hacked and their content has been replaced or modified by the hacker.
    
    * Phishing URLs are malicious websites that are designed to deceive users into giving sensitive information.
    
    * Malware URLs are URLs that host or distribute malware, which refers to malicious software designed to harm or exploit computer systems. Malware can include viruses, Trojans, ransomware, spyware, and other types of harmful software. 
</details>

<details>
  <summary> 2. Data Preprocessing/Feature Engineering: </summary>
  The success of any ML model depends on the quality of training data and the quality of features fed into the model. Certain features must be available to analysts in order to create proactive models to identify malicious URLs. Simple URL strings can be used to extract these features, which can be lexical, content, or network. In this project, only lexical features are being used. 
  
  The lexical features include the elements of the URL string. They are determined by how the URL looks or seems different in users’ eyes and the URL’s textual properties. These include statistical properties such as the length of the URL, length of the domain, number of special characters, and number of digits in the URL.
  
* contains_ip_address: Generally cyber attackers use an IP address in place of the domain name to hide the identity of the website. this feature will check whether the URL has IP address or not.
* abnormal_url: This feature can be extracted from the WHOIS database. For a legitimate website, identity is typically part of its URL.
* google_index: In this feature, we check whether the URL is indexed in google search console or not.
* Count . : The phishing or malware websites generally use more than two sub-domains in the URL. Each domain is separated by dot (.). If any URL contains more than three dots(.), then it increases the probability of a malicious site.
* Count-www: Generally most of the safe websites have one www in its URL. This feature helps in detecting malicious websites if the URL has no or more than one www in its URL.
* count@: The presence of the “@” symbol in the URL ignores everything previous to it.
* Count_dir: The presence of multiple directories in the URL generally indicates suspicious websites.
* Count_embed_domain: The number of the embedded domains can be helpful in detecting malicious URLs. It can be done by checking the occurrence of “//” in the URL.
* Suspicious words in URL: Malicious URLs generally contain suspicious words in the URL such as PayPal, login, sign in, bank, account, update, bonus, service, ebayisapi, token, etc. We have found the presence of such frequently occurring suspicious words in the URL as a binary variable i.e., whether such words present in the URL or not.
* Short_url: This feature is created to identify whether the URL uses URL shortening services like bit. \ly, goo.gl, go2l.ink, etc.
* Count_https: Generally malicious URLs do not use HTTPS protocols as it generally requires user credentials and ensures that the website is safe for transactions. So, the presence or absence of HTTPS protocol in the URL is an important feature.
* Count_http: Most of the time, phishing or malicious websites have more than one HTTP in their URL whereas safe sites have only one HTTP.
* Count%: As we know URLs cannot contain spaces. URL encoding normally replaces spaces with symbol (%). Safe sites generally contain less number of spaces whereas malicious websites generally contain more spaces in their URL hence more number of %.
* Count?: The presence of symbol (?) in URL denotes a query string that contains the data to be passed to the server. More number of ? in URL definitely indicates suspicious URL.
* Count-: Phishers or cybercriminals generally add dashes(-) in prefix or suffix of the brand name so that it looks genuine URL.
* Count=: Presence of equal to (=) in URL indicates passing of variable values from one form page t another. It is considered as riskier in URL as anyone can change the values to modify the page.
* url_length: Attackers generally use long URLs to hide the domain name. We found the average length of a safe URL is 74.
* hostname_length: The length of the hostname is also an important feature for detecting malicious URLs.
* First directory length: This feature helps in determining the length of the first directory in the URL. So looking for the first ‘/’ and counting the length of the URL up to this point helps in finding the first directory length of the URL. For accessing directory level information we need to install python library TLD. You can check this link for installing TLD.
* Length of top-level domains: A top-level domain (TLD) is one of the domains at the highest level in the hierarchical Domain Name System of the Internet. For example, in the domain name www.example.com, the top-level domain is com. So, the length of TLD is also important in identifying malicious URLs. As most of the URLs have .com extension. TLDs in the range from 2 to 3 generally indicate safe URLs.
* Count_digits: The presence of digits in URL generally indicate suspicious URLs. Safe URLs generally do not have digits so counting the number of digits in URL is an important feature for detecting malicious URLs.
* Count_letters: The number of letters in the URL also plays a significant role in identifying malicious URLs. As attackers try to increase the length of the URL to hide the domain name and this is generally done by increasing the number of letters and digits in the URL.

  
</details>

<details>
  <summary> 3. Machine Learning </summary>
The machine learning model used in this project is SVM, Random Forest and XGBoost.
  
SVM stands for Support Vector Machine, a type of machine learning algorithm used for classification and regression analysis. It works by finding the best hyperplane that separates data points of different classes in a high-dimensional space.

Random Forest which is a machine-learning algorithm used for classification, regression, and other tasks. It is an ensemble learning method that works by combining multiple decision trees to make predictions. It is resistant to overfitting, and performs well on complex datasets.

XGBoost which stands for eXtreme Gradient Boosting, and it is a popular machine learning algorithm used for supervised learning tasks, such as classification and regression. XGBoost is an ensemble method that combines multiple weak prediction models, such as decision trees, to create a stronger and more accurate model. XGBoost works by iteratively training new models that correct the errors of the previous models. During each iteration, the algorithm evaluates the gradient of the loss function with respect to the current model's predictions and uses this information to update the model's parameters. This process is called gradient boosting.


</details>

<details>
  <summary> 4. Results </summary>
Evaluation Metric: Accuracy (the percentage of correct decisions among all correct samples)
  
  The accuracy obtained from the models are: 
  
  SVM Accuracy: 95.73%
  Random Forest Accuracy: 99.18%
  XGBoost Accuracy: 97.92%
 
</details>

<details>
  <summary> 5. Conclusion </summary>


  The Random Forest algorithm has proven to be effective in detecting malicious URLs in the current dataset. However, there is always room for improvement. By introducing network features, we can gain a better understanding of the URLs' behavior and potentially improve the classification accuracy. Additionally, using a larger dataset can provide more data points for the model to learn from and may lead to improved performance. Embedding the model in applications for easy interface can also automate the detection process, making it more efficient and scalable for real-time monitoring. However, it is important to fine-tune the model's hyperparameters and carefully evaluate its performance on the new dataset to ensure that any new features added are relevant and informative for the classification task.

</details>
