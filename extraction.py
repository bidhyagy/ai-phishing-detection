import urllib.parse
import tldextract
import requests

def extract_features(url):
    features = {}
    
    # १. LongURL फिचर (-1 यदि धेरै लामो छ भने, अन्यथा 1)
    # यदि URL को लम्बाई ५४ भन्दा धेरै छ भने यसलाई शङ्कास्पद मानिन्छ
    if len(url) < 54:
        features['LongURL'] = 1
    elif len(url) >= 54 and len(url) <= 75:
        features['LongURL'] = 0
    else:
        features['LongURL'] = -1

    # २. HTTPS फिचर (लिङ्क सुरक्षित छ कि छैन)
    if url.startswith("https"):
        features['HTTPS'] = 1
    else:
        features['HTTPS'] = -1

    # ३. PrefixSuffix- फिचर (डोमेनमा ड्यास '-' छ कि छैन)
    # ह्याकरहरूले अक्सर secure-bank.com जस्ता नाम प्रयोग गर्छन्
    ext = tldextract.extract(url)
    if '-' in ext.domain:
        features['PrefixSuffix-'] = -1
    else:
        features['PrefixSuffix-'] = 1

    return features

# चेक गर्नको लागि एउटा नक्कली जस्तो देखिने लिङ्क राखौँ
test_url = "http://secure-login-bank-details-update-now.com/identity/login"
result = extract_features(test_url)
print(result)