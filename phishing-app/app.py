from flask import Flask, render_template, request
import pickle
import pandas as pd
import re
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

# Load XGBoost model
def load_xgboost_model(model_path='phishing_model.pkl'):
    with open(model_path, 'rb') as file:
        model = pickle.load(file)
    return model

# Extract features from URLs
def extract_features(url):
    parsed_url = urlparse(url)
    features = {
        'UsingIP': 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else -1,
        'LongURL': 1 if len(url) > 75 else -1,
        'ShortURL': 1 if len(url) < 15 else -1,
        'Symbol@': 1 if '@' in url else -1,
        'Redirecting//': 1 if '//' in url[7:] else -1,
        'PrefixSuffix-': 1 if '-' in parsed_url.netloc else -1,
        'SubDomains': parsed_url.netloc.count('.'),
        'HTTPS': 1 if parsed_url.scheme == 'https' else -1,
        'GoogleIndex': 1 if 'google' in url else -1
    }
    return list(features.values())

# Predict phishing
def predict_phishing_xgboost(url, xgb_model):
    features = extract_features(url)
    features_df = pd.DataFrame([features])
    prediction = xgb_model.predict(features_df)[0]
    probability = xgb_model.predict_proba(features_df)[0][1]
    label_mapping = {0: "Legitimate", 1: "Phishing"}
    return label_mapping[prediction], probability

# Scrape and analyze URLs on a webpage
def scrape_and_analyze(url, xgb_model):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        urls = [link.get('href') for link in soup.find_all('a', href=True)]
        urls = [u for u in urls if u.startswith('http')]

        if not urls:
            return {}

        results = {}
        for u in urls[:10]:  # Limit to first 10 URLs
            result, prob = predict_phishing_xgboost(u, xgb_model)
            results[u] = (result, float(prob))

        return results
    except Exception as e:
        return {"Error": str(e)}

# Load the model
xgb_model = load_xgboost_model()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form['url'].strip()
    
    # Ensure URL is properly formatted
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  

    scrape = request.form.get('scrape')  # Will be 'true' if checked

    if scrape == 'true':
        results = scrape_and_analyze(url, xgb_model)
        
        # Fix the unpacking issue
        result_class = "phishing" if any(
            isinstance(val, tuple) and len(val) == 2 and val[0] == "Phishing"
            for val in results.values()
        ) else "legitimate"

        return render_template('scraping_result.html', results=results, result_class=result_class, url=url)
    else:
        result, prob = predict_phishing_xgboost(url, xgb_model)
        result_class = "phishing" if result == "Phishing" else "legitimate"
        return render_template('result.html', result=result, result_class=result_class, url=url)

if __name__ == '__main__':
    app.run(debug=True)
