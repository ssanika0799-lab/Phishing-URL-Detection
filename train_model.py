import re
import ipaddress
import pandas as pd
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import pickle

def extract_features(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    hostname = parsed.netloc.split("@")[-1].split(":")[0].lower()
    path = parsed.path

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    return [
        len(url),
        url.count("."),
        url.count("-"),
        url.count("@"),
        url.count("?"),
        url.count("="),
        sum(c.isdigit() for c in url),
        int("https" != parsed.scheme),
        has_ip,
        int("@" in url),
        len(path),
        int(hostname.startswith("xn--"))
    ]

# Small illustrative training dataset.
# Label 0 = legitimate example; 1 = phishing example.
legitimate = [
    "https://www.wikipedia.org",
    "https://www.python.org",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.amazon.com",
    "https://www.github.com",
    "https://www.mozilla.org",
    "https://www.nasa.gov",
    "https://www.bbc.com",
    "https://www.adobe.com"
]

phishing = [
    "http://secure-login-verify.example.com/account",
    "http://paypal-login.example.net/verify",
    "http://account-update.example.org/signin",
    "http://192.0.2.10/login",
    "http://verify-user.example.com/reset?account=1",
    "http://xn--example.invalid/login",
    "http://bank-secure.example.net/update",
    "http://login.example.org/confirm?user=1",
    "http://free-gift.example.com/claim",
    "http://security-check.example.net/verify"
]

urls = legitimate + phishing
labels = [0] * len(legitimate) + [1] * len(phishing)

X = pd.DataFrame([extract_features(url) for url in urls])
y = pd.Series(labels)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

predictions = model.predict(X_test)
print("Test accuracy on illustrative sample:",
      round(accuracy_score(y_test, predictions) * 100, 2), "%")

with open("phishing_model.pkl", "wb") as file:
    pickle.dump(model, file)

print("Model saved as phishing_model.pkl")