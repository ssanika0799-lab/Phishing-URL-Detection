from flask import Flask, request, render_template_string
from urllib.parse import urlparse
import ipaddress
import pickle
import pandas as pd
from train_model import extract_features

app = Flask(__name__)

with open("phishing_model.pkl", "rb") as file:
    model = pickle.load(file)

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhishGuard | URL Security Scanner</title>

<style>
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: Inter, "Segoe UI", Arial, sans-serif;
    color: #f1f5f9;
    background: #080d1b;
    min-height: 100vh;
    overflow-x: hidden;
}

body::before {
    content: "";
    position: fixed;
    width: 480px;
    height: 480px;
    background: #4338ca;
    filter: blur(170px);
    opacity: 0.22;
    top: -200px;
    left: -150px;
    pointer-events: none;
}

body::after {
    content: "";
    position: fixed;
    width: 400px;
    height: 400px;
    background: #0891b2;
    filter: blur(170px);
    opacity: 0.13;
    right: -150px;
    bottom: -180px;
    pointer-events: none;
}

header {
    position: relative;
    z-index: 1;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 22px 7%;
    border-bottom: 1px solid #20283b;
}

.brand {
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 21px;
    font-weight: 750;
    letter-spacing: -0.5px;
}

.logo {
    width: 42px;
    height: 42px;
    border-radius: 13px;
    display: grid;
    place-items: center;
    background: linear-gradient(135deg, #6366f1, #06b6d4);
    font-size: 23px;
}

.brand span {
    color: #818cf8;
}

.status {
    color: #a7f3d0;
    border: 1px solid #17664f;
    background: #0b2925;
    border-radius: 30px;
    padding: 9px 13px;
    font-size: 12px;
}

main {
    width: min(900px, 90%);
    margin: auto;
    padding: 75px 0 55px;
    position: relative;
    z-index: 1;
}

.hero {
    text-align: center;
    margin-bottom: 38px;
}

.eyebrow {
    display: inline-block;
    color: #a5b4fc;
    background: #191c3a;
    border: 1px solid #33366b;
    padding: 8px 15px;
    border-radius: 30px;
    font-size: 12px;
    letter-spacing: 1.2px;
    margin-bottom: 22px;
}

h1 {
    font-size: clamp(34px, 6vw, 56px);
    line-height: 1.12;
    letter-spacing: -2px;
    margin-bottom: 20px;
}

.gradient {
    background: linear-gradient(90deg, #818cf8, #22d3ee);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
}

.subtitle {
    color: #a1acc2;
    line-height: 1.8;
    max-width: 600px;
    margin: auto;
    font-size: 15px;
}

.scanner {
    background: rgba(18, 26, 45, 0.92);
    border: 1px solid #303a52;
    border-radius: 22px;
    padding: 30px;
    box-shadow: 0 25px 70px rgba(0, 0, 0, 0.25);
}

.scanner-label {
    font-size: 14px;
    font-weight: 650;
    margin-bottom: 13px;
}

.input-wrap {
    display: flex;
    gap: 12px;
}

input {
    flex: 1;
    min-width: 0;
    padding: 17px;
    border-radius: 11px;
    border: 1px solid #3b4660;
    background: #0b1223;
    color: white;
    font-size: 14px;
    outline: none;
}

input:focus {
    border-color: #818cf8;
    box-shadow: 0 0 0 3px rgba(129, 140, 248, 0.13);
}

input::placeholder {
    color: #73809b;
}

button {
    border: none;
    border-radius: 11px;
    padding: 0 23px;
    color: white;
    background: linear-gradient(120deg, #6366f1, #4f46e5);
    font-size: 14px;
    font-weight: 700;
    cursor: pointer;
    transition: transform 0.2s, opacity 0.2s;
}

button:hover {
    transform: translateY(-2px);
    opacity: 0.93;
}

button:disabled {
    opacity: 0.65;
    cursor: wait;
}

.hint {
    color: #8995ad;
    font-size: 12px;
    margin-top: 13px;
}

.result {
    margin-top: 23px;
    border-radius: 13px;
    padding: 21px;
    background: #101a2d;
    border: 1px solid #35415b;
    animation: appear 0.35s ease;
}

.result.safe {
    border-color: #167a59;
    background: rgba(6, 78, 59, 0.22);
}

.result.danger {
    border-color: #a53d51;
    background: rgba(127, 29, 29, 0.2);
}

.result.invalid {
    border-color: #a16207;
}

.result h2 {
    font-size: 20px;
    margin-bottom: 10px;
}

.result p {
    color: #c1ccdc;
    font-size: 14px;
    line-height: 1.7;
    overflow-wrap: anywhere;
}

.result .scanned-url {
    color: #94a3b8;
    margin-top: 12px;
    font-size: 12px;
}

.features {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 17px;
    margin-top: 26px;
}

.feature {
    padding: 22px 17px;
    border: 1px solid #273249;
    background: rgba(16, 24, 42, 0.82);
    border-radius: 16px;
}

.feature-icon {
    font-size: 25px;
    margin-bottom: 15px;
}

.feature h3 {
    font-size: 14px;
    margin-bottom: 9px;
}

.feature p {
    color: #94a3b8;
    font-size: 12px;
    line-height: 1.7;
}

.notice {
    margin-top: 24px;
    padding: 17px;
    border-radius: 12px;
    border: 1px solid #3c354f;
    background: rgba(45, 32, 66, 0.4);
    color: #c4b5fd;
    font-size: 12px;
    line-height: 1.8;
}

footer {
    position: relative;
    z-index: 1;
    border-top: 1px solid #20283b;
    text-align: center;
    padding: 25px 15px;
    color: #78869e;
    font-size: 12px;
    line-height: 1.8;
}

@keyframes appear {
    from { opacity: 0; transform: translateY(8px); }
    to { opacity: 1; transform: translateY(0); }
}

@media (max-width: 600px) {
    header {
        padding: 17px 5%;
    }

    .brand {
        font-size: 17px;
    }

    .status {
        font-size: 10px;
        padding: 7px 9px;
    }

    main {
        padding-top: 48px;
    }

    h1 {
        letter-spacing: -1px;
    }

    .scanner {
        padding: 20px;
    }

    .input-wrap {
        flex-direction: column;
    }

    input, button {
        min-height: 51px;
        width: 100%;
    }

    .features {
        grid-template-columns: 1fr;
    }
}
</style>
</head>

<body>
<header>
    <div class="brand">
        <div class="logo">🛡️</div>
        Phish<span>Guard</span>
    </div>
    <div class="status">● ML Scanner</div>
</header>

<main>
    <section class="hero">
        <div class="eyebrow">CYBERSECURITY • URL ANALYSIS</div>
        <h1>Stay one step ahead of<br>
            <span class="gradient">online threats.</span>
        </h1>
        <p class="subtitle">
            Analyze website URLs with a Machine Learning prototype
            designed to identify potentially suspicious patterns.
        </p>
    </section>

    <section class="scanner">
        <div class="scanner-label">🔎 Enter a website URL to analyze</div>
        <form method="POST" id="scanForm">
            <div class="input-wrap">
                <input
                    type="text"
                    name="url"
                    id="urlInput"
                    placeholder="https://example.com"
                    value="{{ url }}"
                    autocomplete="url"
                    required>
                <button type="submit" id="scanButton">
                    Analyze URL →
                </button>
            </div>
        </form>
        <p class="hint">
            Enter a URL for feature-based analysis. No website is opened.
        </p>

        {% if result %}
        <div class="result {{ result_type }}" role="status">
            <h2>{{ result_icon }} {{ result }}</h2>
            <p>{{ message }}</p>
            <p class="scanned-url">Analyzed URL: {{ url }}</p>
        </div>
        {% endif %}
    </section>

    <section class="features">
        <div class="feature">
            <div class="feature-icon">🧠</div>
            <h3>ML-Based Analysis</h3>
            <p>Uses a trained Random Forest model to classify URL features.</p>
        </div>
        <div class="feature">
            <div class="feature-icon">⚡</div>
            <h3>Quick Results</h3>
            <p>Analyze URL patterns directly from this dashboard.</p>
        </div>
        <div class="feature">
            <div class="feature-icon">🔐</div>
            <h3>Security Awareness</h3>
            <p>Learn to recognize suspicious links before interacting with them.</p>
        </div>
    </section>

    <div class="notice">
        <strong>⚠️ Educational prototype:</strong>
        Predictions are not a guarantee of safety or maliciousness.
        The current model uses a very small illustrative dataset.
        Do not enter passwords or sensitive information on unfamiliar sites.
    </div>
</main>

<footer>
    PhishGuard — Intelligent Phishing URL Detection System<br>
    CSE Final Year Project • Machine Learning Prototype
</footer>

<script>
const form = document.getElementById("scanForm");
const button = document.getElementById("scanButton");

form.addEventListener("submit", function () {
    button.disabled = true;
    button.textContent = "Analyzing...";
});
</script>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def home():
    result = ""
    message = ""
    url = ""
    result_type = ""
    result_icon = ""

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        candidate = url if "://" in url else "http://" + url
        parsed = urlparse(candidate)

        try:
            hostname = parsed.hostname or ""
            valid_host = bool(hostname and "." in hostname)

            if hostname:
                try:
                    ipaddress.ip_address(hostname)
                    valid_host = True
                except ValueError:
                    pass

            if (
                parsed.scheme not in ("http", "https")
                or not valid_host
                or any(c.isspace() for c in url)
                or parsed.username is not None
                or parsed.password is not None
            ):
                result = "Invalid URL"
                message = "Enter a valid HTTP or HTTPS website URL."
                result_type = "invalid"
                result_icon = "⚠️"

            else:
                features = pd.DataFrame([extract_features(url)])
                prediction = int(model.predict(features)[0])

                if prediction == 1:
                    result = "Potential Phishing"
                    message = (
                        "The model detected suspicious URL patterns. "
                        "Avoid interacting with this link until it has "
                        "been checked using trusted security tools."
                    )
                    result_type = "danger"
                    result_icon = "🚨"
                else:
                    result = "Likely Legitimate"
                    message = (
                        "The model did not identify a phishing pattern. "
                        "This does not guarantee that the website is safe."
                    )
                    result_type = "safe"
                    result_icon = "🔎"

        except Exception:
            result = "Analysis Error"
            message = "The URL could not be analyzed. Please try again."
            result_type = "invalid"
            result_icon = "⚠️"

    return render_template_string(
        HTML,
        result=result,
        message=message,
        url=url,
        result_type=result_type,
        result_icon=result_icon,
    )


if __name__ == "__main__":
    app.run(debug=True)