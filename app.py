import streamlit as st
import joblib
import urllib.parse
import pandas as pd
import re

# Load the trained model
model = joblib.load('random_forest_model.joblib')

# Define the feature extraction function
def extract_features(text):
    """Extract features from the URL to classify XSS attack type."""
    return {
        'has_script_tag': bool(re.search(r'<script>', text, re.IGNORECASE)),
        'has_alert_function': bool(re.search(r'alert\s*\(', text, re.IGNORECASE)),
        'has_document_cookie': bool(re.search(r'document\.cookie', text, re.IGNORECASE)),
        'has_img_tag': bool(re.search(r'<img', text, re.IGNORECASE)),
        'has_onerror': bool(re.search(r'onerror\s*=', text, re.IGNORECASE)),
        'length_of_text': len(text)
    }

# Function to process and classify the input URL
def classify_xss(url):
    """Classify the type of XSS attack using feature extraction and model prediction."""
    # Decode the URL
    decoded_url = urllib.parse.unquote(url)
    
    # Extract features from the URL using the extract_features function
    features = extract_features(decoded_url)
    
    # Convert features to a DataFrame
    features_df = pd.DataFrame([features])
    
    # Predict the XSS attack type using the trained model
    prediction = model.predict(features_df)[0]
    return prediction

# CSS styling
css_style = """
<style>
/* General Body Style */
body {
    font-family: Arial, sans-serif;
    background-color: #f5faff;
    margin: 0;
    padding: 0;
}

/* Title Section */
h1 {
    color: #ffffff;
    text-align: center;
    background-color: #6ed7e1;
    padding: 15px;
    border-radius: 5px;
}

/* Form Section */
.container {
    max-width: 600px;
    margin: 50px auto;
    background-color: #ffffff;
    padding: 20px;
    border: 1px solid #dfe6e9;
    border-radius: 8px;
    box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1);
}

/* Input Field */
input[type="text"] {
    width: 100%;
    padding: 10px;
    margin: 10px 0;
    border: 1px solid #ced4da;
    border-radius: 5px;
    font-size: 16px;
}

/* Button Style */
button {
    background-color: #2ecc71;
    color: #ffffff;
    padding: 10px 20px;
    border: none;
    border-radius: 5px;
    font-size: 16px;
    cursor: pointer;
    width: 100%;
}

button:hover {
    background-color: #27ae60;
}

/* Result Section */
.result {
    margin-top: 20px;
    font-size: 18px;
    font-weight: bold;
    color: #e74c3c;
}

/* Success Message */
.success {
    color: #2ecc71;
}
</style>
"""

# Add the CSS to the app
st.markdown(css_style, unsafe_allow_html=True)

# Streamlit App UI
st.markdown('<h1>XSS Attack Detection and Classification</h1>', unsafe_allow_html=True)


# URL input
url_input = st.text_input("Enter an URL to check if it's vulnerable to XSS attack:", placeholder="https://example.com")

# Prediction button
if st.button("Classify URL"):
    if url_input.strip():
        try:
            # Perform classification
            attack_type = classify_xss(url_input)
            # Display the result
            st.markdown(f'<p class="success">The URL is classified as: <strong>{attack_type}</strong> XSS attack.</p>', unsafe_allow_html=True)
        except ValueError as e:
            st.markdown(f'<p class="result">Feature mismatch error: {str(e)}</p>', unsafe_allow_html=True)
        except Exception as e:
            st.markdown(f'<p class="result">An error occurred: {str(e)}</p>', unsafe_allow_html=True)
    else:
        st.markdown('<p class="result">Please enter a valid URL.</p>', unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True)
