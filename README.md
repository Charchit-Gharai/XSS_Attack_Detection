# XSS Attack Detection

A lightweight machine learning-based web application for identifying potential XSS (Cross-Site Scripting) attack patterns in URLs. The project uses a trained Random Forest model and a Streamlit interface to classify whether an input URL contains suspicious XSS indicators.

## Overview

Cross-Site Scripting is one of the most common web application vulnerabilities. Attackers inject JavaScript or malicious script payloads into a website, which are then executed in a victim’s browser. This project aims to detect suspicious URL patterns by analyzing features such as:

- `<script>` tags
- `alert()` function calls
- `document.cookie` usage
- `<img>` tags
- `onerror` handlers
- URL length and structure indicators

The app converts the submitted URL into a feature vector and passes it to a trained ML model for classification.

## Features

- Real-time XSS URL classification through a Streamlit app
- Feature extraction from suspicious URL strings
- URL decoding before prediction
- Random Forest-based classification model
- Simple and user-friendly web interface
- Easy setup and deployment

## Tech Stack

- Python
- Streamlit
- pandas
- scikit-learn
- joblib
- NumPy

## Project Structure

```text
XSS_Attack_Detection/
├── app.py                     # Streamlit web application and prediction logic
├── random_forest_model.joblib # Trained machine learning model
├── requirements.txt          # Python dependencies
├── README.md                 # Project documentation
└── .venv/                    # Optional virtual environment (not committed)
```

## Installation

1. Clone the repository:

```bash
git clone https://github.com/Charchit-Gharai/XSS_Attack_Detection.git
cd XSS_Attack_Detection
```

2. Create and activate a virtual environment:

```bash
python -m venv .venv
```

On macOS/Linux:

```bash
source .venv/bin/activate
```

On Windows:

```bash
.venv\Scripts\activate
```

3. Install the dependencies:

```bash
pip install -r requirements.txt
```

## Run the Application

Start the app with:

```bash
streamlit run app.py
```

Then open the local URL shown in the terminal (typically `http://localhost:8501`).

## How It Works

The application follows this pipeline:

1. The user enters a URL into the Streamlit interface.
2. The URL is URL-decoded and cleaned.
3. Relevant XSS-related features are extracted.
4. The extracted features are converted into a DataFrame.
5. A pre-trained Random Forest model predicts whether the input matches a suspicious XSS pattern.
6. The result is displayed in the app interface.

## Example

Example payloads that may trigger XSS detection patterns include:

```text
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
javascript:alert(document.cookie)
```

## Model Details

The model is saved as `random_forest_model.joblib` and is loaded in `app.py`. It uses handcrafted features derived from malicious script patterns, which allows the app to classify suspicious URLs efficiently.

## Limitations

- This project is intended for educational and demonstration purposes.
- Detection is based on heuristic feature analysis and may not cover every possible XSS payload variant.
- It should be used as part of a broader security assessment workflow, not as a standalone production-grade security control.

## Contributing

Contributions are welcome. If you would like to improve the detection logic, add more URL indicators, or enhance the UI, feel free to submit a pull request.

## License

This project is provided for educational and research purposes. No explicit license file is included in the repository at this time.

## Author

Charchit Gharai
