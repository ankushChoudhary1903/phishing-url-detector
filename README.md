# Phishing URL Detection System

## Overview

This project implements a machine learning based phishing URL detection system designed to identify malicious websites hidden behind shortened URLs.

The system combines URL expansion, blacklist verification, and feature-based machine learning classification to assess whether a URL is legitimate or potentially malicious. A Streamlit web application is included for real-time URL analysis and prediction.

## Objective

Shortened URLs can obscure their actual destination, making them a common technique in phishing campaigns.

The objective of this project is to evaluate the effectiveness of URL-based feature engineering and blacklist verification for phishing detection without relying on webpage content analysis.

## Features

- Short URL expansion through redirect resolution
- PhishTank blacklist verification
- Extraction of 30 URL-based features
- Machine learning based phishing classification
- Risk assessment scoring
- Interactive Streamlit web interface
- Session history export functionality

## Dataset

Dataset used:

```text
UCI Phishing Websites Dataset
```

Source:

https://archive.ics.uci.edu/dataset/327/phishing+websites

### Dataset Characteristics

- Labeled phishing and legitimate website samples
- URL and domain-level attributes
- Suitable for supervised machine learning tasks
- Frequently used benchmark dataset for phishing detection research

## Detection Pipeline

The detection workflow consists of six stages.

### 1. URL Validation

The input URL is validated before analysis begins.

### 2. URL Expansion

Shortened URLs are expanded to reveal the final destination after redirection.

### 3. Blacklist Verification

The expanded URL is checked against known phishing indicators using PhishTank data.

### 4. Feature Extraction

Thirty URL-based features are extracted, including:

- URL length
- Presence of IP addresses
- Number of special characters
- HTTPS usage
- Domain characteristics
- Redirect behavior
- Suspicious token patterns

### 5. Machine Learning Classification

The extracted features are passed to a trained machine learning model for prediction.

### 6. Risk Assessment

The system returns one of the following classifications:

- Safe
- Suspicious
- Phishing

## Models Evaluated

| Model | Accuracy |
|---------|---------|
| Random Forest | 96.7% |
| Gradient Boosting | 95.1% |
| Support Vector Machine | 94.7% |
| K-Nearest Neighbors | 94.1% |
| Naive Bayes | 58.3% |

## Selected Model

Gradient Boosting was selected for deployment because it provided strong classification performance while maintaining consistent prediction behavior during testing.

Performance Metrics:

```text
Accuracy : 95.1%
AUC Score: 0.9902
```

## Web Application

Live Demo:

https://psudps-detector.streamlit.app

The application allows users to:

- Analyze URLs in real time
- Expand shortened links
- View prediction results
- Review session history
- Export analysis records

## Project Structure

```text
phishing-url-detector/
│
├── app.py
│
├── src/
│   └── url_pipeline.py
│
├── models/
│
├── notebooks/
│   ├── 02_EDA.ipynb
│   ├── 03_ML_Models.ipynb
│   ├── 04_URL_Pipeline_dev.ipynb
│   └── 05_Integration.ipynb
│
├── data/
│   ├── raw/
│   └── processed/
│
├── requirements.txt
└── README.md
```

## Installation

Create a Python environment:

```bash
conda create -n phishing-env python=3.11
conda activate phishing-env
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Launch the application:

```bash
streamlit run app.py
```

## Results

The evaluated machine learning models achieved classification accuracies above 94% with the exception of Naive Bayes.

Gradient Boosting achieved:

```text
Accuracy : 95.1%
AUC      : 0.9902
```

The combination of blacklist verification and feature-based classification provides an effective approach for identifying phishing URLs while maintaining a lightweight deployment workflow.

## Future Work

Potential improvements include:

- Real-time threat intelligence integration
- Domain reputation scoring
- Explainable AI based predictions
- Additional ensemble models
- Browser extension deployment
- Continuous blacklist updates

## References

1. UCI Machine Learning Repository – Phishing Websites Dataset  
   https://archive.ics.uci.edu/dataset/327/phishing+websites

2. PhishTank  
   https://phishtank.org
