# Phishing Short URL Detection and Prevention System (PSUDPS)

A machine learning system to detect phishing attacks hidden
behind short URLs. Based on research paper: "Detection and
Prevention of Phishing Short URLs Using Machine Learning and
Blacklist Approaches" by Odeh and Hijazi, 2025.

## Live Demo

🌐 https://psudps-detector.streamlit.app

## Features

- Expands short URLs to reveal true destination
- Checks against PhishTank blacklist database
- Extracts 30 URL-based features for ML analysis
- Gradient Boosting model with 95%+ accuracy
- Three verdict levels: SAFE / SUSPICIOUS / PHISHING
- Session history with CSV export

## Setup

1. Create conda environment: conda create -n phishing-env python=3.11
2. Activate: conda activate phishing-env
3. Install dependencies: pip install -r requirements.txt
4. Run locally: streamlit run app.py

## Dataset

Download the UCI Phishing Websites dataset from:
https://archive.ics.uci.edu/dataset/327/phishing+websites
Place it in data/raw/

## Project Structure

```
phishing-url-detector/
├── app.py                  ← Streamlit web application
├── src/url_pipeline.py     ← Complete ML pipeline
├── models/                 ← Saved trained models
├── notebooks/              ← EDA and ML training notebooks
│   ├── 02_EDA.ipynb
│   ├── 03_ML_Models.ipynb
│   ├── 04_URL_Pipeline_dev.ipynb
│   └── 05_Integration.ipynb
└── data/
    ├── raw/                ← Original dataset
    └── processed/          ← Charts and results
```

## ML Models Performance

| Model             | Accuracy |
| ----------------- | -------- |
| Gradient Boosting | 95.1% 🥇 |
| KNN               | 94.1%    |
| Random Forest     | 96.7%    |
| SVM               | 94.7%    |
| Naive Bayes       | 58.3%    |

## Best Model

Gradient Boosting — 95%+ Accuracy
AUC Score: 0.9902

## How It Works

1. Input URL validated
2. Short URL expanded via redirect following
3. Expanded URL checked against PhishTank blacklist
4. 30 features extracted from URL structure
5. Gradient Boosting model predicts phishing probability
6. Final verdict: SAFE / SUSPICIOUS / PHISHING
