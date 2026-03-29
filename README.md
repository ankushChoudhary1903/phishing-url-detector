# Phishing Short URL Detection and Prevention System

A machine learning system to detect phishing attacks hidden behind short URLs.
Based on research paper: "Detection and Prevention of Phishing Short URLs Using Machine Learning and Blacklist Approaches" by Odeh and Hijazi, 2025.

## Setup
1. Create conda environment: conda create -n phishing-env python=3.11
2. Activate: conda activate phishing-env
3. Install dependencies: pip install -r requirements.txt

## Dataset
Download the UCI Phishing Websites dataset from:
https://archive.ics.uci.edu/dataset/327/phishing+websites
Place it in data/raw/

## Best Model
Gradient Boosting - 97.1% Accuracy
