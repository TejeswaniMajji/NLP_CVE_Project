# CVE NLP Trend Analysis and Prediction

This project explores CVE data with NLP, machine learning, and time-series analysis. The main work is in the notebook [CVE_NLP_Trend_Analysis_with_prediction_(1).ipynb](CVE_NLP_Trend_Analysis_with_prediction_(1).ipynb), with a small Flask backend in [web/backend](web/backend) for serving predictions.

## What this project does

- Pulls CVE details from the NVD API.
- Cleans and tokenizes CVE descriptions.
- Extracts structured security fields such as exploit type, affected component, and impact.
- Predicts severity using zero-shot BERT and compares it with classical ML.
- Stores processed CVE data in SQLite for querying.
- Builds temporal trend charts and forecasts future CVE counts.
- Exposes a simple API for prediction through Flask.

## Step-by-Step Process

### 1. Install dependencies

The notebook begins by installing the libraries needed for data processing, modeling, visualization, and API access:

- `transformers`
- `torch`
- `scikit-learn`
- `pandas`
- `matplotlib`
- `seaborn`
- `requests`
- `beautifulsoup4`
- `datasets`

### 2. Collect CVE data from NVD

The notebook fetches CVE records from the NVD API using a single CVE lookup flow. It validates the CVE format, calls the API, and builds a dataframe with fields such as:

- CVE ID
- description
- year
- CVSS score
- CWE
- weaknesses

### 3. Preprocess the text

The CVE descriptions are cleaned before modeling. The preprocessing stage includes:

- lowercasing text
- regex-based cleanup
- removing extra punctuation and noise
- whitespace tokenization
- token count generation

### 4. Extract structured security information

The notebook derives structured labels from the descriptions, including:

- exploit type
- affected component
- impact summary

This gives a more organized dataset for later analysis and prediction.

### 5. Predict severity with NLP models

The notebook compares severity prediction approaches:

- zero-shot BERT classification using `facebook/bart-large-mnli`
- classical ML using TF-IDF features and Random Forest

It also compares predictions against severity derived from CVSS scores.

### 6. Fine-tune a transformer for CVE text classification

For the main text-classification task, the notebook fine-tunes a transformer model and applies it to CVE descriptions. The workflow follows the usual sequence:

- load a labeled dataset
- tokenize text
- fine-tune the model
- evaluate the result
- run inference on CVE descriptions

### 7. Store processed data in SQLite

Processed CVE data is stored in SQLite (`cve_research.db`). This makes it possible to:

- filter records by severity
- group by year
- rank exploit types
- query the final processed dataset

### 8. Analyze temporal trends

The notebook then performs trend analysis across years and exploit types. It produces charts for:

- year-wise attack type counts
- affected component distribution
- exploit type distribution
- CVSS score distribution

It also fits forecasting models to estimate future CVE counts.

### 9. Run the interactive prediction tool

The final notebook section provides an interactive CVE prediction flow. It accepts a CVE ID, fetches live NVD data, and predicts:

- severity
- exploit type
- affected component
- impact summary
- reasoning

## Backend API

The Flask app in [web/backend/app.py](web/backend/app.py) serves the prediction endpoint.

### Available routes

- `GET /` returns the static frontend.
- `POST /api/predict` accepts either `cve_id` or `description` and returns prediction results.

## How to run

### Notebook

1. Open [CVE_NLP_Trend_Analysis_with_prediction_(1).ipynb](CVE_NLP_Trend_Analysis_with_prediction_(1).ipynb).
2. Run the cells from top to bottom.
3. If you use the API-driven steps, make sure you have network access and the required API keys.

### Backend

1. Go to [web/backend](web/backend).
2. Create and activate a virtual environment.
3. Install dependencies from [web/backend/requirements.txt](web/backend/requirements.txt).
4. Run the Flask app:

```bash
python app.py
```

5. Open `http://localhost:5000`.

## Project Structure

- [CVE_NLP_Trend_Analysis_with_prediction_(1).ipynb](CVE_NLP_Trend_Analysis_with_prediction_(1).ipynb) - main analysis notebook
- [scripts](scripts) - helper scripts for notebook widget cleanup
- [web/backend](web/backend) - Flask backend and static frontend

## Notes

- The notebook uses live CVE data, so results can change over time.
- Some notebook sections depend on API access and may require valid keys.
- The analysis was built to support both structured extraction and forecasting on CVE trends.