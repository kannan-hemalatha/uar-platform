from google.cloud import storage
import pandas as pd, os, io

def upload_to_gcs(file_obj, filename):
    """Upload a file to GCS and return the GCS URI."""
    bucket_name = os.environ.get('GCS_BUCKET_NAME')
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(f'uploads/{filename}')
    blob.upload_from_file(file_obj)
    return f'gs://{bucket_name}/uploads/{filename}'

def parse_file_from_gcs(gcs_uri):
    """Download file from GCS and parse into a DataFrame."""
    client = storage.Client()
    blob = storage.Blob.from_string(gcs_uri, client=client)
    content = blob.download_as_bytes()
    if gcs_uri.endswith('.csv'):
        return pd.read_csv(io.BytesIO(content))
    else:
        return pd.read_excel(io.BytesIO(content))

REQUIRED_COLS = ['account_name', 'current_role', 'system', 'last_login']

def validate_dataframe(df):
    """Return list of (row_index, missing_cols) tuples for invalid rows."""
    errors = []
    for col in REQUIRED_COLS:
        if col not in df.columns:
            return None, [f'Missing required column: {col}']
    missing = df[df[REQUIRED_COLS].isnull().any(axis=1)]
    return df, [f'Row {i+2}: missing required fields' for i in missing.index.tolist()]

