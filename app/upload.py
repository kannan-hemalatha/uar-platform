from google.cloud import storage
import pandas as pd, os, io

REQUIRED_COLS = ['account_name','current_role','system','last_login']

def upload_to_gcs(file_obj, filename):
    env = os.environ.get('ENV', 'test')
    bucket = storage.Client().bucket(os.environ['GCS_BUCKET_NAME'])
    blob = bucket.blob(f'{env}/uploads/{filename}')
    blob.upload_from_file(file_obj)
    return f'gs://{os.environ["GCS_BUCKET_NAME"]}/{env}/uploads/{filename}'

def parse_and_validate(gcs_uri):
    blob = storage.Blob.from_string(gcs_uri, client=storage.Client())
    data = blob.download_as_bytes()
    df = pd.read_csv(io.BytesIO(data)) if gcs_uri.endswith('.csv') \
         else pd.read_excel(io.BytesIO(data))
    missing = df[df[REQUIRED_COLS].isnull().any(axis=1)].index.tolist()
    return df, [f'Row {i+2}: missing required fields' for i in missing]

