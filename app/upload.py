# app/upload.py
import os
import pandas as pd

REQUIRED_COLS = ['account_name', 'current_role', 'system', 'last_login']


def upload_to_gcs(file_obj, filename):
    is_gcp = os.environ.get('GOOGLE_CLOUD_PROJECT') is not None

    if is_gcp:
        from google.cloud import storage
        import io
        env    = os.environ.get('ENV', 'test')
        bucket = storage.Client().bucket(os.environ['GCS_BUCKET_NAME'])
        blob   = bucket.blob(f'{env}/uploads/{filename}')
        blob.upload_from_file(file_obj)
        return f'gcs://{os.environ["GCS_BUCKET_NAME"]}/{env}/uploads/{filename}'
    else:
        upload_folder = os.path.join(os.getcwd(), 'local_uploads')
        os.makedirs(upload_folder, exist_ok=True)
        local_path = os.path.join(upload_folder, filename)
        file_obj.save(local_path)
        return f'local://{local_path}'


def parse_and_validate(uri):
    is_gcp = uri.startswith('gcs://')

    if is_gcp:
        from google.cloud import storage
        import io
        blob = storage.Blob.from_string(
            uri.replace('gcs://', 'gs://'),
            client=storage.Client()
        )
        data = blob.download_as_bytes()
        df = pd.read_csv(io.BytesIO(data)) if uri.endswith('.csv') \
             else pd.read_excel(io.BytesIO(data))
    else:
        local_path = uri.replace('local://', '')
        df = pd.read_csv(local_path) if local_path.endswith('.csv') \
             else pd.read_excel(local_path)

    missing_cols = [c for c in REQUIRED_COLS if c not in df.columns]
    if missing_cols:
        return df, [f'Missing required column: {c}' for c in missing_cols]

    errors = []
    for i, row in df.iterrows():
        missing = [c for c in REQUIRED_COLS
                   if pd.isna(row.get(c)) or str(row.get(c)).strip() == '']
        if missing:
            errors.append(f'Row {i + 2}: missing values in {", ".join(missing)}')

    return df, errors

