# app/upload.py
import os
import pandas as pd

# Canonical required fields the platform stores per UAR entry.
REQUIRED_COLS = ['account_name', 'current_role', 'system', 'last_login']
OPTIONAL_COLS = ['justification']
ALL_TARGET_FIELDS = REQUIRED_COLS + OPTIONAL_COLS

# DEF-020 FIX: alias map used for automatic column-name mapping. Source headers
# (lower-cased, stripped) on the left map to canonical target fields on the
# right. This lets files using 'User Name', 'permissions', etc. be mapped
# automatically, with the Initiator able to review/adjust before submission.
COLUMN_ALIASES = {
    'account_name':  ['account_name', 'account name', 'user name', 'username',
                      'user', 'account', 'login', 'login id', 'user id', 'userid'],
    'current_role':  ['current_role', 'current role', 'role', 'permissions',
                      'permission', 'access', 'access level', 'entitlement',
                      'entitlements', 'group', 'privilege'],
    'system':        ['system', 'system/application', 'system / application',
                      'application', 'app', 'system name', 'platform', 'resource'],
    'last_login':    ['last_login', 'last login', 'last login date',
                      'last_login_date', 'lastlogin', 'last access',
                      'last accessed', 'last sign-in', 'last signin'],
    'justification': ['justification', 'business justification',
                      'business justification/ peer group context',
                      'business justification / peer group context',
                      'peer group context', 'reason', 'notes', 'comment'],
}


def upload_to_gcs(file_obj, filename):
    """Persist the uploaded file (GCS in cloud, local disk in dev) and return
    a URI the parser can later read."""
    is_gcp = os.environ.get('GOOGLE_CLOUD_PROJECT') is not None

    if is_gcp:
        from google.cloud import storage
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


def _read_dataframe(uri):
    """Load the stored file into a DataFrame (handles GCS or local)."""
    if uri.startswith('gcs://'):
        from google.cloud import storage
        import io
        blob = storage.Blob.from_string(
            uri.replace('gcs://', 'gs://'), client=storage.Client())
        data = blob.download_as_bytes()
        return pd.read_csv(io.BytesIO(data)) if uri.endswith('.csv') \
            else pd.read_excel(io.BytesIO(data))
    else:
        local_path = uri.replace('local://', '')
        return pd.read_csv(local_path) if local_path.endswith('.csv') \
            else pd.read_excel(local_path)


def analyze_upload(uri):
    """DEF-019 / DEF-020 FIX: pre-submission analysis of an uploaded file.

    Returns a dict describing:
      - source_columns: the raw headers found in the file
      - duplicate_columns: headers that appear more than once
      - auto_mapping: best-guess mapping {source_header -> target_field}
      - unmapped_columns: source headers we could not map
      - missing_required: required target fields with no mapped source column
      - row_count: number of data rows
    The Initiator reviews and can adjust this mapping before any data is saved.
    """
    df = _read_dataframe(uri)
    source_columns = [str(c) for c in df.columns]

    # DEF-020 FIX: detect duplicate column names (case-insensitive).
    seen, duplicate_columns = {}, []
    for c in source_columns:
        key = c.strip().lower()
        seen[key] = seen.get(key, 0) + 1
    duplicate_columns = [c for c in source_columns
                         if seen[c.strip().lower()] > 1]

    # Build reverse alias lookup: normalized source header -> target field.
    reverse = {}
    for target, aliases in COLUMN_ALIASES.items():
        for a in aliases:
            reverse[a] = target

    auto_mapping = {}
    used_targets = set()
    for c in source_columns:
        key = c.strip().lower()
        target = reverse.get(key)
        # Only auto-map the FIRST source column that claims a given target,
        # so duplicates don't silently overwrite each other.
        if target and target not in used_targets:
            auto_mapping[c] = target
            used_targets.add(target)
        else:
            auto_mapping[c] = ''     # unmapped / needs Initiator decision

    unmapped_columns = [c for c, t in auto_mapping.items() if not t]
    missing_required = [f for f in REQUIRED_COLS if f not in used_targets]

    return {
        'source_columns':    source_columns,
        'duplicate_columns': list(dict.fromkeys(duplicate_columns)),
        'auto_mapping':      auto_mapping,
        'unmapped_columns':  unmapped_columns,
        'missing_required':  missing_required,
        'row_count':         int(len(df)),
        'target_fields':     ALL_TARGET_FIELDS,
        'required_fields':   REQUIRED_COLS,
    }


def build_rows(uri, mapping):
    """DEF-020 / DEF-021 FIX: using the Initiator-confirmed mapping
    {source_header -> target_field}, return (rows, errors) where rows is a
    list of dicts keyed by canonical target field. Validates that every
    required field is present and non-empty per row.
    """
    df = _read_dataframe(uri)
    # Invert mapping: target_field -> source_header (ignore blanks).
    target_to_source = {}
    for source, target in mapping.items():
        if target:
            target_to_source[target] = source

    errors = []
    missing_required = [f for f in REQUIRED_COLS if f not in target_to_source]
    if missing_required:
        errors.append('Cannot proceed: no column mapped to required field(s): '
                      + ', '.join(missing_required))
        return [], errors

    rows = []
    for i, row in df.iterrows():
        record = {}
        row_missing = []
        for target in ALL_TARGET_FIELDS:
            source = target_to_source.get(target)
            val = '' if source is None else row.get(source, '')
            val = '' if pd.isna(val) else str(val).strip()
            record[target] = val
            if target in REQUIRED_COLS and val == '':
                row_missing.append(target)
        if row_missing:
            errors.append(f'Row {i + 2}: missing values in '
                          f'{", ".join(row_missing)}')
        rows.append(record)

    return rows, errors


# ----------------------------------------------------------------------
# Backwards-compatible helper retained so existing imports do not break.
# DEF-020: parse_and_validate now delegates to the alias-aware mapper using
# the auto-mapping, so the legacy direct-upload path still works.
# ----------------------------------------------------------------------
def parse_and_validate(uri):
    analysis = analyze_upload(uri)
    rows, errors = build_rows(uri, analysis['auto_mapping'])
    df = pd.DataFrame(rows) if rows else _read_dataframe(uri)
    return df, errors
