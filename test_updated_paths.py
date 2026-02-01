# test_updated_paths.py
import os

# Test with local path
os.environ['PERSISTENT_DATA_PATH'] = 'test_data_local'

def get_data_path(subpath=''):
    """Test version"""
    base_path = os.environ.get('PERSISTENT_DATA_PATH', 'data')
    full_path = os.path.join(base_path, subpath)
    
    if '/' in subpath:
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
    
    return full_path

# Test paths
test_cases = [
    ("'data/users.json'", get_data_path('users.json')),
    ('"data/users.json"', get_data_path("users.json")),
    ("'data/events/test.json'", get_data_path('events/test.json')),
    ("'data/reports/form_reports.json'", get_data_path('reports/form_reports.json')),
]

print("Testing updated paths:")
for original, updated in test_cases:
    print(f"  {original:35} → {updated}")
