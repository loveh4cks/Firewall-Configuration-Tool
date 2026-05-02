import yaml
import json
import os
from typing import List, Dict, Any

class ConfigLoader:
    """Loads configuration policies from YAML or JSON files."""

    @staticmethod
    def load_policy(file_path: str) -> List[Dict[str, Any]]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Policy file not found: {file_path}")

        ext = os.path.splitext(file_path)[1].lower()
        
        with open(file_path, 'r') as f:
            if ext in ['.yaml', '.yml']:
                data = yaml.safe_load(f)
            elif ext == '.json':
                data = json.load(f)
            else:
                raise ValueError(f"Unsupported file format: {ext}")
        
        # Validate basic structure
        if not isinstance(data, dict) or 'rules' not in data:
            raise ValueError("Invalid policy format. Root directory must contain 'rules' list.")
            
        return data.get('rules', [])

if __name__ == "__main__":
    # Simple test
    print("ConfigLoader module ready.")
