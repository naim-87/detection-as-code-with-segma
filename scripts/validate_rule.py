import yaml
import json
import sys
from jsonschema import validate, ValidationError

def load_yaml(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def load_schema(schema_path):
    with open(schema_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def validate_rule(yaml_path, schema_path):
    try:
        rule = load_yaml(yaml_path)
        schema = load_schema(schema_path)
        validate(instance=rule, schema=schema)
        print(f"✅ {yaml_path} est valide.")
        return True
    except ValidationError as e:
        print(f"❌ Erreur de validation dans {yaml_path}: {e.message}")
        return False
    except Exception as e:
        print(f"❌ Erreur lecture: {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python validate_rule.py <rule.yml> <schema.json>")
        sys.exit(1)
    rule_file = sys.argv[1]
    schema_file = sys.argv[2]
    if not validate_rule(rule_file, schema_file):
        sys.exit(1)