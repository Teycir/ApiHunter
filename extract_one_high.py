#!/usr/bin/env python3
import json

# Read the scan results
with open('final_results.json', 'r') as f:
    lines = f.readlines()

# Find first HIGH severity finding
for line in lines:
    try:
        data = json.loads(line.strip())
        if data.get('severity') == 'HIGH':
            print(json.dumps(data, indent=2))
            break
    except:
        continue
