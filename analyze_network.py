import pandas as pd
from datetime import datetime
from joblib import load
from collections import defaultdict
import numpy as np
import os

# Define thresholds and parameters
TIME_WINDOW = 5  # seconds
MAX_RATE = 1e3  # maximum packets per second

# Thresholds for packet rates indicating an attack (per second)
ATTACK_THRESHOLDS = {'SYN': 20, 'UDP': 20, 'ICMP': 20}
DEFAULT_ATTACK_THRESHOLD = 20  # Default threshold for unspecified protocols

# Parse line of Wireshark output
def parse_wireshark_line(line):
    parts = line.strip().split(',')
    if len(parts) < 5 or not parts[0].startswith('"'):
        return None

    timestamp = datetime.fromtimestamp(float(parts[0].strip('"')))
    src_ip = parts[1].strip('"') if parts[1] else 'UNKNOWN'
    length = int(parts[2]) if parts[2].isdigit() else 0
    protocol = parts[3].strip('"') if parts[3] else 'UNKNOWN'
    info = parts[4].strip('"') if parts[4] else ''

    return {'Timestamp': timestamp, 'Source': src_ip, 'Length': length, 'Protocol': protocol, 'Info': info}

# Process Wireshark output
def process_wireshark(file_path):
    data = []
    with open(file_path, 'r') as file:
        next(file)  # Skip header
        for line in file:
            parsed_line = parse_wireshark_line(line)
            if parsed_line:
                data.append(parsed_line)

    if not data:
        return pd.DataFrame(), None

    df = pd.DataFrame(data)
    df.sort_values('Timestamp', inplace=True)
    df['Time_Diff'] = df['Timestamp'].diff().dt.total_seconds().replace(0, 0.1)
    df['Packets_Per_Second'] = np.minimum(1 / df['Time_Diff'], MAX_RATE)

    return df, df[['Length', 'Packets_Per_Second']]

# Load model
model = load('trained_model.joblib')

# Process output
print("Reading Wireshark output file...")
wireshark_df, features_for_prediction = process_wireshark(os.path.expanduser('~/Desktop/project/tcpdump_output.txt'))

if not wireshark_df.empty and features_for_prediction is not None:
    predictions = model.predict(features_for_prediction)
    packet_counter = defaultdict(int)
    attack_counter = defaultdict(int)

    for index, row in wireshark_df.iterrows():
        protocol = row['Protocol']
        packet_counter[protocol] += 1
        if 'Flood' in predictions[index]:
            attack_counter[protocol] += 1

    # Summary
    for proto, count in packet_counter.items():
        print(f"Total number of '{proto}' packets: {count}")
        threshold = ATTACK_THRESHOLDS.get(proto, DEFAULT_ATTACK_THRESHOLD)
        if attack_counter[proto] > threshold:
            print(f"ALERT: Potential {proto} Flood detected with {attack_counter[proto]} packets.")

# Ensure the model file is compatible with the current version of scikit-learn.

