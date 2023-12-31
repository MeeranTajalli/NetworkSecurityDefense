import pandas as pd
from datetime import datetime
from joblib import load
from collections import Counter
import os

# Function to parse a single line of Wireshark output
def parse_wireshark_line(line):
    parts = line.strip().split(',')
    if len(parts) < 5 or not parts[0].startswith('"'):
        return None  # Skip lines that are not properly formatted

    timestamp = datetime.fromtimestamp(float(parts[0].strip('"')))
    src_ip = parts[1].strip('"') if parts[1] else 'UNKNOWN'
    length = int(parts[2]) if parts[2].isdigit() else 0
    protocol = parts[3].strip('"') if parts[3] else 'UNKNOWN'
    info = parts[4].strip('"') if parts[4] else ''

    return {'Timestamp': timestamp, 'Source': src_ip, 'Length': length, 'Protocol': protocol, 'Info': info}

# Function to process the Wireshark output and calculate packets per second
def process_wireshark(file_path):
    data = []
    with open(file_path, 'r') as file:
        next(file)  # Skip the header line
        for line in file:
            parsed_line = parse_wireshark_line(line)
            if parsed_line:
                data.append(parsed_line)

    if not data:
        return pd.DataFrame()

    df = pd.DataFrame(data)
    df.sort_values('Timestamp', inplace=True)
    df['Packets_Per_Second'] = df.groupby('Source')['Timestamp'].transform(lambda x: 1 / x.diff().dt.total_seconds().fillna(0.1))

    return df[['Length', 'Packets_Per_Second']]

# Load the model
model = load('trained_model.joblib')

# Process the Wireshark output
print("Reading Wireshark output file...")
file_path = os.path.expanduser('~/Desktop/project/tcpdump_output.txt')
wireshark_df = process_wireshark(file_path)

if wireshark_df.empty:
    print("No valid data found in Wireshark output.")
else:
    print("Making predictions on Wireshark data...")
    predictions = model.predict(wireshark_df)

    print("Analyzing predictions...")
    packet_counts = Counter(predictions)

    print("Summary of packets:")
    for packet_type, count in packet_counts.items():
        print(f"Total number of '{packet_type}' packets: {count}")

    # Define thresholds for each attack type
    attack_thresholds = {
        'UDP Flood': 10,
        'ICMP Flood': 10,
        'TCP Flood': 10  # Example threshold, adjust based on your criteria
    }

    # Alert for each attack type based on its threshold
    for attack_type, threshold in attack_thresholds.items():
        if packet_counts[attack_type] > threshold:
            print(f"ALERT: Possible {attack_type} detected with {packet_counts[attack_type]} packets!")

# Ensure the 'trained_model.joblib' is up to date and the thresholds reflect your criteria for an attack.

