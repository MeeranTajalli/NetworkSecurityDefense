import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from joblib import dump

# Load the dataset
print("Loading data...")
df = pd.read_csv('network_traffic.csv')
print("Data loaded successfully.")

# Feature engineering
print("Starting feature engineering...")
df['Time'] = pd.to_timedelta(df['Time'], unit='s')
df['Time'] = pd.to_datetime('today').normalize() + df['Time']
df['Packets_Per_Second'] = df.groupby('Source')['Time'].transform(lambda x: 1 / x.diff().dt.total_seconds().fillna(0.1))
df['Packets_Per_Second'] = df['Packets_Per_Second'].clip(upper=1000)

# Labeling the data
print("Labeling the data...")
def label_row(row):
    if 'UDP' in row['Protocol']:
        return 'UDP Flood' if row['Packets_Per_Second'] > 10 else 'Normal'
    elif 'ICMP' in row['Protocol']:
        return 'ICMP Flood' if row['Packets_Per_Second'] > 10 else 'Normal'
    elif 'TCP' in row['Protocol']:
        # Check for a pattern of SYN packets without corresponding ACKs to indicate a SYN Flood
        if '[SYN]' in row['Info'] and not '[ACK]' in row['Info']:
            return 'SYN Flood' if row['Packets_Per_Second'] > 10 else 'Normal'
        else:
            return 'Normal'
    else:
        return 'Normal'

df['Label'] = df.apply(label_row, axis=1)

# Preprocessing data
print("Preprocessing data...")
X = df[['Length', 'Packets_Per_Second']]
y = df['Label']

numeric_features = ['Length', 'Packets_Per_Second']
numeric_transformer = Pipeline(steps=[
    ('imputer', SimpleImputer(strategy='mean')),
    ('scaler', StandardScaler())
])

preprocessor = ColumnTransformer(transformers=[
    ('num', numeric_transformer, numeric_features)
])

# Modeling
pipeline = Pipeline(steps=[
    ('preprocessor', preprocessor),
    ('classifier', RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced'))
])

# Splitting data into training and testing sets
print("Splitting data into training and testing sets...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

# Training the model
print("Training the model...")
pipeline.fit(X_train, y_train)

# Saving the model to disk
model_filename = 'trained_model.joblib'
dump(pipeline, model_filename)
print(f"Model saved to {model_filename}.")

# Making predictions on the test set
print("Making predictions on the test set...")
y_pred = pipeline.predict(X_test)

# Evaluating the model's performance
print("Evaluating model performance...")
print(classification_report(y_test, y_pred))
print(f"Model accuracy: {accuracy_score(y_test, y_pred)}")

print("Model training and evaluation complete.")

