import pandas as pd
import numpy as np
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from imblearn.under_sampling import RandomUnderSampler
import joblib
import warnings
warnings.filterwarnings('ignore')

FILES = [
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv', 
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',
    'Monday-WorkingHours.pcap_ISCX.csv',
    'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'Tuesday-WorkingHours.pcap_ISCX.csv',
    'Wednesday-workingHours.pcap_ISCX.csv'
]

FEATURES = [
    'src_ip',
    'dst_ip', 
    'src_port',
    'dst_port',
    'protocol',
    'Destination Port',
    'Flow Duration',
    'Total Fwd Packets',
    'Total Length of Fwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Min', 
    'Fwd Packet Length Mean',
    'Fwd Packet Length Std',
    'Bwd Packet Length Max',
    'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 
    'Bwd Packet Length Std',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Fwd Packets/s',
    'Bwd Packets/s',
    'Min Packet Length',
    'Max Packet Length', 
    'Packet Length Mean',
    'Packet Length Std',
    'Packet Length Variance',
    'Average Packet Size',
    'Flow IAT Mean',
    'Flow IAT Std', 
    'Flow IAT Max',
    'Flow IAT Min',
    'Fwd IAT Total',
    'Fwd IAT Mean',
    'Fwd IAT Std',
    'Fwd IAT Max', 
    'Fwd IAT Min',
    'Bwd IAT Total',
    'Bwd IAT Mean',
    'Bwd IAT Std',
    'Bwd IAT Max',
    'Bwd IAT Min',
    'Fwd Header Length',
    'Bwd Header Length',
    'Init_Win_bytes_forward',
    'Init_Win_bytes_backward',
    'PSH Flag Count',
    'FIN Flag Count', 
    'ACK Flag Count',
    'Subflow Fwd Bytes'
]
def load_data():
    dfs = []
    for file in FILES:
        df = pd.read_csv(f'cic-ids-17/{file}')
        df.columns = df.columns.str.strip()
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        dfs.append(df)
    
    combined = pd.concat(dfs, ignore_index=True)
    print(f"Combined dataset: {combined.shape}")
    return combined

def preprocess(df):
    label_col = df.columns[-1]
    
    available_features = [f for f in FEATURES if f in df.columns]
    data = df[available_features + [label_col]].copy()
    
    data[label_col] = data[label_col].str.strip()
    data = data.dropna()
    
    corr_matrix = data[available_features].corr().abs()
    upper_tri = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
    high_corr = [col for col in upper_tri.columns if any(upper_tri[col] > 0.95)]
    
    if high_corr:
        available_features = [f for f in available_features if f not in high_corr]
        print(f"Removed {len(high_corr)} correlated features")
    
    X = data[available_features]
    y = data[label_col].apply(lambda x: 0 if x.upper() == 'BENIGN' else 1)
    
    print(f"Features: {len(available_features)}")

    return X, y, available_features

def train_model(X, y):
    
    X_temp, X_test, y_temp, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    X_train, X_val, y_train, y_val = train_test_split(X_temp, y_temp, test_size=0.25, random_state=42, stratify=y_temp)
    
    params = {
        'objective': 'binary',
        'metric': 'binary_logloss',
        'num_leaves': 5,
        'learning_rate': 0.01,
        'feature_fraction': 0.5,
        'bagging_fraction': 0.5,
        'bagging_freq': 1,
        'min_data_in_leaf': 500,
        'lambda_l1': 1.0,
        'lambda_l2': 1.0,
        'max_depth': 3,
        'verbose': -1,
        'is_unbalance': True
    }
    
    # Train
    train_data = lgb.Dataset(X_train, label=y_train)
    val_data = lgb.Dataset(X_val, label=y_val, reference=train_data)
    
    model = lgb.train(
        params, train_data,
        valid_sets=[val_data],
        num_boost_round=100,
        callbacks=[lgb.early_stopping(10), lgb.log_evaluation(20)]
    )
    
    y_pred = (model.predict(X_test) > 0.5).astype(int)
    print("\nTest Results:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Anomaly']))
    
    return model, X_test, y_test

def save_model(model, features):

    model.save_model('anomaly_detector.txt')
    joblib.dump({
        'features': features,
        'classes': ['Normal', 'Anomaly'],
        'threshold': 0.5
    }, 'model_info.pkl')
    print("Model saved: anomaly_detector.txt, model_info.pkl")

if __name__ == "__main__":
    # Pipeline
    df = load_data()
    X, y, features = preprocess(df)
    model, X_test, y_test = train_model(X, y)
    save_model(model, features)
    
    print(f"\nFinal shape: {X.shape}")
