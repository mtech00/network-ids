import pandas as pd
import numpy as np
from pathlib import Path
import lightgbm as lgb
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import warnings
warnings.filterwarnings('ignore')


files = [
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv', 
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',
    'Monday-WorkingHours.pcap_ISCX.csv',
    'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'Tuesday-WorkingHours.pcap_ISCX.csv',
    'Wednesday-workingHours.pcap_ISCX.csv'
]


RELIABLE_FEATURES = [
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
features_to_keep = RELIABLE_FEATURES

def load_and_combine_data():
    dfs = []
    base_path = Path('cic-ids-17')
    
    for file in files:
        file_path = base_path / file
        print(f"Loading {file}...")
        
        df = pd.read_csv(file_path)
        

        df.columns = df.columns.str.strip()
        

        
        dfs.append(df)
    
    combined_df = pd.concat(dfs, ignore_index=True)
    print(f"Combined dataset shape: {combined_df.shape}")
    return combined_df

def preprocess_data(df):
    
    label_col = df.columns[-1]
    

    df[label_col] = df[label_col].str.strip()
    

    categorical_features = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
    numerical_features = [f for f in features_to_keep if f not in categorical_features]
    
    available_features = [f for f in numerical_features if f in df.columns]
    features_df = df[available_features + [label_col]].copy()
    
    print(f"Using {len(available_features)} numerical features")
    print(f"Skipped categorical: {[f for f in categorical_features if f in df.columns]}")
    

    features_df = features_df.dropna()
    

    corr_matrix = features_df[available_features].corr().abs()

    upper_tri = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
    high_corr_features = [column for column in upper_tri.columns if any(upper_tri[column] > 0.95)]
    
    if high_corr_features:
        print(f"Removing {len(high_corr_features)} highly correlated features")
        available_features = [f for f in available_features if f not in high_corr_features]
    

    X = features_df[available_features]
    y = features_df[label_col]

    y_binary = y.apply(lambda x: 0 if x.upper() in ['BENIGN'] else 1)
    
    print(f"Final feature count: {len(available_features)}")
    print(f"Class distribution: {y_binary.value_counts()}")
    
    return X, y_binary, available_features



def train_model(X, y):

    

    if len(X) > 500000:
        print("Subsampling to 500k records to prevent overfitting...")
        X_sample, _, y_sample, _ = train_test_split(X, y, train_size=500000, random_state=42, stratify=y)
        X, y = X_sample, y_sample
    
    # Run cross-validation first
    # cv_score = validate_model(X, y)
    
    # Split: 60% train, 20% val, 20% test
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.25, random_state=42, stratify=y_temp
    )
    
    print(f"Train: {X_train.shape[0]}, Val: {X_val.shape[0]}, Test: {X_test.shape[0]}")
    

    params = {
        'objective': 'binary',
        'metric': 'binary_logloss',
        'boosting_type': 'gbdt',
        'num_leaves': 5,           # Very small
        'learning_rate': 0.01,     # Very slow
        'feature_fraction': 0.5,   # Use only half features each iteration
        'bagging_fraction': 0.5,   # Use only half samples each iteration
        'bagging_freq': 1,         # Every iteration
        'min_data_in_leaf': 500,   # Much higher minimum
        'lambda_l1': 1.0,          # Strong L1 regularization
        'lambda_l2': 1.0,          # Strong L2 regularization
        'min_gain_to_split': 1.0,  # Much higher threshold
        'max_depth': 3,            # Very shallow trees
        'min_child_weight': 100,   # Higher minimum child weight
        'verbose': -1,
        'is_unbalance': True
    }
    

    train_data = lgb.Dataset(X_train, label=y_train)
    val_data = lgb.Dataset(X_val, label=y_val, reference=train_data)
    

    print("Training LightGBM with aggressive regularization...")
    model = lgb.train(
        params,
        train_data,
        valid_sets=[val_data],
        num_boost_round=100,       # Much fewer rounds
        callbacks=[lgb.early_stopping(10), lgb.log_evaluation(20)]  
    )
    

    y_val_pred = model.predict(X_val, num_iteration=model.best_iteration)
    y_val_pred_class = (y_val_pred > 0.5).astype(int)
    
    print("\nValidation Results:")
    print(classification_report(y_val, y_val_pred_class, target_names=['Normal', 'Anomaly']))
    
 
    y_test_pred = model.predict(X_test, num_iteration=model.best_iteration)
    y_test_pred_class = (y_test_pred > 0.5).astype(int)
    
    print("\nTest Results:")
    print(classification_report(y_test, y_test_pred_class, target_names=['Normal', 'Anomaly']))
    

    importance = model.feature_importance(importance_type='gain')
    feature_imp = pd.DataFrame({
        'feature': X.columns,
        'importance': importance
    }).sort_values('importance', ascending=False)
    
    print(f"\nTop 10 features:")
    print(feature_imp.head(10))
    
    return model, X_test, y_test, y_test_pred_class

def save_artifacts(model, features):
    
 
    model.save_model('cic_ids_binary_model.txt')
    

    joblib.dump(features, 'feature_names.pkl')


    model_info = {
        'n_classes': 2,
        'classes': ['Normal', 'Anomaly'],
        'features': features,
        'model_type': 'lightgbm_binary',
        'threshold': 0.5
    }
    joblib.dump(model_info, 'model_info.pkl')
    
    print("Saved artifacts:")
    print("- cic_ids_binary_model.txt")
    print("- feature_names.pkl")
    print("- model_info.pkl")

if __name__ == "__main__":

    df = load_and_combine_data()
    

    X, y, features = preprocess_data(df)
    

    model, X_test, y_test, y_pred = train_model(X, y)
    

    save_artifacts(model, features)
    
    print(f"\nTraining complete. Final dataset shape: {X.shape}")
    print("Binary anomaly detection model ready.")
