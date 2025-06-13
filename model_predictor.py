import pandas as pd
import joblib
import lightgbm as lgb
from config import MODEL_FILE, FEATURE_NAMES_FILE, MODEL_INFO_FILE, THRESHOLD
from spike_detector import SpikeDetector
from disk_read_detector import DiskReadDetector

class ModelPredictor:
    def __init__(self):
        self.model = None
        self.feature_names = None
        self.model_info = None
        self.spike_detector = SpikeDetector()
        self.disk_detector = DiskReadDetector()
        self.load_model()
    
    def load_model(self):
        try:
            self.model = lgb.Booster(model_file=MODEL_FILE)
            self.feature_names = joblib.load(FEATURE_NAMES_FILE)
            self.model_info = joblib.load(MODEL_INFO_FILE)
            print(f"Model loaded with {len(self.feature_names)} features")
        except Exception as e:
            raise Exception(f"Model loading failed: {e}")
    
    def predict(self, features):
        if self.model is None or features is None:
            return None, None
        
        df = pd.DataFrame([features])
        
        missing = set(self.feature_names) - set(df.columns)
        for feat in missing:
            df[feat] = 0
        
        df = df[self.feature_names]
        
        prob = self.model.predict(df)[0]
        
        if self.spike_detector.detect_spike():
            prob += 0.1
        
        disk_spike, high_volume = self.disk_detector.detect_spike()
        if disk_spike:
            prob += 0.1
        if high_volume:
            prob += 0.1
        
        prob = min(prob, 1.0)
        prediction = int(prob > THRESHOLD)
        
        return prob, prediction