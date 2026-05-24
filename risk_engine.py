# risk_engine.py - Complete ML version for Streamlit
import numpy as np
import joblib
import os
import requests
import logging
from datetime import datetime
from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor, IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

class RiskEngine:
    def __init__(self):
        self.random_forest = None
        self.gradient_boosting = None
        self.isolation_forest = None
        self.scaler = None
        self.model_path = 'models/'
        self.use_external_api = True  # Use the Render API
        self.api_url = "https://mfa-r6ib.onrender.com/predict"
        self.load_models()
    
    def load_models(self):
        """Load pre-trained models if they exist"""
        os.makedirs(self.model_path, exist_ok=True)
        
        rf_path = os.path.join(self.model_path, 'risk_model_rf.pkl')
        gb_path = os.path.join(self.model_path, 'risk_model_gb.pkl')
        scaler_path = os.path.join(self.model_path, 'scaler.pkl')
        if_path = os.path.join(self.model_path, 'isolation_forest.pkl')
        
        models_loaded = False
        if os.path.exists(rf_path):
            try:
                self.random_forest = joblib.load(rf_path)
                self.gradient_boosting = joblib.load(gb_path)
                self.scaler = joblib.load(scaler_path)
                if os.path.exists(if_path):
                    self.isolation_forest = joblib.load(if_path)
                logger.info("✅ Loaded ML models successfully")
                models_loaded = True
            except Exception as e:
                logger.error(f"Error loading models: {e}")
        
        if not models_loaded:
            logger.warning("⚠️ No pre-trained models found. Will use external API or train new models.")
        
        return models_loaded
    
    def train_models_from_logs(self, auth_logs):
        """Train ML models from historical authentication logs"""
        if not auth_logs or len(auth_logs) < 100:
            logger.warning("Insufficient data for training. Need at least 100 samples.")
            return False
        
        # Extract features and labels from historical logs
        X = []
        y = []
        
        for log in auth_logs:
            features = self.extract_features_from_log(log)
            if features is not None:
                X.append(features)
                # Use risk_score as label if available, otherwise calculate rule-based
                risk_score = log.get('risk_score')
                if risk_score is None:
                    risk_score = self.calculate_rule_based_score(log)
                y.append(risk_score / 100.0)  # Normalize to 0-1
        
        if len(X) < 50:
            logger.warning(f"Only {len(X)} valid samples, need at least 50 for training")
            return False
        
        X = np.array(X)
        y = np.array(y)
        
        # Train scaler
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Random Forest
        self.random_forest = RandomForestRegressor(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        self.random_forest.fit(X_scaled, y)
        
        # Train Gradient Boosting
        self.gradient_boosting = GradientBoostingRegressor(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=5,
            random_state=42
        )
        self.gradient_boosting.fit(X_scaled, y)
        
        # Train Isolation Forest for anomaly detection
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.isolation_forest.fit(X_scaled)
        
        # Save models
        os.makedirs(self.model_path, exist_ok=True)
        joblib.dump(self.random_forest, os.path.join(self.model_path, 'risk_model_rf.pkl'))
        joblib.dump(self.gradient_boosting, os.path.join(self.model_path, 'risk_model_gb.pkl'))
        joblib.dump(self.scaler, os.path.join(self.model_path, 'scaler.pkl'))
        joblib.dump(self.isolation_forest, os.path.join(self.model_path, 'isolation_forest.pkl'))
        
        logger.info(f"✅ Trained ML models on {len(X)} samples")
        return True
    
    def extract_features_from_log(self, log):
        """Extract feature vector from a log entry"""
        try:
            features = [
                log.get('hour', 12) / 24.0,
                log.get('minute', 0) / 60.0,
                log.get('day_of_week', 3) / 6.0,
                1 if log.get('is_weekend', False) else 0,
                1 if log.get('is_business_hours', False) else 0,
                min(1.0, log.get('failed_attempts', 0) / 10.0),
                1 if log.get('device_fingerprint') else 0,
                1.0 if log.get('browser', '') in ['Chrome', 'Firefox', 'Safari', 'Edge'] else 0.5,
                1.0 if log.get('os', '') in ['Windows', 'macOS', 'iOS', 'Android', 'Linux'] else 0.5,
                {'mobile': 1.0, 'tablet': 0.7, 'desktop': 0.3}.get(log.get('device_type'), 0.5),
                1 if log.get('country') else 0,
                1 if log.get('location_mismatch', False) else 0,
                1 if log.get('is_known_device', False) else 0,
                1 if log.get('is_known_location', False) else 0,
                1 if log.get('time_anomaly', False) else 0,
                min(1.0, log.get('velocity_check', 0) / 1000.0),
                1,  # cookies_enabled (assume true)
                1,  # javascript_enabled (assume true)
            ]
            return features
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None
    
    def extract_features(self, request_data):
        """Extract features from request data for ML prediction"""
        features = [
            request_data.get('hour', datetime.now().hour) / 24.0,
            request_data.get('minute', datetime.now().minute) / 60.0,
            request_data.get('day_of_week', datetime.now().weekday()) / 6.0,
            1 if request_data.get('is_weekend', datetime.now().weekday() >= 5) else 0,
            1 if request_data.get('is_business_hours', 9 <= datetime.now().hour <= 17) else 0,
            min(1.0, request_data.get('failed_attempts', 0) / 10.0),
            1 if request_data.get('device_fingerprint') else 0,
            1.0 if request_data.get('browser', '') in ['Chrome', 'Firefox', 'Safari', 'Edge'] else 0.5,
            1.0 if request_data.get('os', '') in ['Windows', 'macOS', 'iOS', 'Android', 'Linux'] else 0.5,
            {'mobile': 1.0, 'tablet': 0.7, 'desktop': 0.3}.get(request_data.get('device_type'), 0.5),
            1 if request_data.get('country') else 0,
            1 if request_data.get('location_mismatch', False) else 0,
            1 if request_data.get('is_known_device', False) else 0,
            1 if request_data.get('is_known_location', False) else 0,
            1 if request_data.get('time_anomaly', False) else 0,
            min(1.0, request_data.get('velocity_check', 0) / 1000.0),
            1 if request_data.get('cookies_enabled', True) else 0,
            1 if request_data.get('javascript_enabled', True) else 0,
        ]
        return np.array(features, dtype=np.float32).reshape(1, -1)
    
    def predict_ml(self, features):
        """Predict risk score using ML models"""
        if not all([self.random_forest, self.gradient_boosting, self.scaler]):
            return None
        
        try:
            features_scaled = self.scaler.transform(features)
            
            # Get predictions from both models
            rf_risk = self.random_forest.predict(features_scaled)[0]
            gb_risk = self.gradient_boosting.predict(features_scaled)[0]
            
            # Ensemble average
            risk_normalized = (rf_risk + gb_risk) / 2
            
            # Anomaly detection
            if self.isolation_forest:
                is_anomaly = self.isolation_forest.predict(features_scaled)[0]
                if is_anomaly == -1:
                    risk_normalized = min(1.0, risk_normalized * 1.2)  # Increase risk by 20%
            
            risk_score = risk_normalized * 100
            return max(0, min(100, risk_score))
        except Exception as e:
            logger.error(f"ML prediction error: {e}")
            return None
    
    def predict_external_api(self, request_data):
        """Call external ML API"""
        if not self.use_external_api:
            return None
        
        try:
            response = requests.post(self.api_url, json=request_data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return {
                        'risk_score': result.get('risk_score', 50),
                        'action': result.get('action', 'challenge'),
                        'method': 'external_api'
                    }
        except Exception as e:
            logger.warning(f"External API failed: {e}")
        return None
    
    def calculate_rule_based_score(self, data):
        """Fallback rule-based calculation"""
        score = 50
        
        hour = data.get('hour', datetime.now().hour)
        if hour < 6 or hour > 22:
            score += 20
        elif 9 <= hour <= 17:
            score -= 10
        
        if data.get('is_weekend', False):
            score += 10
        
        failed = data.get('failed_attempts', 0)
        score += min(30, failed * 10)
        
        if not data.get('device_fingerprint'):
            score += 25
        
        if data.get('location_mismatch', False):
            score += 30
        
        if not data.get('is_known_device', False):
            score += 15
        
        return max(0, min(100, score))
    
    def predict(self, request_data):
        """Main prediction method with fallbacks"""
        
        # Priority 1: Try external ML API
        api_result = self.predict_external_api(request_data)
        if api_result:
            return api_result
        
        # Priority 2: Try local ML models
        features = self.extract_features(request_data)
        ml_score = self.predict_ml(features)
        
        if ml_score is not None:
            if ml_score < 30:
                action = 'allow'
            elif ml_score < 70:
                action = 'challenge'
            else:
                action = 'block'
            return {'risk_score': ml_score, 'action': action, 'method': 'ml_ensemble'}
        
        # Priority 3: Fallback to rule-based
        rule_score = self.calculate_rule_based_score(request_data)
        if rule_score < 30:
            action = 'allow'
        elif rule_score < 70:
            action = 'challenge'
        else:
            action = 'block'
        
        return {'risk_score': rule_score, 'action': action, 'method': 'rule_based'}

# Singleton instance
risk_engine = RiskEngine()
