"""
AdPredictor - Fast TensorFlow Lite inference for ad/telemetry detection

This module provides fast ML inference using TensorFlow Lite models.
Optimized for <10ms inference time on typical hardware.
"""

import numpy as np
import pickle
import logging
import time
import threading
from typing import List, Optional, Union
from pathlib import Path

try:
    import tflite_runtime.interpreter as tflite
    TFLITE_AVAILABLE = True
except ImportError:
    try:
        import tensorflow as tf
        TFLITE_AVAILABLE = False
        logging.warning("tflite-runtime not available, falling back to TensorFlow")
    except ImportError:
        raise ImportError("Neither tflite-runtime nor tensorflow is available")


class AdPredictor:
    """
    Fast TensorFlow Lite predictor for ad/telemetry classification.
    
    Loads a quantized TFLite model and StandardScaler for efficient inference.
    Thread-safe and optimized for real-time prediction.
    """
    
    def __init__(self, model_path: str, scaler_path: str):
        """
        Initialize predictor with TFLite model and scaler.
        
        Args:
            model_path: Path to .tflite model file
            scaler_path: Path to StandardScaler pickle file
            
        Raises:
            FileNotFoundError: If model or scaler files not found
            ValueError: If model loading fails
        """
        self.model_path = Path(model_path)
        self.scaler_path = Path(scaler_path)
        self.logger = logging.getLogger(__name__)
        
        # Thread lock for thread-safe operations
        self._lock = threading.Lock()
        
        # Performance metrics
        self.inference_times = []
        self.total_predictions = 0
        
        # Load model and scaler
        self._load_model()
        self._load_scaler()
        
        self.logger.info(f"AdPredictor initialized with model: {self.model_path}")
    
    def _load_model(self) -> None:
        """Load TensorFlow Lite model."""
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model file not found: {self.model_path}")
        
        try:
            if TFLITE_AVAILABLE:
                # Use TFLite Runtime (preferred)
                self.interpreter = tflite.Interpreter(model_path=str(self.model_path))
                self.interpreter.allocate_tensors()
                
                # Get input/output details
                self.input_details = self.interpreter.get_input_details()
                self.output_details = self.interpreter.get_output_details()
                
                self.logger.info("Loaded model with tflite-runtime")
                
            else:
                # Fallback to full TensorFlow
                self.interpreter = tf.lite.Interpreter(model_path=str(self.model_path))
                self.interpreter.allocate_tensors()
                
                self.input_details = self.interpreter.get_input_details()
                self.output_details = self.interpreter.get_output_details()
                
                self.logger.info("Loaded model with TensorFlow (fallback)")
            
            # Validate model input shape
            expected_shape = self.input_details[0]['shape']
            self.logger.info(f"Model input shape: {expected_shape}")
            
            if len(expected_shape) != 3 or expected_shape[1] != 10 or expected_shape[2] != 30:
                self.logger.warning(f"Unexpected input shape: {expected_shape}, expected [batch, 10, 30]")
            
        except Exception as e:
            self.logger.error(f"Failed to load TFLite model: {e}")
            raise ValueError(f"Model loading failed: {e}")
    
    def _load_scaler(self) -> None:
        """Load StandardScaler from pickle file."""
        if not self.scaler_path.exists():
            raise FileNotFoundError(f"Scaler file not found: {self.scaler_path}")
        
        try:
            with open(self.scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            
            # Validate scaler
            if not hasattr(self.scaler, 'transform'):
                raise ValueError("Invalid scaler object - missing transform method")
            
            self.logger.info(f"Loaded scaler from: {self.scaler_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to load scaler: {e}")
            raise ValueError(f"Scaler loading failed: {e}")
    
    def predict(self, features: np.ndarray) -> float:
        """
        Predict probability that traffic is ad/telemetry.
        
        Args:
            features: Feature array of shape (10, 30) - time series of 10 flows with 30 features each
            
        Returns:
            Probability [0.0-1.0] that traffic is ad/telemetry
            
        Raises:
            ValueError: If features have wrong shape
        """
        start_time = time.time()
        
        try:
            # Validate input shape
            if features.shape != (10, 30):
                raise ValueError(f"Expected shape (10, 30), got {features.shape}")
            
            # Normalize features
            normalized_features = self._normalize(features)
            
            # Add batch dimension
            input_data = np.expand_dims(normalized_features, axis=0).astype(np.float32)
            
            with self._lock:
                # Set input tensor
                self.interpreter.set_tensor(self.input_details[0]['index'], input_data)
                
                # Run inference
                self.interpreter.invoke()
                
                # Get prediction
                output_data = self.interpreter.get_tensor(self.output_details[0]['index'])
                probability = float(output_data[0][0])
            
            # Record timing
            inference_time = (time.time() - start_time) * 1000  # milliseconds
            self.inference_times.append(inference_time)
            self.total_predictions += 1
            
            # Keep only last 1000 timing measurements
            if len(self.inference_times) > 1000:
                self.inference_times = self.inference_times[-1000:]
            
            # Log slow predictions
            if inference_time > 15:
                self.logger.warning(f"Slow inference: {inference_time:.1f}ms")
            
            return probability
            
        except Exception as e:
            self.logger.error(f"Prediction failed: {e}")
            return 0.0  # Return neutral prediction on error
    
    def predict_batch(self, features_list: List[np.ndarray]) -> List[float]:
        """
        Predict probabilities for batch of feature arrays.
        
        Args:
            features_list: List of feature arrays, each of shape (10, 30)
            
        Returns:
            List of probabilities [0.0-1.0] for each input
        """
        if not features_list:
            return []
        
        start_time = time.time()
        
        try:
            # Validate all inputs
            for i, features in enumerate(features_list):
                if features.shape != (10, 30):
                    self.logger.error(f"Batch item {i} has wrong shape: {features.shape}")
                    return [0.0] * len(features_list)
            
            # Normalize all features
            normalized_batch = []
            for features in features_list:
                normalized = self._normalize(features)
                normalized_batch.append(normalized)
            
            # Stack into batch
            batch_data = np.stack(normalized_batch).astype(np.float32)
            
            with self._lock:
                # Resize interpreter for batch size
                self.interpreter.resize_tensor_input(
                    self.input_details[0]['index'], 
                    [len(features_list), 10, 30]
                )
                self.interpreter.allocate_tensors()
                
                # Set input tensor
                self.interpreter.set_tensor(self.input_details[0]['index'], batch_data)
                
                # Run inference
                self.interpreter.invoke()
                
                # Get predictions
                output_data = self.interpreter.get_tensor(self.output_details[0]['index'])
                probabilities = [float(output_data[i][0]) for i in range(len(features_list))]
            
            # Record timing
            inference_time = (time.time() - start_time) * 1000  # milliseconds
            avg_time = inference_time / len(features_list)
            self.inference_times.extend([avg_time] * len(features_list))
            self.total_predictions += len(features_list)
            
            self.logger.debug(f"Batch prediction: {len(features_list)} samples in {inference_time:.1f}ms")
            
            return probabilities
            
        except Exception as e:
            self.logger.error(f"Batch prediction failed: {e}")
            return [0.0] * len(features_list)
    
    def _normalize(self, features: np.ndarray) -> np.ndarray:
        """
        Normalize features using loaded StandardScaler.
        
        Args:
            features: Raw feature array of shape (10, 30)
            
        Returns:
            Normalized feature array of same shape
        """
        try:
            # Reshape to 2D for scaler
            original_shape = features.shape
            features_2d = features.reshape(-1, features.shape[-1])
            
            # Apply scaling
            normalized_2d = self.scaler.transform(features_2d)
            
            # Reshape back to original shape
            normalized = normalized_2d.reshape(original_shape)
            
            return normalized.astype(np.float32)
            
        except Exception as e:
            self.logger.error(f"Feature normalization failed: {e}")
            # Return original features on normalization error
            return features.astype(np.float32)
    
    def get_performance_stats(self) -> dict:
        """
        Get performance statistics for inference timing.
        
        Returns:
            Dictionary with timing statistics
        """
        if not self.inference_times:
            return {
                'total_predictions': 0,
                'avg_inference_time_ms': 0,
                'min_inference_time_ms': 0,
                'max_inference_time_ms': 0,
                'p95_inference_time_ms': 0
            }
        
        times = np.array(self.inference_times)
        
        return {
            'total_predictions': self.total_predictions,
            'avg_inference_time_ms': float(np.mean(times)),
            'min_inference_time_ms': float(np.min(times)),
            'max_inference_time_ms': float(np.max(times)),
            'p95_inference_time_ms': float(np.percentile(times, 95)),
            'last_100_avg_ms': float(np.mean(times[-100:])) if len(times) >= 100 else float(np.mean(times))
        }
    
    def validate_model(self) -> bool:
        """
        Validate model by running test prediction.
        
        Returns:
            True if model validation passes, False otherwise
        """
        try:
            # Create dummy input
            test_features = np.random.random((10, 30)).astype(np.float32)
            
            # Run prediction
            prediction = self.predict(test_features)
            
            # Check output is valid probability
            if 0.0 <= prediction <= 1.0:
                self.logger.info("Model validation passed")
                return True
            else:
                self.logger.error(f"Invalid prediction value: {prediction}")
                return False
                
        except Exception as e:
            self.logger.error(f"Model validation failed: {e}")
            return False
    
    def benchmark_inference(self, num_samples: int = 100) -> dict:
        """
        Benchmark inference performance.
        
        Args:
            num_samples: Number of test samples to run
            
        Returns:
            Dictionary with benchmark results
        """
        self.logger.info(f"Running inference benchmark with {num_samples} samples...")
        
        # Generate test data
        test_features = [
            np.random.random((10, 30)).astype(np.float32) 
            for _ in range(num_samples)
        ]
        
        # Single prediction benchmark
        start_time = time.time()
        single_predictions = [self.predict(features) for features in test_features]
        single_time = (time.time() - start_time) * 1000
        
        # Batch prediction benchmark  
        start_time = time.time()
        batch_predictions = self.predict_batch(test_features)
        batch_time = (time.time() - start_time) * 1000
        
        results = {
            'num_samples': num_samples,
            'single_prediction_total_ms': single_time,
            'single_prediction_avg_ms': single_time / num_samples,
            'batch_prediction_total_ms': batch_time,
            'batch_prediction_avg_ms': batch_time / num_samples,
            'batch_speedup': single_time / batch_time if batch_time > 0 else 0,
            'predictions_match': np.allclose(single_predictions, batch_predictions, atol=1e-6)
        }
        
        self.logger.info(f"Benchmark results: {results}")
        return results
    
    def reload_model(self, new_model_path: str, new_scaler_path: str) -> bool:
        """
        Reload model and scaler from new paths.
        
        Args:
            new_model_path: Path to new .tflite model
            new_scaler_path: Path to new scaler pickle file
            
        Returns:
            True if reload successful, False otherwise
        """
        try:
            # Backup current state
            old_model_path = self.model_path
            old_scaler_path = self.scaler_path
            old_interpreter = getattr(self, 'interpreter', None)
            old_scaler = getattr(self, 'scaler', None)
            
            # Update paths and reload
            self.model_path = Path(new_model_path)
            self.scaler_path = Path(new_scaler_path)
            
            self._load_model()
            self._load_scaler()
            
            # Validate new model
            if not self.validate_model():
                # Restore old state
                self.model_path = old_model_path
                self.scaler_path = old_scaler_path
                self.interpreter = old_interpreter
                self.scaler = old_scaler
                return False
            
            self.logger.info(f"Model reloaded successfully: {new_model_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Model reload failed: {e}")
            # Restore old state on error
            self.model_path = old_model_path
            self.scaler_path = old_scaler_path
            if old_interpreter:
                self.interpreter = old_interpreter
            if old_scaler:
                self.scaler = old_scaler
            return False