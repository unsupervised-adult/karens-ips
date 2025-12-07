#!/usr/bin/env python3
"""
LSTM training pipeline for ML Ad Detector
"""

import argparse
import sys
import pickle
import json
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, Any
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, roc_curve
)

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, callbacks
except ImportError:
    print("Error: TensorFlow not installed. Install with: pip install tensorflow")
    sys.exit(1)

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
from feature_extractor import AdTrafficFeatureExtractor


class ModelTrainer:
    """LSTM model training pipeline"""

    LABEL_MAP = {
        'content': 0,
        'ad': 1,
        'telemetry': 1,
        'tracking': 1
    }

    def __init__(self, output_dir: str = 'models'):
        """
        Initialize trainer

        Args:
            output_dir: Directory to save models
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.scaler = StandardScaler()
        self.model = None
        self.history = None

    def load_data(self, csv_path: str) -> Tuple[np.ndarray, np.ndarray]:
        """
        Load and prepare labeled data

        Args:
            csv_path: Path to labeled CSV file

        Returns:
            Tuple of (X, y) arrays
        """
        print(f"Loading data from {csv_path}...")
        df = pd.read_csv(csv_path)

        df = df[df['label'].isin(self.LABEL_MAP.keys())].copy()
        df['label_binary'] = df['label'].map(self.LABEL_MAP)

        print(f"Loaded {len(df)} labeled flows")
        print(f"Label distribution:")
        print(df['label'].value_counts())

        features_list = []
        labels = []

        for idx in range(len(df)):
            flow = df.iloc[idx]

            features = self._extract_features_from_row(flow)
            if features is not None:
                features_list.append(features)
                labels.append(flow['label_binary'])

        X = np.array(features_list)
        y = np.array(labels)

        print(f"\nDataset shape: {X.shape}")
        print(f"Labels shape: {y.shape}")
        print(f"Class balance: {np.bincount(y)}")

        return X, y

    def _extract_features_from_row(self, row: pd.Series) -> np.ndarray:
        """
        Extract 30 features from flow row

        Args:
            row: DataFrame row

        Returns:
            Feature array of shape (30,)
        """
        features = np.zeros(30)

        features[0] = row.get('duration', 0)
        features[1] = row.get('bytes_sent', 0)
        features[2] = row.get('bytes_recv', 0)
        features[3] = row.get('packets_sent', 0)
        features[4] = row.get('packets_recv', 0)

        bytes_recv = max(row.get('bytes_recv', 1), 1)
        packets_recv = max(row.get('packets_recv', 1), 1)
        features[5] = row.get('bytes_sent', 0) / bytes_recv
        features[6] = row.get('packets_sent', 0) / packets_recv

        features[7] = row.get('duration', 0) / max(row.get('packets_sent', 1), 1)

        dst_port = row.get('dst_port', 0)
        features[8] = 1 if dst_port in [80, 443] else 0
        features[9] = 1 if dst_port == 443 else 0

        state = str(row.get('state', ''))
        features[10] = 1 if 'S' in state else 0
        features[11] = 1 if 'F' in state else 0
        features[12] = 1 if 'R' in state else 0

        return features

    def build_time_series_dataset(
        self,
        X: np.ndarray,
        y: np.ndarray,
        sequence_length: int = 10
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Build time-series sequences

        Args:
            X: Feature array (n_samples, n_features)
            y: Labels array (n_samples,)
            sequence_length: Number of flows per sequence

        Returns:
            Tuple of (X_seq, y_seq)
        """
        print(f"\nBuilding time-series sequences (length={sequence_length})...")

        X_seq = []
        y_seq = []

        for i in range(len(X) - sequence_length + 1):
            X_seq.append(X[i:i+sequence_length])
            y_seq.append(y[i+sequence_length-1])

        X_seq = np.array(X_seq)
        y_seq = np.array(y_seq)

        print(f"Sequence dataset shape: {X_seq.shape}")
        return X_seq, y_seq

    def normalize_features(
        self,
        X_train: np.ndarray,
        X_val: np.ndarray,
        X_test: np.ndarray
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Normalize features using StandardScaler

        Args:
            X_train, X_val, X_test: Feature arrays

        Returns:
            Normalized arrays
        """
        print("\nNormalizing features...")

        n_samples, seq_len, n_features = X_train.shape

        X_train_flat = X_train.reshape(-1, n_features)
        self.scaler.fit(X_train_flat)

        X_train_norm = self.scaler.transform(X_train_flat).reshape(n_samples, seq_len, n_features)

        n_val = X_val.shape[0]
        X_val_flat = X_val.reshape(-1, n_features)
        X_val_norm = self.scaler.transform(X_val_flat).reshape(n_val, seq_len, n_features)

        n_test = X_test.shape[0]
        X_test_flat = X_test.reshape(-1, n_features)
        X_test_norm = self.scaler.transform(X_test_flat).reshape(n_test, seq_len, n_features)

        return X_train_norm, X_val_norm, X_test_norm

    def build_model(self, input_shape: Tuple[int, int]) -> keras.Model:
        """
        Build LSTM model

        Args:
            input_shape: (sequence_length, n_features)

        Returns:
            Compiled Keras model
        """
        print(f"\nBuilding LSTM model with input shape {input_shape}...")

        model = keras.Sequential([
            layers.Input(shape=input_shape),

            layers.Bidirectional(layers.LSTM(64, return_sequences=True)),
            layers.Dropout(0.3),

            layers.Bidirectional(layers.LSTM(32, return_sequences=False)),
            layers.Dropout(0.3),

            layers.Dense(32, activation='relu'),
            layers.Dropout(0.4),

            layers.Dense(1, activation='sigmoid')
        ])

        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', keras.metrics.Precision(), keras.metrics.Recall()]
        )

        print(model.summary())
        return model

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        epochs: int = 50,
        batch_size: int = 32
    ) -> keras.callbacks.History:
        """
        Train the model

        Args:
            X_train, y_train: Training data
            X_val, y_val: Validation data
            epochs: Maximum epochs
            batch_size: Training batch size

        Returns:
            Training history
        """
        print(f"\nTraining model (epochs={epochs}, batch_size={batch_size})...")

        checkpoint_path = self.output_dir / 'best_model.keras'
        model_callbacks = [
            callbacks.EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True,
                verbose=1
            ),
            callbacks.ModelCheckpoint(
                filepath=str(checkpoint_path),
                monitor='val_loss',
                save_best_only=True,
                verbose=1
            ),
            callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=5,
                min_lr=1e-6,
                verbose=1
            )
        ]

        self.history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            callbacks=model_callbacks,
            verbose=1
        )

        return self.history

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """
        Evaluate model on test set

        Args:
            X_test, y_test: Test data

        Returns:
            Dictionary of metrics
        """
        print("\nEvaluating model on test set...")

        y_pred_proba = self.model.predict(X_test, verbose=0).flatten()
        y_pred = (y_pred_proba >= 0.5).astype(int)

        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0),
            'f1': f1_score(y_test, y_pred, zero_division=0),
            'roc_auc': roc_auc_score(y_test, y_pred_proba),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
        }

        print("\nTest Set Metrics:")
        print(f"  Accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall:    {metrics['recall']:.4f}")
        print(f"  F1-Score:  {metrics['f1']:.4f}")
        print(f"  ROC-AUC:   {metrics['roc_auc']:.4f}")
        print(f"\nConfusion Matrix:")
        print(f"  {metrics['confusion_matrix']}")

        return metrics

    def convert_to_tflite(self, model_name: str = 'ad_detector') -> Path:
        """
        Convert model to TFLite with INT8 quantization

        Args:
            model_name: Output model name

        Returns:
            Path to TFLite model
        """
        print("\nConverting to TFLite with INT8 quantization...")

        converter = tf.lite.TFLiteConverter.from_keras_model(self.model)
        converter.optimizations = [tf.lite.Optimize.DEFAULT]

        tflite_model = converter.convert()

        tflite_path = self.output_dir / f'{model_name}.tflite'
        tflite_path.write_bytes(tflite_model)

        size_mb = tflite_path.stat().st_size / 1024 / 1024
        print(f"TFLite model saved to {tflite_path}")
        print(f"Model size: {size_mb:.2f} MB")

        return tflite_path

    def save_artifacts(self, model_name: str = 'ad_detector'):
        """Save model and scaler"""
        scaler_path = self.output_dir / f'{model_name}_scaler.pkl'
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        print(f"Scaler saved to {scaler_path}")

        metrics_path = self.output_dir / f'{model_name}_metrics.json'
        with open(metrics_path, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'model_name': model_name
            }, f, indent=2)
        print(f"Metrics saved to {metrics_path}")


def main():
    parser = argparse.ArgumentParser(description='Train LSTM ad detector model')
    parser.add_argument('--data', required=True, help='Labeled CSV path')
    parser.add_argument('--epochs', type=int, default=50, help='Max epochs')
    parser.add_argument('--batch-size', type=int, default=32, help='Batch size')
    parser.add_argument('--output-dir', default='models', help='Output directory')
    parser.add_argument('--model-name', default='ad_detector', help='Model name')

    args = parser.parse_args()

    print("="*60)
    print("ML AD DETECTOR - TRAINING PIPELINE")
    print("="*60)

    trainer = ModelTrainer(output_dir=args.output_dir)

    X, y = trainer.load_data(args.data)

    X_seq, y_seq = trainer.build_time_series_dataset(X, y, sequence_length=10)

    X_temp, X_test, y_temp, y_test = train_test_split(
        X_seq, y_seq, test_size=0.15, random_state=42, stratify=y_seq
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.176, random_state=42, stratify=y_temp
    )

    print(f"\nTrain: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")

    X_train, X_val, X_test = trainer.normalize_features(X_train, X_val, X_test)

    trainer.model = trainer.build_model(input_shape=(10, 30))

    trainer.train(X_train, y_train, X_val, y_val, epochs=args.epochs, batch_size=args.batch_size)

    metrics = trainer.evaluate(X_test, y_test)

    tflite_path = trainer.convert_to_tflite(model_name=args.model_name)
    trainer.save_artifacts(model_name=args.model_name)

    print("\n" + "="*60)
    print("TRAINING COMPLETE")
    print("="*60)
    print(f"Model: {tflite_path}")
    print(f"Accuracy: {metrics['accuracy']:.2%}")
    print("="*60)

    return 0


if __name__ == '__main__':
    sys.exit(main())
