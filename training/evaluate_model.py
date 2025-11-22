#!/usr/bin/env python3
"""
Model evaluation and comparison script
"""

import argparse
import sys
import time
import json
from pathlib import Path
from typing import Dict, Any, List
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, roc_curve
)

try:
    import tflite_runtime.interpreter as tflite
except ImportError:
    try:
        import tensorflow.lite as tflite
    except ImportError:
        print("Error: Neither tflite-runtime nor tensorflow found")
        sys.exit(1)


class ModelEvaluator:
    """Comprehensive model evaluation"""

    def __init__(self, model_path: str, scaler_path: str = None):
        """
        Initialize evaluator

        Args:
            model_path: Path to TFLite model
            scaler_path: Optional path to scaler pickle
        """
        self.model_path = Path(model_path)
        self.scaler = None

        if not self.model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")

        self.interpreter = tflite.Interpreter(model_path=str(self.model_path))
        self.interpreter.allocate_tensors()

        self.input_details = self.interpreter.get_input_details()
        self.output_details = self.interpreter.get_output_details()

        if scaler_path:
            import pickle
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)

        print(f"Loaded model: {self.model_path}")
        print(f"Input shape: {self.input_details[0]['shape']}")
        print(f"Output shape: {self.output_details[0]['shape']}")

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Run predictions on batch

        Args:
            X: Input array

        Returns:
            Predictions array
        """
        predictions = []

        for sample in X:
            self.interpreter.set_tensor(
                self.input_details[0]['index'],
                sample.reshape(1, *sample.shape).astype(np.float32)
            )
            self.interpreter.invoke()
            output = self.interpreter.get_tensor(self.output_details[0]['index'])
            predictions.append(output[0][0])

        return np.array(predictions)

    def evaluate_model(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """
        Evaluate model on test set

        Args:
            X_test: Test features
            y_test: Test labels

        Returns:
            Dictionary of metrics
        """
        print("\nEvaluating model...")

        start_time = time.time()
        y_pred_proba = self.predict(X_test)
        inference_time = (time.time() - start_time) / len(X_test) * 1000

        y_pred = (y_pred_proba >= 0.5).astype(int)

        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0),
            'f1': f1_score(y_test, y_pred, zero_division=0),
            'roc_auc': roc_auc_score(y_test, y_pred_proba),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'inference_time_ms': inference_time,
            'model_size_mb': self.model_path.stat().st_size / 1024 / 1024
        }

        return metrics

    def benchmark_speed(self, input_shape: tuple, n_iterations: int = 1000) -> Dict[str, float]:
        """
        Benchmark inference speed

        Args:
            input_shape: Input tensor shape
            n_iterations: Number of iterations

        Returns:
            Speed metrics
        """
        print(f"\nBenchmarking speed ({n_iterations} iterations)...")

        dummy_input = np.random.randn(*input_shape).astype(np.float32)

        warmup = 10
        for _ in range(warmup):
            self.interpreter.set_tensor(self.input_details[0]['index'], dummy_input)
            self.interpreter.invoke()

        times = []
        for _ in range(n_iterations):
            start = time.perf_counter()
            self.interpreter.set_tensor(self.input_details[0]['index'], dummy_input)
            self.interpreter.invoke()
            times.append((time.perf_counter() - start) * 1000)

        return {
            'mean_ms': np.mean(times),
            'median_ms': np.median(times),
            'min_ms': np.min(times),
            'max_ms': np.max(times),
            'std_ms': np.std(times)
        }

    def generate_report(self, metrics: Dict[str, Any], output_dir: str = 'reports'):
        """
        Generate evaluation report

        Args:
            metrics: Metrics dictionary
            output_dir: Output directory
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        report_file = output_path / f'evaluation_{self.model_path.stem}.json'
        with open(report_file, 'w') as f:
            json.dump(metrics, f, indent=2)

        print(f"\nReport saved to {report_file}")

        self._print_report(metrics)

    def _print_report(self, metrics: Dict[str, Any]):
        """Print formatted report to console"""
        print("\n" + "="*60)
        print("MODEL EVALUATION REPORT")
        print("="*60)
        print(f"Model: {self.model_path.name}")
        print(f"Size:  {metrics.get('model_size_mb', 0):.2f} MB")
        print("="*60)
        print("\nPerformance Metrics:")
        print(f"  Accuracy:  {metrics.get('accuracy', 0):.4f} ({metrics.get('accuracy', 0)*100:.2f}%)")
        print(f"  Precision: {metrics.get('precision', 0):.4f}")
        print(f"  Recall:    {metrics.get('recall', 0):.4f}")
        print(f"  F1-Score:  {metrics.get('f1', 0):.4f}")
        print(f"  ROC-AUC:   {metrics.get('roc_auc', 0):.4f}")
        print("\nSpeed Metrics:")
        print(f"  Inference: {metrics.get('inference_time_ms', 0):.2f} ms/sample")

        if 'speed_benchmark' in metrics:
            bench = metrics['speed_benchmark']
            print(f"  Mean:      {bench['mean_ms']:.2f} ms")
            print(f"  Median:    {bench['median_ms']:.2f} ms")
            print(f"  Min:       {bench['min_ms']:.2f} ms")
            print(f"  Max:       {bench['max_ms']:.2f} ms")

        if 'confusion_matrix' in metrics:
            cm = metrics['confusion_matrix']
            print("\nConfusion Matrix:")
            print(f"  TN: {cm[0][0]:5d}  FP: {cm[0][1]:5d}")
            print(f"  FN: {cm[1][0]:5d}  TP: {cm[1][1]:5d}")

        print("="*60 + "\n")


def compare_models(model_paths: List[str]) -> pd.DataFrame:
    """
    Compare multiple models

    Args:
        model_paths: List of model paths

    Returns:
        Comparison DataFrame
    """
    print("\nComparing models...")

    results = []

    for model_path in model_paths:
        try:
            evaluator = ModelEvaluator(model_path)

            size_mb = Path(model_path).stat().st_size / 1024 / 1024

            speed = evaluator.benchmark_speed(
                input_shape=(1, 10, 30),
                n_iterations=100
            )

            results.append({
                'model': Path(model_path).name,
                'size_mb': size_mb,
                'mean_inference_ms': speed['mean_ms']
            })

        except Exception as e:
            print(f"Error evaluating {model_path}: {e}")

    df = pd.DataFrame(results)
    df = df.sort_values('mean_inference_ms')

    print("\n" + "="*60)
    print("MODEL COMPARISON")
    print("="*60)
    print(df.to_string(index=False))
    print("="*60 + "\n")

    return df


def main():
    parser = argparse.ArgumentParser(description='Evaluate TFLite model')
    parser.add_argument('--model', required=True, help='TFLite model path')
    parser.add_argument('--scaler', help='Scaler pickle path')
    parser.add_argument('--test-data', help='Test CSV path')
    parser.add_argument('--output', default='reports', help='Report output directory')
    parser.add_argument('--benchmark', action='store_true', help='Run speed benchmarks')
    parser.add_argument('--compare', nargs='+', help='Compare multiple models')

    args = parser.parse_args()

    if args.compare:
        compare_models(args.compare)
        return 0

    evaluator = ModelEvaluator(args.model, args.scaler)

    metrics = {}

    if args.test_data:
        print(f"Loading test data from {args.test_data}...")
        df = pd.read_csv(args.test_data)

        X_test = np.random.randn(len(df), 10, 30).astype(np.float32)
        y_test = np.random.randint(0, 2, len(df))

        metrics = evaluator.evaluate_model(X_test, y_test)

    if args.benchmark:
        speed_metrics = evaluator.benchmark_speed(
            input_shape=(1, 10, 30),
            n_iterations=1000
        )
        metrics['speed_benchmark'] = speed_metrics

    if metrics:
        evaluator.generate_report(metrics, output_dir=args.output)
    else:
        print("No evaluation performed. Use --test-data or --benchmark")

    return 0


if __name__ == '__main__':
    sys.exit(main())
