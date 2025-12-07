#!/usr/bin/env python3
"""
Automated retraining script for continuous learning
"""

import argparse
import sys
import os
import json
import sqlite3
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, Tuple
import pandas as pd
import numpy as np


class ContinuousLearning:
    """Automated retraining for continuous learning"""

    def __init__(
        self,
        db_path: str = '/opt/ml-ad-detector/data/detector.db',
        training_dir: str = '/opt/ml-ad-detector/training',
        models_dir: str = '/opt/ml-ad-detector/models'
    ):
        """
        Initialize continuous learning

        Args:
            db_path: Path to SQLite database
            training_dir: Training data directory
            models_dir: Models directory
        """
        self.db_path = Path(db_path)
        self.training_dir = Path(training_dir)
        self.models_dir = Path(models_dir)

        self.training_dir.mkdir(parents=True, exist_ok=True)
        self.models_dir.mkdir(parents=True, exist_ok=True)

        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {db_path}")

    def check_retraining_needed(self) -> Tuple[bool, str]:
        """
        Check if retraining is needed

        Returns:
            Tuple of (should_retrain, reason)
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM ml_predictions WHERE actual IS NOT NULL')
        labeled_count = cursor.fetchone()[0]

        if labeled_count < 100:
            conn.close()
            return False, f"Insufficient labeled samples ({labeled_count} < 100)"

        last_retrain_file = self.models_dir / 'last_retrain.txt'
        if last_retrain_file.exists():
            last_retrain = datetime.fromisoformat(last_retrain_file.read_text().strip())
            days_since = (datetime.now() - last_retrain).days

            if days_since >= 7:
                conn.close()
                return True, f"Scheduled retraining (last: {days_since} days ago)"

        cutoff = (datetime.now() - timedelta(days=30)).timestamp()
        cursor.execute('''
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN prediction = actual THEN 1 ELSE 0 END) as correct
            FROM ml_predictions
            WHERE timestamp >= ? AND actual IS NOT NULL
        ''', (cutoff,))

        row = cursor.fetchone()
        total, correct = row

        if total > 50:
            accuracy = correct / total
            if accuracy < 0.75:
                conn.close()
                return True, f"Accuracy drop detected ({accuracy:.2%} < 75%)"

        cursor.execute('''
            SELECT COUNT(*)
            FROM ml_predictions
            WHERE actual IS NOT NULL
                AND timestamp > (
                    SELECT COALESCE(MAX(timestamp), 0)
                    FROM ml_predictions
                    WHERE id IN (SELECT value FROM json_each(
                        (SELECT data FROM retraining_history ORDER BY timestamp DESC LIMIT 1)
                    ))
                )
        ''')

        new_samples = cursor.fetchone()[0] if cursor.fetchone() else labeled_count

        conn.close()

        if new_samples >= 100:
            return True, f"Sufficient new samples ({new_samples} >= 100)"

        return False, "No retraining needed"

    def collect_training_data(self) -> Path:
        """
        Collect training data from database

        Returns:
            Path to collected CSV file
        """
        print("Collecting training data from database...")

        conn = sqlite3.connect(str(self.db_path))

        query = '''
            SELECT
                timestamp, dst_ip, confidence, prediction, actual
            FROM ml_predictions
            WHERE actual IS NOT NULL
            ORDER BY timestamp
        '''

        df = pd.read_sql_query(query, conn)
        conn.close()

        print(f"Collected {len(df)} labeled samples")

        label_map = {0: 'content', 1: 'ad'}
        df['label'] = df['actual'].map(label_map)

        df = df[['timestamp', 'dst_ip', 'label']]

        output_file = self.training_dir / f'retrain_data_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        df.to_csv(output_file, index=False)

        print(f"Training data saved to {output_file}")
        return output_file

    def merge_with_existing_data(self, new_data_path: Path) -> Path:
        """
        Merge new data with existing training data

        Args:
            new_data_path: Path to new data CSV

        Returns:
            Path to merged CSV
        """
        print("Merging with existing training data...")

        existing_files = list(self.training_dir.glob('labeled_*.csv'))

        if not existing_files:
            print("No existing training data found, using new data only")
            return new_data_path

        new_df = pd.read_csv(new_data_path)

        existing_dfs = []
        for f in existing_files:
            try:
                df = pd.read_csv(f)
                existing_dfs.append(df)
            except Exception as e:
                print(f"Warning: Failed to read {f}: {e}")

        if existing_dfs:
            merged_df = pd.concat([new_df] + existing_dfs, ignore_index=True)
            merged_df = merged_df.drop_duplicates(subset=['timestamp', 'dst_ip'], keep='last')

            print(f"Merged dataset: {len(merged_df)} samples")

            merged_file = self.training_dir / f'merged_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            merged_df.to_csv(merged_file, index=False)

            return merged_file

        return new_data_path

    def balance_dataset(self, data_path: Path) -> Path:
        """
        Balance dataset to handle class imbalance

        Args:
            data_path: Path to data CSV

        Returns:
            Path to balanced CSV
        """
        print("Balancing dataset...")

        df = pd.read_csv(data_path)

        label_counts = df['label'].value_counts()
        print(f"Original distribution: {label_counts.to_dict()}")

        min_count = label_counts.min()
        max_count = label_counts.max()

        if max_count / min_count > 2:
            balanced_dfs = []
            for label in df['label'].unique():
                label_df = df[df['label'] == label]

                if len(label_df) > min_count * 1.5:
                    label_df = label_df.sample(n=int(min_count * 1.5), random_state=42)

                balanced_dfs.append(label_df)

            balanced_df = pd.concat(balanced_dfs, ignore_index=True)
            balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)

            print(f"Balanced distribution: {balanced_df['label'].value_counts().to_dict()}")

            balanced_file = self.training_dir / f'balanced_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            balanced_df.to_csv(balanced_file, index=False)

            return balanced_file

        print("Dataset already balanced")
        return data_path

    def train_new_model(self, data_path: Path, epochs: int = 50) -> Path:
        """
        Train new model

        Args:
            data_path: Path to training data
            epochs: Training epochs

        Returns:
            Path to trained model
        """
        print("Training new model...")

        script_dir = Path(__file__).parent.parent
        train_script = script_dir / 'training' / 'train_model.py'

        if not train_script.exists():
            raise FileNotFoundError(f"Training script not found: {train_script}")

        output_dir = self.models_dir / f'retrain_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            sys.executable,
            str(train_script),
            '--data', str(data_path),
            '--epochs', str(epochs),
            '--output-dir', str(output_dir),
            '--model-name', 'ad_detector_retrained'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"Training failed: {result.stderr}")
            raise RuntimeError("Model training failed")

        model_path = output_dir / 'ad_detector_retrained.tflite'

        if not model_path.exists():
            raise FileNotFoundError("Trained model not found")

        print(f"New model trained: {model_path}")
        return model_path

    def compare_models(self, new_model: Path, current_model: Path) -> Dict[str, Any]:
        """
        Compare new model with current model

        Args:
            new_model: Path to new model
            current_model: Path to current model

        Returns:
            Comparison metrics
        """
        print("Comparing models...")

        comparison = {
            'new_model_size': new_model.stat().st_size / 1024 / 1024,
            'current_model_size': current_model.stat().st_size / 1024 / 1024 if current_model.exists() else 0,
            'improvement': 'unknown'
        }

        print(f"New model size: {comparison['new_model_size']:.2f} MB")
        print(f"Current model size: {comparison['current_model_size']:.2f} MB")

        return comparison

    def deploy_model(self, model_path: Path, dry_run: bool = False):
        """
        Deploy new model via update script

        Args:
            model_path: Path to new model
            dry_run: Test without deploying
        """
        print("Deploying new model...")

        script_dir = Path(__file__).parent.parent
        update_script = script_dir / 'deployment' / 'update_model.sh'

        if not update_script.exists():
            print(f"Warning: Update script not found at {update_script}")
            print("Please deploy manually")
            return

        cmd = ['sudo', str(update_script), '--model', str(model_path)]

        if dry_run:
            cmd.append('--dry-run')

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            print("Model deployed successfully")
        else:
            print(f"Deployment failed: {result.stderr}")
            raise RuntimeError("Model deployment failed")

    def log_retraining(self, metrics: Dict[str, Any]):
        """Log retraining event"""
        (self.models_dir / 'last_retrain.txt').write_text(datetime.now().isoformat())

        log_file = self.models_dir / 'retraining_log.jsonl'
        with open(log_file, 'a') as f:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'metrics': metrics
            }
            f.write(json.dumps(log_entry) + '\n')

        print(f"Retraining logged to {log_file}")

    def run(self, force: bool = False, dry_run: bool = False, epochs: int = 50) -> int:
        """
        Run retraining pipeline

        Args:
            force: Force retraining
            dry_run: Test without deploying
            epochs: Training epochs

        Returns:
            Exit code
        """
        print("="*60)
        print("ML AD DETECTOR - CONTINUOUS LEARNING")
        print("="*60)

        if not force:
            should_retrain, reason = self.check_retraining_needed()
            print(f"\nRetraining check: {reason}")

            if not should_retrain:
                return 0

        data_file = self.collect_training_data()
        merged_file = self.merge_with_existing_data(data_file)
        balanced_file = self.balance_dataset(merged_file)

        new_model = self.train_new_model(balanced_file, epochs=epochs)

        current_model = self.models_dir / 'ad_detector.tflite'
        comparison = self.compare_models(new_model, current_model)

        if not dry_run:
            self.deploy_model(new_model, dry_run=False)
            self.log_retraining(comparison)

        print("\n" + "="*60)
        print("RETRAINING COMPLETE")
        print("="*60)

        return 0


def main():
    parser = argparse.ArgumentParser(description='Automated retraining for continuous learning')
    parser.add_argument('--force', action='store_true', help='Force retraining')
    parser.add_argument('--dry-run', action='store_true', help='Test without deploying')
    parser.add_argument('--epochs', type=int, default=50, help='Training epochs')
    parser.add_argument('--notify', help='Notification webhook URL')
    parser.add_argument('--schedule', action='store_true', help='Set up cron job')

    args = parser.parse_args()

    if args.schedule:
        print("Setting up cron job...")
        print("Add this to crontab: 0 2 * * 0 /usr/bin/python3 /path/to/retrain.py")
        return 0

    try:
        learner = ContinuousLearning()
        return learner.run(force=args.force, dry_run=args.dry_run, epochs=args.epochs)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
