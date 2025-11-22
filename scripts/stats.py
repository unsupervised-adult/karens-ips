#!/usr/bin/env python3
"""
Statistics viewer and reporter for ML Ad Detector
"""

import argparse
import sys
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, List
import pandas as pd


class StatsViewer:
    """Generate statistics reports from ML detector database"""

    def __init__(self, db_path: str = '/opt/ml-ad-detector/data/detector.db'):
        """
        Initialize stats viewer

        Args:
            db_path: Path to SQLite database
        """
        self.db_path = Path(db_path)

        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {db_path}")

        self.conn = sqlite3.connect(str(self.db_path))

    def __del__(self):
        """Close database connection"""
        if hasattr(self, 'conn'):
            self.conn.close()

    def daily_stats(self, days: int = 7) -> pd.DataFrame:
        """
        Get daily statistics

        Args:
            days: Number of days to retrieve

        Returns:
            DataFrame with daily stats
        """
        query = '''
            SELECT
                DATE(timestamp, 'unixepoch') as date,
                COUNT(*) as total_predictions,
                SUM(CASE WHEN prediction = 1 THEN 1 ELSE 0 END) as blocks,
                SUM(CASE WHEN prediction = 1 AND actual = 0 THEN 1 ELSE 0 END) as false_positives,
                AVG(confidence) as avg_confidence
            FROM ml_predictions
            WHERE timestamp >= ?
            GROUP BY DATE(timestamp, 'unixepoch')
            ORDER BY date DESC
        '''

        cutoff = (datetime.now() - timedelta(days=days)).timestamp()
        df = pd.read_sql_query(query, self.conn, params=(cutoff,))

        df['block_rate'] = (df['blocks'] / df['total_predictions'] * 100).round(2)
        df['fp_rate'] = (df['false_positives'] / df['blocks'].replace(0, 1) * 100).round(2)

        return df

    def weekly_trend(self) -> pd.DataFrame:
        """Get weekly trends"""
        query = '''
            SELECT
                strftime('%Y-W%W', timestamp, 'unixepoch') as week,
                COUNT(*) as total_predictions,
                SUM(CASE WHEN prediction = 1 THEN 1 ELSE 0 END) as blocks,
                AVG(confidence) as avg_confidence
            FROM ml_predictions
            GROUP BY week
            ORDER BY week DESC
            LIMIT 12
        '''

        df = pd.read_sql_query(query, self.conn)
        df['block_rate'] = (df['blocks'] / df['total_predictions'] * 100).round(2)

        return df

    def top_blocked_ips(self, n: int = 10) -> pd.DataFrame:
        """
        Get top blocked IPs

        Args:
            n: Number of IPs to return

        Returns:
            DataFrame with top blocked IPs
        """
        query = '''
            SELECT
                dst_ip,
                COUNT(*) as block_count,
                AVG(confidence) as avg_confidence,
                MAX(timestamp) as last_blocked
            FROM ml_predictions
            WHERE prediction = 1
            GROUP BY dst_ip
            ORDER BY block_count DESC
            LIMIT ?
        '''

        df = pd.read_sql_query(query, self.conn, params=(n,))

        df['last_blocked'] = pd.to_datetime(df['last_blocked'], unit='s')
        df['avg_confidence'] = df['avg_confidence'].round(3)

        return df

    def false_positive_analysis(self) -> pd.DataFrame:
        """Analyze false positive patterns"""
        query = '''
            SELECT
                dst_ip,
                COUNT(*) as fp_count,
                AVG(confidence) as avg_confidence
            FROM ml_predictions
            WHERE prediction = 1 AND actual = 0
            GROUP BY dst_ip
            ORDER BY fp_count DESC
            LIMIT 20
        '''

        df = pd.read_sql_query(query, self.conn)
        df['avg_confidence'] = df['avg_confidence'].round(3)

        return df

    def model_performance(self, days: int = 30) -> Dict[str, Any]:
        """
        Calculate model performance metrics

        Args:
            days: Days to analyze

        Returns:
            Dictionary of performance metrics
        """
        cutoff = (datetime.now() - timedelta(days=days)).timestamp()

        query = '''
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN prediction = 1 THEN 1 ELSE 0 END) as predicted_positive,
                SUM(CASE WHEN actual = 1 THEN 1 ELSE 0 END) as actual_positive,
                SUM(CASE WHEN prediction = 1 AND actual = 1 THEN 1 ELSE 0 END) as true_positive,
                SUM(CASE WHEN prediction = 0 AND actual = 0 THEN 1 ELSE 0 END) as true_negative,
                SUM(CASE WHEN prediction = 1 AND actual = 0 THEN 1 ELSE 0 END) as false_positive,
                SUM(CASE WHEN prediction = 0 AND actual = 1 THEN 1 ELSE 0 END) as false_negative,
                AVG(confidence) as avg_confidence
            FROM ml_predictions
            WHERE timestamp >= ? AND actual IS NOT NULL
        '''

        cursor = self.conn.cursor()
        cursor.execute(query, (cutoff,))
        row = cursor.fetchone()

        if not row or row[0] == 0:
            return {
                'error': 'No labeled data available for performance calculation'
            }

        total, pred_pos, actual_pos, tp, tn, fp, fn, avg_conf = row

        accuracy = (tp + tn) / total if total > 0 else 0
        precision = tp / pred_pos if pred_pos > 0 else 0
        recall = tp / actual_pos if actual_pos > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        return {
            'total_samples': total,
            'accuracy': round(accuracy, 4),
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1_score': round(f1, 4),
            'true_positive': tp,
            'true_negative': tn,
            'false_positive': fp,
            'false_negative': fn,
            'avg_confidence': round(avg_conf, 3)
        }

    def hourly_distribution(self) -> pd.DataFrame:
        """Get hourly prediction distribution"""
        query = '''
            SELECT
                strftime('%H', timestamp, 'unixepoch') as hour,
                COUNT(*) as predictions,
                SUM(CASE WHEN prediction = 1 THEN 1 ELSE 0 END) as blocks
            FROM ml_predictions
            GROUP BY hour
            ORDER BY hour
        '''

        df = pd.read_sql_query(query, self.conn)
        df['block_rate'] = (df['blocks'] / df['predictions'] * 100).round(2)

        return df

    def export_report(
        self,
        output_file: str,
        format: str = 'json',
        period: str = 'daily'
    ):
        """
        Export statistics report

        Args:
            output_file: Output file path
            format: Output format (json, csv, html)
            period: Report period (daily, weekly)
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if period == 'daily':
            df = self.daily_stats(days=30)
        elif period == 'weekly':
            df = self.weekly_trend()
        else:
            raise ValueError(f"Unknown period: {period}")

        if format == 'json':
            df.to_json(output_path, orient='records', indent=2)
        elif format == 'csv':
            df.to_csv(output_path, index=False)
        elif format == 'html':
            df.to_html(output_path, index=False)
        else:
            raise ValueError(f"Unknown format: {format}")

        print(f"Report exported to {output_path}")

    def print_summary(self):
        """Print summary report to console"""
        print("="*60)
        print("ML AD DETECTOR - STATISTICS SUMMARY")
        print("="*60)

        print("\nDaily Stats (Last 7 Days):")
        print("-"*60)
        daily = self.daily_stats(days=7)
        print(daily.to_string(index=False))

        print("\n\nTop Blocked IPs:")
        print("-"*60)
        top_ips = self.top_blocked_ips(n=5)
        print(top_ips.to_string(index=False))

        print("\n\nModel Performance (Last 30 Days):")
        print("-"*60)
        perf = self.model_performance(days=30)
        if 'error' in perf:
            print(perf['error'])
        else:
            for key, value in perf.items():
                print(f"  {key:20s}: {value}")

        print("\n\nHourly Distribution:")
        print("-"*60)
        hourly = self.hourly_distribution()
        print(hourly.to_string(index=False))

        print("="*60 + "\n")


def main():
    parser = argparse.ArgumentParser(description='ML Ad Detector Statistics Viewer')

    parser.add_argument('--db', default='/opt/ml-ad-detector/data/detector.db', help='Database path')

    parser.add_argument('--period', choices=['daily', 'weekly', 'monthly', 'all'], default='daily', help='Report period')

    parser.add_argument('--metric', choices=['predictions', 'blocks', 'accuracy', 'fps'], help='Specific metric to show')

    parser.add_argument('--format', choices=['table', 'json', 'csv', 'html'], default='table', help='Output format')

    parser.add_argument('--export', help='Export to file')

    parser.add_argument('--days', type=int, default=7, help='Number of days for daily stats')

    parser.add_argument('--top', type=int, default=10, help='Number of top IPs to show')

    args = parser.parse_args()

    try:
        viewer = StatsViewer(db_path=args.db)

        if args.export:
            viewer.export_report(args.export, format=args.format, period=args.period)
        elif args.metric == 'predictions':
            df = viewer.daily_stats(days=args.days)
            print(df[['date', 'total_predictions']].to_string(index=False))
        elif args.metric == 'blocks':
            df = viewer.top_blocked_ips(n=args.top)
            print(df.to_string(index=False))
        elif args.metric == 'accuracy':
            perf = viewer.model_performance()
            print(json.dumps(perf, indent=2))
        elif args.metric == 'fps':
            df = viewer.false_positive_analysis()
            print(df.to_string(index=False))
        else:
            viewer.print_summary()

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
