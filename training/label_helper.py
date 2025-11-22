#!/usr/bin/env python3
"""
Interactive CLI tool for labeling network flows
"""

import argparse
import sys
import json
from pathlib import Path
from typing import Dict, Any, Optional
import pandas as pd
from datetime import datetime


class LabelHelper:
    """Interactive flow labeling tool"""

    LABELS = {
        '0': ('content', 'Normal content request'),
        '1': ('ad', 'Advertisement'),
        '2': ('telemetry', 'Telemetry/Analytics'),
        '3': ('tracking', 'Tracking/Fingerprinting'),
        's': ('skip', 'Skip this flow'),
        'u': ('undo', 'Undo last label'),
        'q': ('quit', 'Save and quit'),
        '?': ('help', 'Show this help')
    }

    def __init__(self, input_file: str, output_file: str, batch_size: int = 50):
        """
        Initialize labeling helper

        Args:
            input_file: CSV file to label
            output_file: Output file for labeled data
            batch_size: Number of flows per session
        """
        self.input_file = Path(input_file)
        self.output_file = Path(output_file)
        self.batch_size = batch_size
        self.session_file = self.input_file.parent / '.label_session.json'

        if not self.input_file.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")

        self.df = pd.read_csv(self.input_file)
        self.current_idx = 0
        self.labels_this_session = 0
        self.history = []

        self._load_session()

    def _load_session(self):
        """Load previous session if exists"""
        if self.session_file.exists():
            try:
                with open(self.session_file, 'r') as f:
                    session = json.load(f)
                    self.current_idx = session.get('current_idx', 0)
                    print(f"\nResuming from flow {self.current_idx}/{len(self.df)}")
            except (json.JSONDecodeError, IOError):
                pass

    def _save_session(self):
        """Save current session state"""
        session = {
            'current_idx': self.current_idx,
            'timestamp': datetime.now().isoformat()
        }
        try:
            with open(self.session_file, 'w') as f:
                json.dump(session, f, indent=2)
        except IOError as e:
            print(f"Warning: Could not save session: {e}")

    def _save_progress(self):
        """Save labeled data to output file"""
        self.output_file.parent.mkdir(parents=True, exist_ok=True)

        labeled_df = self.df[self.df['label'] != ''].copy()

        if len(labeled_df) > 0:
            labeled_df.to_csv(self.output_file, index=False)
            print(f"\nSaved {len(labeled_df)} labeled flows to {self.output_file}")

    def _show_help(self):
        """Display help message"""
        print("\n" + "="*60)
        print("LABELING OPTIONS:")
        print("="*60)
        for key, (label, desc) in self.LABELS.items():
            print(f"  {key:3s} - {desc}")
        print("="*60 + "\n")

    def _show_stats(self):
        """Display labeling statistics"""
        total = len(self.df)
        labeled = len(self.df[self.df['label'] != ''])
        remaining = total - labeled

        label_counts = self.df[self.df['label'] != '']['label'].value_counts()

        print("\n" + "="*60)
        print("LABELING STATISTICS:")
        print("="*60)
        print(f"Total flows:      {total}")
        print(f"Labeled:          {labeled} ({labeled/total*100:.1f}%)")
        print(f"Remaining:        {remaining} ({remaining/total*100:.1f}%)")
        print(f"This session:     {self.labels_this_session}")
        print()
        print("Label distribution:")
        for label, count in label_counts.items():
            print(f"  {label:12s}: {count:5d}")
        print("="*60 + "\n")

    def _display_flow(self, idx: int) -> Dict[str, Any]:
        """
        Display flow details

        Args:
            idx: Flow index

        Returns:
            Flow data dictionary
        """
        if idx >= len(self.df):
            return None

        flow = self.df.iloc[idx]

        print("\n" + "="*60)
        print(f"FLOW {idx + 1}/{len(self.df)}")
        print("="*60)
        print(f"Timestamp:        {datetime.fromtimestamp(flow['timestamp'])}")
        print(f"Source IP:        {flow['src_ip']}")
        print(f"Destination IP:   {flow['dst_ip']}")
        print(f"Destination Port: {flow['dst_port']}")
        print(f"Protocol:         {flow['protocol']}")
        print(f"Duration:         {flow['duration']:.2f}s")
        print(f"Bytes sent:       {flow['bytes_sent']:,}")
        print(f"Bytes received:   {flow['bytes_recv']:,}")
        print(f"Packets sent:     {flow['packets_sent']}")
        print(f"Packets received: {flow['packets_recv']}")
        print(f"State:            {flow['state']}")

        byte_ratio = flow['bytes_sent'] / max(flow['bytes_recv'], 1)
        print(f"Byte ratio:       {byte_ratio:.2f}")

        print("="*60)

        return flow.to_dict()

    def _undo(self) -> bool:
        """
        Undo last label

        Returns:
            True if undo successful
        """
        if not self.history:
            print("Nothing to undo")
            return False

        last_idx, last_label = self.history.pop()
        self.df.at[last_idx, 'label'] = ''
        self.current_idx = last_idx
        self.labels_this_session -= 1

        print(f"Undone: Flow {last_idx} label '{last_label}'")
        return True

    def _set_label(self, idx: int, label: str):
        """Set label for flow"""
        old_label = self.df.at[idx, 'label']
        self.df.at[idx, 'label'] = label

        if old_label == '':
            self.labels_this_session += 1

        self.history.append((idx, old_label))

        if len(self.history) > 20:
            self.history.pop(0)

    def run(self):
        """Run interactive labeling session"""
        print("\n" + "="*60)
        print("ML AD DETECTOR - FLOW LABELING TOOL")
        print("="*60)
        print(f"Input:  {self.input_file}")
        print(f"Output: {self.output_file}")
        print("="*60)

        self._show_help()
        self._show_stats()

        try:
            while self.current_idx < len(self.df):
                if self.df.iloc[self.current_idx]['label'] != '':
                    self.current_idx += 1
                    continue

                flow = self._display_flow(self.current_idx)

                if flow is None:
                    break

                while True:
                    choice = input("\nLabel [0/1/2/3/s/u/q/?]: ").strip().lower()

                    if choice == 'q':
                        self._save_progress()
                        self._save_session()
                        print("\nLabeling session saved. Goodbye!")
                        return 0

                    elif choice == '?':
                        self._show_help()
                        continue

                    elif choice == 'u':
                        if self._undo():
                            break
                        continue

                    elif choice == 's':
                        print("Skipped")
                        self.current_idx += 1
                        break

                    elif choice in ['0', '1', '2', '3']:
                        label_name = self.LABELS[choice][0]
                        self._set_label(self.current_idx, label_name)
                        print(f"Labeled as: {label_name}")
                        self.current_idx += 1
                        break

                    else:
                        print("Invalid choice. Press '?' for help")

                if self.labels_this_session > 0 and self.labels_this_session % 10 == 0:
                    self._save_progress()
                    self._save_session()
                    print(f"\nAuto-saved progress ({self.labels_this_session} labels this session)")

                if self.labels_this_session >= self.batch_size:
                    print(f"\nReached batch size ({self.batch_size})")
                    self._show_stats()

                    if input("Continue labeling? [y/N]: ").strip().lower() != 'y':
                        self._save_progress()
                        self._save_session()
                        return 0

            print("\nAll flows labeled!")
            self._show_stats()
            self._save_progress()

            if self.session_file.exists():
                self.session_file.unlink()

        except KeyboardInterrupt:
            print("\n\nInterrupted by user")
            self._save_progress()
            self._save_session()
            return 1

        return 0


def main():
    parser = argparse.ArgumentParser(
        description='Interactive flow labeling tool'
    )
    parser.add_argument(
        '--input',
        required=True,
        help='Input CSV file to label'
    )
    parser.add_argument(
        '--output',
        help='Output labeled CSV file (default: input_labeled.csv)'
    )
    parser.add_argument(
        '--resume',
        action='store_true',
        help='Resume from saved session'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        default=50,
        help='Flows per session (default: 50)'
    )

    args = parser.parse_args()

    output_file = args.output
    if not output_file:
        input_path = Path(args.input)
        output_file = input_path.parent / 'labeled' / f'{input_path.stem}_labeled.csv'

    try:
        helper = LabelHelper(
            input_file=args.input,
            output_file=output_file,
            batch_size=args.batch_size
        )
        return helper.run()

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
