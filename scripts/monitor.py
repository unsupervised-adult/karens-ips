#!/usr/bin/env python3
"""
Real-time monitoring of ML Ad Detector
"""

import sys
import time
import curses
import sqlite3
from pathlib import Path
from datetime import datetime
from collections import deque
from typing import Dict, Any, Optional
import redis


class MLDetectorMonitor:
    """Real-time monitor for ML Ad Detector"""

    def __init__(self, db_path: str = '/opt/ml-ad-detector/data/detector.db'):
        """
        Initialize monitor

        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        self.redis_clients = []
        self.recent_detections = deque(maxlen=20)
        self.stats = {
            'total_predictions': 0,
            'total_blocks': 0,
            'false_positives': 0,
            'last_update': time.time()
        }
        self.paused = False
        self.filter_confidence = 0.0
        self.filter_ip = None

        self._connect_redis()
        self._load_stats()

    def _connect_redis(self):
        """Connect to Redis servers"""
        for port in [6379, 6380]:
            try:
                client = redis.Redis(
                    host='localhost',
                    port=port,
                    decode_responses=True,
                    socket_connect_timeout=2
                )
                client.ping()
                self.redis_clients.append(client)
            except redis.ConnectionError:
                pass

    def _load_stats(self):
        """Load statistics from database"""
        if not Path(self.db_path).exists():
            return

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) FROM ml_predictions')
            self.stats['total_predictions'] = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM ml_predictions WHERE prediction = 1')
            self.stats['total_blocks'] = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM ml_predictions WHERE prediction = 1 AND actual = 0')
            self.stats['false_positives'] = cursor.fetchone()[0]

            conn.close()

        except sqlite3.Error:
            pass

    def _get_recent_predictions(self, limit: int = 20) -> list:
        """Get recent predictions from database"""
        if not Path(self.db_path).exists():
            return []

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            query = '''
                SELECT timestamp, dst_ip, confidence, prediction
                FROM ml_predictions
                ORDER BY timestamp DESC
                LIMIT ?
            '''
            cursor.execute(query, (limit,))
            results = cursor.fetchall()
            conn.close()

            return results

        except sqlite3.Error:
            return []

    def _format_detection(self, timestamp: float, dst_ip: str, confidence: float, prediction: int) -> str:
        """Format detection for display"""
        dt = datetime.fromtimestamp(timestamp)
        time_str = dt.strftime('%H:%M:%S')

        if prediction == 1:
            label = 'Ad'
            status = 'BLOCKED' if confidence >= 0.75 else ''
        else:
            label = 'Content'
            status = ''

        return f"[{time_str}] {dst_ip:15s} → {label:7s} ({confidence:.2f}) {status}"

    def _draw_header(self, stdscr, width: int):
        """Draw header section"""
        stdscr.addstr(0, 0, "═" * width)
        stdscr.addstr(1, (width - 28) // 2, "ML AD DETECTOR MONITOR", curses.A_BOLD)
        stdscr.addstr(2, 0, "═" * width)

    def _draw_status(self, stdscr, y: int, width: int):
        """Draw status section"""
        status_text = "Running" if not self.paused else "Paused"
        stdscr.addstr(y, 2, f"Status: {status_text}")

        elapsed = time.time() - self.stats['last_update']
        predictions_per_sec = self.stats['total_predictions'] / max(elapsed, 1)

        stdscr.addstr(y + 1, 2, f"Predictions: {self.stats['total_predictions']:,} ({predictions_per_sec:.2f}/sec)")

        if self.stats['total_predictions'] > 0:
            block_rate = self.stats['total_blocks'] / self.stats['total_predictions'] * 100
            stdscr.addstr(y + 2, 2, f"Blocks: {self.stats['total_blocks']:,} ({block_rate:.2f}%)")

            if self.stats['total_blocks'] > 0:
                fp_rate = self.stats['false_positives'] / self.stats['total_blocks'] * 100
                stdscr.addstr(y + 3, 2, f"False Positives: {self.stats['false_positives']:,} ({fp_rate:.2f}%)")

    def _draw_detections(self, stdscr, y: int, width: int, height: int):
        """Draw recent detections section"""
        stdscr.addstr(y, 0, "─" * width)
        stdscr.addstr(y + 1, 2, "Recent Detections:", curses.A_BOLD)

        predictions = self._get_recent_predictions(height - y - 3)

        for idx, (timestamp, dst_ip, confidence, prediction) in enumerate(predictions):
            if y + idx + 2 >= height - 1:
                break

            if self.filter_confidence > 0 and confidence < self.filter_confidence:
                continue

            if self.filter_ip and self.filter_ip not in dst_ip:
                continue

            detection_str = self._format_detection(timestamp, dst_ip, confidence, prediction)

            color = curses.A_NORMAL
            if prediction == 1:
                if confidence >= 0.75:
                    color = curses.color_pair(1)
                else:
                    color = curses.color_pair(3)
            else:
                color = curses.color_pair(2)

            try:
                stdscr.addstr(y + idx + 2, 4, detection_str[:width-5], color)
            except curses.error:
                pass

    def _draw_footer(self, stdscr, height: int, width: int):
        """Draw footer with keyboard commands"""
        footer_y = height - 1
        stdscr.addstr(footer_y, 0, "─" * width)

        commands = "q:Quit  p:Pause  c:Clear  s:Stats  f:Filter"
        stdscr.addstr(footer_y, 2, commands)

    def _draw_ui(self, stdscr):
        """Draw complete UI"""
        height, width = stdscr.getmaxyx()

        stdscr.clear()

        self._draw_header(stdscr, width)
        self._draw_status(stdscr, 3, width)
        self._draw_detections(stdscr, 8, width, height)
        self._draw_footer(stdscr, height, width)

        stdscr.refresh()

    def run(self, stdscr):
        """Main monitoring loop"""
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(1000)

        curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)

        while True:
            if not self.paused:
                self._load_stats()

            self._draw_ui(stdscr)

            try:
                key = stdscr.getch()

                if key == ord('q') or key == ord('Q'):
                    break

                elif key == ord('p') or key == ord('P'):
                    self.paused = not self.paused

                elif key == ord('c') or key == ord('C'):
                    stdscr.clear()

                elif key == ord('s') or key == ord('S'):
                    self._show_detailed_stats(stdscr)

                elif key == ord('f') or key == ord('F'):
                    self._set_filter(stdscr)

            except KeyboardInterrupt:
                break

            time.sleep(0.1)

    def _show_detailed_stats(self, stdscr):
        """Show detailed statistics popup"""
        height, width = stdscr.getmaxyx()

        popup_height = 12
        popup_width = 50
        popup_y = (height - popup_height) // 2
        popup_x = (width - popup_width) // 2

        popup = curses.newwin(popup_height, popup_width, popup_y, popup_x)
        popup.box()

        popup.addstr(1, 2, "DETAILED STATISTICS", curses.A_BOLD)
        popup.addstr(2, 2, "─" * (popup_width - 4))

        popup.addstr(3, 2, f"Total Predictions:  {self.stats['total_predictions']:,}")
        popup.addstr(4, 2, f"Total Blocks:       {self.stats['total_blocks']:,}")
        popup.addstr(5, 2, f"False Positives:    {self.stats['false_positives']:,}")

        if self.stats['total_predictions'] > 0:
            block_rate = self.stats['total_blocks'] / self.stats['total_predictions'] * 100
            popup.addstr(7, 2, f"Block Rate:         {block_rate:.2f}%")

        if self.stats['total_blocks'] > 0:
            fp_rate = self.stats['false_positives'] / self.stats['total_blocks'] * 100
            popup.addstr(8, 2, f"FP Rate:            {fp_rate:.2f}%")

        popup.addstr(10, 2, "Press any key to close...")

        popup.refresh()
        popup.nodelay(False)
        popup.getch()

    def _set_filter(self, stdscr):
        """Set filtering options"""
        height, width = stdscr.getmaxyx()

        popup_height = 8
        popup_width = 50
        popup_y = (height - popup_height) // 2
        popup_x = (width - popup_width) // 2

        popup = curses.newwin(popup_height, popup_width, popup_y, popup_x)
        popup.box()

        popup.addstr(1, 2, "SET FILTER", curses.A_BOLD)
        popup.addstr(2, 2, "─" * (popup_width - 4))
        popup.addstr(3, 2, "1. Filter by confidence (0.0-1.0)")
        popup.addstr(4, 2, "2. Filter by IP address")
        popup.addstr(5, 2, "3. Clear filters")
        popup.addstr(6, 2, "Press 1-3 or any other key to cancel")

        popup.refresh()
        popup.nodelay(False)

        key = popup.getch()

        if key == ord('3'):
            self.filter_confidence = 0.0
            self.filter_ip = None

        popup.clear()


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='Monitor ML Ad Detector')
    parser.add_argument('--db', default='/opt/ml-ad-detector/data/detector.db', help='Database path')

    args = parser.parse_args()

    try:
        monitor = MLDetectorMonitor(db_path=args.db)
        curses.wrapper(monitor.run)

    except KeyboardInterrupt:
        print("\nMonitor stopped")
        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
