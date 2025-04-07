#!/usr/bin/env python3
"""
AI Network Protection System (Hostname-Specific Logging/Model & Device Control)

This script implements an AI-based network monitoring and protection system that:
1. Captures and analyzes network traffic
2. Detects anomalies using machine learning (CPU/GPU option for TF)
3. Identifies potential threats
4. Alerts users to suspicious activities (HIGH severity only)
5. Provides options for automated responses (IP Blocking for KNOWN_BAD_IP)

Requirements:
- Python 3.8+
- scapy
- scikit-learn
- pandas
- numpy
- matplotlib
- tensorflow (optional for deep learning features, needed for GPU use)
- Npcap (on Windows, installed separately)

Usage:
Linux:   sudo python3 ai_network_monitor.py [-i INTERFACE] [-t TRAINING_SECONDS] [-v] [--device auto|gpu|cpu]
Windows: python ai_network_monitor.py [-i "INTERFACE NAME"] [-t TRAINING_SECONDS] [-v] [--device auto|gpu|cpu] (Run as Administrator)
"""

import os
import sys
import time
import datetime
import socket 
import ipaddress
import threading
import queue
import pickle
import logging
import argparse
import glob # Ensure glob is imported
from collections import defaultdict, deque

# --- Attempt to import core dependencies ---
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import matplotlib.pyplot as plt
    from matplotlib.animation import FuncAnimation
except ImportError as e:
    print(f"Error: Missing critical dependencies. {e}")
    print("Please install required packages (e.g., pip install scapy scikit-learn pandas numpy matplotlib)")
    sys.exit(1)

# --- Attempt to import TensorFlow (optional) ---
has_tensorflow = False
tf = None # Initialize tf to None
try:
    # Optional: Reduce TensorFlow's default logging verbosity
    # os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2' 
    import tensorflow as tf
    has_tensorflow = True
except ImportError:
    print("INFO: TensorFlow not found. Deep learning features will be disabled.")
    pass # Continue without TensorFlow if not installed

# --- Logger Setup (will be configured in main) ---
logger = logging.getLogger("AI-NetworkProtection")
logger.setLevel(logging.INFO) 

class NetworkMonitor:
    """Main class for network monitoring and anomaly detection"""
    
    # --- Thresholds might need tuning based on longer training ---
    def __init__(self, interface=None, training_period=3600, # Default training 1 hour
                 detection_threshold=0.7, alert_threshold=0.6, # Thresholds for likelihood score [0,1] where 1=max anomaly
                 max_history=10000, model_path="network_model.pkl"):
        """
        Initialize the network monitor
        
        Args:
            interface: Network interface to monitor (None for auto-detect)
            training_period: Initial training period in seconds
            detection_threshold: Likelihood score above which traffic is considered anomalous
            alert_threshold: Likelihood score above which a HIGH alert is generated
            max_history: Maximum number of packet features to keep in history for training
            model_path: Path to save/load the trained model data (should be hostname specific)
        """
        self.interface = interface
        self.training_period = training_period
        # Store likelihood thresholds where HIGHER means more anomalous
        self.low_severity_likelihood_threshold = 0.5 # Example: Likelihood > 0.5 is at least LOW
        self.medium_severity_likelihood_threshold = 0.6 # Example: Likelihood > 0.6 is MEDIUM
        self.high_severity_likelihood_threshold = 0.8 # Example: Likelihood > 0.8 is HIGH
        # Note: The script currently only acts on HIGH, these are for context/potential future use
        
        self.max_history = max_history
        self.model_path = model_path 
        
        # Data structures
        self.packet_history = deque(maxlen=max_history)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0, 'byte_count': 0, 'start_time': time.time(), 'last_time': time.time(),
            'intervals': [], 'packet_sizes': [], 'protocols': set(), 'flags': set(),
        })
        
        # Anomaly detection models & scaler
        self.model = None # Isolation Forest
        self.autoencoder = None # TensorFlow Autoencoder
        self.reconstruction_threshold = None # Threshold for Autoencoder
        self.scaler = StandardScaler()
        self.is_training = True
        self.training_start_time = time.time()
        
        # Threat intelligence
        self.known_bad_ips = self.load_threat_intelligence()
        
        # Statistics and state
        self.stats = {
            'total_packets': 0, 'anomalies_detected': 0, 'alerts_generated': 0, 'start_time': time.time()
        }
        
        # Queues and Threads
        self.packet_queue = queue.Queue(maxsize=max_history * 2) # Add maxsize to prevent unbounded growth if processing lags
        self.alert_queue = queue.Queue()
        self.threads = []
        self.running = True
        
        logger.info(f"Network Monitor initialized. Interface: {interface or 'auto'}")
        logger.info(f"Model data will be saved/loaded from: {self.model_path}")
        logger.info(f"Training Period: {self.training_period}s")
        logger.info(f"HIGH Severity Anomaly Likelihood Threshold: >= {self.high_severity_likelihood_threshold:.3f}")


    def load_threat_intelligence(self):
        """
        Load known malicious IP addresses.
        Includes hardcoded IPs, IPs from 'threat_intel.txt' (one per line),
        and all IPs from '*.txt' files in the 'iplists' subdirectory (one per line).
        """
        # Start with hardcoded IPs
        bad_ips = set([
            '185.180.196.70', '91.109.190.8', '103.91.92.193', '45.227.255.206',
        ])
        logger.info(f"Initialized with {len(bad_ips)} hardcoded IPs.")
        initial_count = len(bad_ips)
        total_added = 0

        # --- Process optional single file 'threat_intel.txt' ---
        single_file = 'threat_intel.txt'
        file_ips_added = 0
        try:
            if os.path.exists(single_file):
                logger.info(f"Processing single file: {single_file}")
                with open(single_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        ip_str = line.strip()
                        if not ip_str or ip_str.startswith('#'): continue
                        try:
                            ipaddress.ip_address(ip_str)
                            if ip_str not in bad_ips:
                                bad_ips.add(ip_str)
                                file_ips_added += 1
                        except ValueError:
                            logger.warning(f"Invalid IP format in {single_file} line {line_num}: '{ip_str}'")
                if file_ips_added > 0:
                     logger.info(f"Added {file_ips_added} unique IPs from {single_file}.")
                     total_added += file_ips_added
        except Exception as e:
            logger.error(f"Error processing {single_file}: {e}")

        # --- Process files in './iplists/' directory ---
        iplists_dir = "iplists"
        dir_ips_added = 0
        processed_files_count = 0
        if os.path.isdir(iplists_dir):
            logger.info(f"Processing *.txt files in directory: {iplists_dir}")
            try:
                txt_files = glob.glob(os.path.join(iplists_dir, '*.txt'))
                if not txt_files: logger.info(f"No *.txt files found in '{iplists_dir}'.")

                for filepath in txt_files:
                    filename = os.path.basename(filepath)
                    logger.debug(f"Reading IPs from: {filepath}")
                    file_added_count = 0
                    processed_files_count += 1
                    try:
                        with open(filepath, 'r') as f:
                            for line_num, line in enumerate(f, 1):
                                ip_str = line.strip()
                                if not ip_str or ip_str.startswith('#'): continue
                                try:
                                    ipaddress.ip_address(ip_str)
                                    if ip_str not in bad_ips:
                                        bad_ips.add(ip_str)
                                        dir_ips_added += 1
                                        file_added_count += 1
                                except ValueError:
                                    logger.warning(f"Invalid IP format in {filename} line {line_num}: '{ip_str}'")
                        if file_added_count > 0: logger.debug(f"Added {file_added_count} unique IPs from {filename}.")
                    except Exception as e:
                        logger.error(f"Error reading or processing file {filepath}: {e}")
                
                if dir_ips_added > 0:
                     logger.info(f"Added {dir_ips_added} unique IPs from {processed_files_count} file(s) in '{iplists_dir}'.")
                     total_added += dir_ips_added

            except Exception as e:
                logger.error(f"Error accessing or processing directory {iplists_dir}: {e}")
        else:
            logger.info(f"Directory '{iplists_dir}' not found. Skipping IP list file loading from directory.")

        if total_added > 0: logger.info(f"Total unique IPs added from files: {total_added}")
        logger.info(f"Total known malicious IPs loaded: {len(bad_ips)}")
        return bad_ips

    def start(self):
        """Start all monitoring threads"""
        # Try loading existing model first
        self.load_model()

        # Start background threads
        processor_thread = threading.Thread(target=self.process_packets, name="PacketProcessor", daemon=True)
        alert_thread = threading.Thread(target=self.handle_alerts, name="AlertHandler", daemon=True)
        self.threads.extend([processor_thread, alert_thread])
        processor_thread.start()
        alert_thread.start()
        
        if sys.stdout.isatty():
            viz_thread = threading.Thread(target=self.start_visualization, name="Visualizer", daemon=True)
            self.threads.append(viz_thread)
            viz_thread.start()
        
        # Start packet capture (blocking call)
        try:
            logger.info(f"Starting packet capture on {self.interface or 'default interface'}...")
            sniff(iface=self.interface, prn=self.packet_handler, store=0, stop_filter=lambda p: not self.running)
            logger.info("Packet capture stopped normally.")
        except OSError as e:
             if "No such device" in str(e): logger.error(f"Network interface '{self.interface}' not found.")
             else: logger.error(f"Permission error starting capture (need sudo/Administrator?). Error: {e}")
             self.running = False # Signal threads to stop if capture fails at start
        except Exception as e:
            logger.error(f"Error during packet capture: {e}", exc_info=True)
            self.running = False # Signal threads to stop
        finally:
             if self.running: # If sniff finished but running flag wasn't set false (e.g. by KeyboardInterrupt handler in main)
                  logger.info("Sniff function exited unexpectedly. Initiating stop.")
                  self.stop() # Ensure cleanup happens


    def load_model(self):
        """Load pre-trained model and scaler if available."""
        if os.path.exists(self.model_path):
            try:
                logger.info(f"Loading existing model data from {self.model_path}")
                with open(self.model_path, 'rb') as f:
                    saved_data = pickle.load(f)
                    self.model = saved_data.get('model')
                    self.scaler = saved_data.get('scaler')
                    # Load AE threshold if saved, but AE model itself needs retraining or separate saving/loading
                    self.reconstruction_threshold = saved_data.get('autoencoder_threshold') 
                    
                    if self.model and self.scaler:
                        self.is_training = False # If model loaded, skip initial training
                        self.training_start_time = 0 # Indicate training already done
                        logger.info("Model and scaler loaded successfully. Skipping initial training.")
                        if self.reconstruction_threshold:
                             logger.info(f"Loaded Autoencoder threshold: {self.reconstruction_threshold:.4f}")
                             # Need to ensure AE model is loaded/recreated here if using TF save/load
                    else:
                         logger.warning("Model file found but failed to load valid model/scaler. Starting fresh training.")
                         self.model = None
                         self.scaler = StandardScaler() # Reinitialize scaler
                         self.is_training = True
                         self.training_start_time = time.time()

            except Exception as e:
                logger.error(f"Error loading model from {self.model_path}: {e}. Starting fresh training.")
                self.model = None
                self.scaler = StandardScaler()
                self.is_training = True
                self.training_start_time = time.time()
        else:
             logger.info("No existing model file found. Starting initial training period.")
             self.is_training = True
             self.training_start_time = time.time()


    def stop(self):
        """Stop all threads and clean up"""
        if not self.running: return
        logger.info("Stopping network monitor...")
        self.running = False 
        time.sleep(1.5) 

        # Save the model if it was trained in this session
        # Check if training completed OR if a model exists (was loaded)
        if (not self.is_training and self.training_start_time > 0) or (self.model is not None): 
            try:
                logger.info(f"Attempting to save model data to {self.model_path}")
                with open(self.model_path, 'wb') as f:
                    save_data = {'model': self.model, 'scaler': self.scaler}
                    # Only save threshold if AE was trained/threshold exists
                    if hasattr(self, 'reconstruction_threshold') and self.reconstruction_threshold is not None:
                         save_data['autoencoder_threshold'] = self.reconstruction_threshold
                    pickle.dump(save_data, f)
                logger.info(f"Model data (scaler/threshold) saved to {self.model_path}")
            except Exception as e:
                logger.error(f"Error saving model data: {e}", exc_info=True)
        else:
             logger.info("No trained model to save for this session.")
        
        logger.info("Waiting for threads to finish...")
        # Add main capture thread simulation if needed? No, sniff handles blocking.
        # Add queue cleanup?
        self.packet_queue.join() # Wait for processor to finish queued items
        self.alert_queue.join() # Wait for alerter to finish queued items

        for thread in self.threads:
            if thread.is_alive():
                logger.debug(f"Joining thread: {thread.name}")
                thread.join(timeout=2) 
                if thread.is_alive(): logger.warning(f"Thread {thread.name} did not exit gracefully.")

        try: 
             duration = time.time() - self.stats['start_time']
             logger.info(f"Monitoring session ended. Duration: {duration:.2f}s")
             logger.info(f"Total packets processed (approx): {self.stats['total_packets']}")
             logger.info(f"Anomalies detected (>=LOW): {self.stats['anomalies_detected']}")
             logger.info(f"Alerts generated (HIGH only): {self.stats['alerts_generated']}")
        except KeyError: logger.warning("Could not log final statistics.")
        logger.info("Shutdown complete.")

    def packet_handler(self, packet):
        if not self.running: return
        self.stats['total_packets'] += 1
        try: self.packet_queue.put(packet, block=False) 
        except queue.Full: logger.warning("Packet queue full, dropping packet.")

    def process_packets(self):
        logger.info("Packet processing thread started")
        processed_count = 0
        while self.running:
            try:
                packet = None # Ensure packet is None if queue is empty
                try:
                    packet = self.packet_queue.get(timeout=1)
                    processed_count += 1
                except queue.Empty:
                    # Still check for training completion even if queue empty
                    if self.is_training and (time.time() - self.training_start_time) >= self.training_period:
                         if len(self.packet_history) > 0: self.train_model()
                         else: logger.warning("Training period ended, but no packets collected.")
                         self.is_training = False
                         logger.info("Initial training period finished.")
                    continue 

                features = self.extract_features(packet)
                if not features:
                    self.packet_queue.task_done(); continue
                
                # Only store history during training phase to save memory
                if self.is_training:
                    self.packet_history.append(features) 
                
                self.update_flow_stats(packet, features) # Update flows regardless
                
                # Check training again (in case it finished between queue check and now)
                if self.is_training and (time.time() - self.training_start_time) >= self.training_period:
                    if len(self.packet_history) > 0: self.train_model()
                    else: logger.warning("Training period ended, but no packets collected.")
                    self.is_training = False
                    logger.info("Initial training period finished.")
                
                # Detect anomalies if not training and models are ready
                if not self.is_training and self.model and self.scaler: 
                    self.detect_anomalies(features, packet)
                
                self.packet_queue.task_done()
            
            except Exception as e:
                logger.exception(f"Error processing packet: {e}")
                if packet: # If error happened after getting packet, mark done
                     try: self.packet_queue.task_done()
                     except ValueError: pass # Ignore if already marked done
        logger.info("Packet processing thread stopped.")

    # --- extract_features, update_flow_stats remain the same as last version ---
    def extract_features(self, packet):
        """Extract features from a packet for anomaly detection"""
        features = {}
        if not packet.haslayer(IP): return None
        
        ip_layer = packet.getlayer(IP)
        features['src_ip'] = ip_layer.src
        features['dst_ip'] = ip_layer.dst
        features['ttl'] = ip_layer.ttl
        features['len'] = len(packet) 
        features['proto'] = ip_layer.proto
        features['timestamp'] = packet.time 

        proto_name = 'OTHER'; sport = 0; dport = 0; flags = 0; window = 0; urgptr = 0
        icmp_type = -1; icmp_code = -1; has_payload = 0; payload_len = 0

        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            proto_name = 'TCP'; sport = tcp_layer.sport; dport = tcp_layer.dport
            flags = int(tcp_layer.flags); window = tcp_layer.window; urgptr = tcp_layer.urgptr
            if packet.haslayer(Raw):
                 payload_len = len(packet.getlayer(Raw).load); has_payload = 1 if payload_len > 0 else 0
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            proto_name = 'UDP'; sport = udp_layer.sport; dport = udp_layer.dport
            payload_len = max(0, udp_layer.len - 8); has_payload = 1 if payload_len > 0 else 0
            if payload_len == 0 and packet.haslayer(Raw):
                 payload_len = len(packet.getlayer(Raw).load); has_payload = 1 if payload_len > 0 else 0
        elif packet.haslayer(ICMP):
            icmp_layer = packet.getlayer(ICMP)
            proto_name = 'ICMP'; icmp_type = icmp_layer.type; icmp_code = icmp_layer.code
            payload_len = len(icmp_layer.payload); has_payload = 1 if payload_len > 0 else 0

        features['proto_name'] = proto_name; features['sport'] = sport; features['dport'] = dport
        features['flags'] = flags; features['window'] = window; features['urgptr'] = urgptr
        features['icmp_type'] = icmp_type; features['icmp_code'] = icmp_code
        features['has_payload'] = has_payload; features['payload_len'] = payload_len
        return features

    def update_flow_stats(self, packet, features):
        """Update statistics for the flow this packet belongs to"""
        flow_key = (features['src_ip'], features['dst_ip'], features['proto'], features.get('sport', 0), features.get('dport', 0))
        flow = self.flow_stats[flow_key]
        flow['packet_count'] += 1; flow['byte_count'] += features['len']
        current_time = features['timestamp']
        if flow['packet_count'] > 1: flow['intervals'].append(current_time - flow['last_time']) 
        flow['last_time'] = current_time; flow['packet_sizes'].append(features['len'])
        flow['protocols'].add(features['proto_name'])
        if features['proto_name'] == 'TCP': flow['flags'].add(features['flags'])

    # --- train_model, train_deep_learning_model remain the same as last version ---
    def train_model(self):
        """Train the anomaly detection model using collected data"""
        logger.info("Starting model training...")
        if len(self.packet_history) < 100: 
            logger.warning(f"Not enough data for training ({len(self.packet_history)} packets). Need >= 100. Extending training...")
            self.is_training = True; return

        logger.info(f"Preparing {len(self.packet_history)} packets for training...")
        X = self.prepare_data_for_model(list(self.packet_history))
        if X is None or len(X) == 0:
             logger.error("Failed to prepare data for model training."); self.is_training = True; return
        logger.info(f"Data prepared, shape: {X.shape}. Fitting scaler...")
        try: X_scaled = self.scaler.fit_transform(X); logger.info("Data scaling complete.")
        except Exception as e: logger.exception(f"Error scaling data: {e}"); self.is_training = True; return

        logger.info("Training Isolation Forest model...")
        try:
            contamination_setting = 0.01 # Lowered contamination assumption
            self.model = IsolationForest(n_estimators=100, max_samples='auto', contamination=contamination_setting, random_state=42, n_jobs=-1)
            self.model.fit(X_scaled); logger.info("Isolation Forest training completed.")
        except Exception as e: logger.exception(f"Error training Isolation Forest: {e}"); self.is_training = True; return

        if has_tensorflow:
            logger.info("Attempting to train Deep Learning model...")
            try: self.train_deep_learning_model(X_scaled)
            except Exception as e: logger.error(f"Error training deep learning model: {e}", exc_info=True); self.autoencoder = None; self.reconstruction_threshold = None
        
        logger.info("Model training phase finished.")
        self.packet_history.clear() # Clear history after training to save memory
        logger.info("Packet history cleared.")

    def train_deep_learning_model(self, X_scaled):
        """Train a deep learning autoencoder for anomaly detection"""
        if not has_tensorflow or tf is None: logger.warning("TensorFlow not available."); return
        
        logger.info("Training deep learning autoencoder model...")
        input_dim = X_scaled.shape[1]
        if input_dim == 0: logger.error("Input dimension for Autoencoder is 0."); return

        encoding_dim = max(1, int(input_dim * 0.5)) 
        inputs = tf.keras.layers.Input(shape=(input_dim,))
        encoded = tf.keras.layers.Dense(int(input_dim * 0.75), activation='relu')(inputs)
        encoded = tf.keras.layers.Dropout(0.1)(encoded) 
        encoded = tf.keras.layers.Dense(encoding_dim, activation='relu')(encoded) 
        decoded = tf.keras.layers.Dense(int(input_dim * 0.75), activation='relu')(encoded)
        decoded = tf.keras.layers.Dropout(0.1)(decoded)
        decoded = tf.keras.layers.Dense(input_dim, activation='linear')(decoded) 
        self.autoencoder = tf.keras.Model(inputs, decoded) 
        self.autoencoder.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=0.001), loss='mse')
        logger.info(f"Autoencoder summary:")
        self.autoencoder.summary(print_fn=logger.info)

        epochs = 20; batch_size = 64 
        early_stopping = tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=3, restore_best_weights=True)
        logger.info(f"Fitting Autoencoder for up to {epochs} epochs...")
        history = self.autoencoder.fit( X_scaled, X_scaled, epochs=epochs, batch_size=batch_size, shuffle=True,
                                        validation_split=0.1, callbacks=[early_stopping], verbose=0 )
        final_epoch = len(history.history['loss']); final_val_loss = history.history['val_loss'][-1]
        logger.info(f"Autoencoder training finished after {final_epoch} epochs. Final validation loss: {final_val_loss:.4f}")

        logger.info("Calculating reconstruction error threshold...")
        try:
             reconstructions = self.autoencoder.predict(X_scaled, verbose=0)
             mse = np.mean(np.power(X_scaled - reconstructions, 2), axis=1)
             anomaly_percentile = 98 
             self.reconstruction_threshold = np.percentile(mse, anomaly_percentile) 
             if self.reconstruction_threshold <= 1e-6: # Check against small epsilon
                  logger.warning("Calculated reconstruction threshold is near zero.")
                  mse_mean = np.mean(mse); mse_std = np.std(mse)
                  self.reconstruction_threshold = mse_mean + 3 * mse_std
                  logger.info(f"Using Mean+3*Std threshold: {self.reconstruction_threshold:.4f}")
             else: logger.info(f"Reconstruction threshold set at {anomaly_percentile}th percentile: {self.reconstruction_threshold:.4f}")
        except Exception as e: logger.exception(f"Error calculating reconstruction threshold: {e}"); self.autoencoder = None; self.reconstruction_threshold = None

    # --- prepare_data_for_model remains the same as last version ---
    def prepare_data_for_model(self, packet_list):
        """Convert packet features dictionary list to NumPy array for the model"""
        numeric_data = []; feature_names = ['ttl', 'len', 'proto', 'sport', 'dport', 'flags', 'window', 'urgptr', 'icmp_type', 'icmp_code', 'has_payload', 'payload_len'] 
        if not packet_list: return None
        for p_dict in packet_list:
             features = [
                 p_dict.get('ttl', 0), p_dict.get('len', 0), p_dict.get('proto', 0), p_dict.get('sport', 0), p_dict.get('dport', 0),
                 int(p_dict.get('flags', 0)), p_dict.get('window', 0), p_dict.get('urgptr', 0),
                 p_dict.get('icmp_type', -1), p_dict.get('icmp_code', -1), p_dict.get('has_payload', 0), p_dict.get('payload_len', 0)
             ]; numeric_data.append(features)
        return np.array(numeric_data, dtype=np.float32) 

    # --- detect_anomalies remains the same as last version (with HIGH filter) ---
    def detect_anomalies(self, features, packet):
        """Detect anomalies in network traffic, queue only HIGH severity"""
        # 1. Check Known Bad IPs
        if features['src_ip'] in self.known_bad_ips or features['dst_ip'] in self.known_bad_ips:
            alert = { 'timestamp': features['timestamp'], 'type': 'KNOWN_BAD_IP', 'severity': 'HIGH', 'score': 1.0, 
                      'details': f"Communication with known malicious IP: {features['src_ip'] if features['src_ip'] in self.known_bad_ips else features['dst_ip']}",
                      'packet': None, 'features': features }; self.alert_queue.put(alert); self.stats['alerts_generated'] += 1; return

        # 2. Prepare data for AI models
        if self.model is None or self.scaler is None: return 
        X = self.prepare_data_for_model([features]); 
        if X is None: logger.error("Failed to prepare data for anomaly detection."); return
        try: X_scaled = self.scaler.transform(X)
        except Exception as e: logger.error(f"Error scaling data for detection: {e}"); return

        # 3. Get Anomaly Scores
        if_score_raw = None; ae_reconstruction_error = None
        try: if_score_raw = self.model.decision_function(X_scaled)[0] 
        except Exception as e: logger.error(f"Error getting IsolationForest score: {e}")
        if has_tensorflow and self.autoencoder and self.reconstruction_threshold:
             try:
                  reconstruction = self.autoencoder.predict(X_scaled, verbose=0)
                  ae_reconstruction_error = np.mean(np.power(X_scaled - reconstruction, 2))
             except Exception as e: logger.error(f"Error getting Autoencoder score: {e}")

        # 4. Combine Scores -> Likelihood [0,1] where 1=max anomaly
        if_likelihood = (1.0 - if_score_raw) / 2.0 if if_score_raw is not None else 0.0; ae_likelihood = 0.0
        if ae_reconstruction_error is not None and self.reconstruction_threshold is not None and self.reconstruction_threshold > 1e-6:
             ae_likelihood = min(1.0, ae_reconstruction_error / self.reconstruction_threshold)
        
        if ae_reconstruction_error is not None and if_score_raw is not None: final_likelihood = (if_likelihood + ae_likelihood) / 2.0
        elif if_score_raw is not None: final_likelihood = if_likelihood
        else: return # No valid scores

        # 5. Check Thresholds and Generate HIGH Alerts Only
        is_anomalous = final_likelihood >= self.low_severity_likelihood_threshold # Check if anomalous at all
        if is_anomalous:
            self.stats['anomalies_detected'] += 1 
            severity = 'LOW' 
            if final_likelihood >= self.medium_severity_likelihood_threshold: severity = 'MEDIUM'
            if final_likelihood >= self.high_severity_likelihood_threshold: severity = 'HIGH'
            
            if severity == 'HIGH': # Filter: Only queue HIGH alerts
                 alert = { 'timestamp': features['timestamp'], 'type': 'ANOMALY', 'severity': 'HIGH', 'score': final_likelihood, 
                           'details': self.generate_alert_details(features, final_likelihood), 'packet': None, 'features': features }
                 self.alert_queue.put(alert); self.stats['alerts_generated'] += 1

    # --- generate_alert_details remains the same as last version ---
    def generate_alert_details(self, features, score):
        """Generate human-readable details for an alert"""
        details = f"Anomalous traffic detected (Likelihood Score: {score:.3f})\n" 
        details += f"  Source IP: {features['src_ip']}, Destination IP: {features['dst_ip']}\n"; proto_name = features.get('proto_name', 'OTHER')
        sport = features.get('sport', 0); dport = features.get('dport', 0)
        if proto_name == 'TCP': details += f"  TCP {sport} -> {dport}, flags: {int(features.get('flags', 0))}\n"
        elif proto_name == 'UDP': details += f"  UDP {sport} -> {dport}\n"
        elif proto_name == 'ICMP': details += f"  ICMP type: {features.get('icmp_type', -1)}, code: {features.get('icmp_code', -1)}\n"
        else: details += f"  Protocol: {features.get('proto', 'N/A')}\n"
        details += f"  Packet Length: {features.get('len', 0)}, TTL: {features.get('ttl', 0)}"
        if features.get('has_payload', 0) == 1: details += f", Payload Len: {features.get('payload_len', 0)}"
        return details

    # --- handle_alerts remains the same as last version (only receives HIGH) ---
    def handle_alerts(self):
        """Process and handle alerts from the queue (Now only receives HIGH alerts)"""
        logger.info("Alert handling thread started (Processing HIGH severity alerts only)")
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=1)
                logger.warning(f"ALERT [{alert['severity']}]: Score={alert.get('score', 0.0):.3f} Type={alert.get('type','UNK')}\n{alert['details']}")
                self.take_protective_action(alert)
                self.alert_queue.task_done()
            except queue.Empty: continue
            except Exception as e: logger.exception(f"Error handling alert: {e}")
        logger.info("Alert handling thread stopped.")

    # --- take_protective_action remains the same as last version (with safety filter) ---
    def take_protective_action(self, alert):
        """Take automated protective action based on HIGH severity alert"""
        src_ip = alert['features'].get('src_ip', None); dst_ip = alert['features'].get('dst_ip', None)
        alert_type = alert.get('type', 'ANOMALY') 
        logger.warning(f"!! PROTECTIVE ACTION TRIGGERED !!"); logger.warning(f"   Alert Type: {alert_type}"); # ... (log other details) ...

        # *** SAFETY FILTER: Uncomment the next lines to ONLY block known bad IPs ***
        # if alert_type != 'KNOWN_BAD_IP':
        #     logger.warning("   Automated blocking based on ANOMALY score is currently disabled for safety.")
        #     return

        if sys.platform.startswith("linux") and src_ip:
            import subprocess 
            try:
                check_command = ["iptables", "-C", "INPUT", "-s", src_ip, "-j", "DROP"]; rule_exists = False
                try:
                     result_check = subprocess.run(check_command, capture_output=True, text=True, timeout=5)
                     if result_check.returncode == 0 and not result_check.stderr: rule_exists = True; logger.info(f"   Block rule for {src_ip} already exists.")
                except FileNotFoundError: logger.error("   iptables command not found."); return
                except Exception as e_check: logger.error(f"   Error checking iptables rule for {src_ip}: {e_check}")
                if not rule_exists:
                    block_command = ["iptables", "-I", "INPUT", "1", "-s", src_ip, "-j", "DROP"]; logger.info(f"   Executing: {' '.join(block_command)}")
                    result_add = subprocess.run(block_command, capture_output=True, text=True, timeout=5, check=True) 
                    logger.info(f"   Successfully blocked source IP: {src_ip}")
            except FileNotFoundError: logger.error("   iptables command not found.")
            except subprocess.CalledProcessError as e: logger.error(f"   Failed to block source IP {src_ip} via iptables. Error: {e.stderr.strip()}")
            except subprocess.TimeoutExpired: logger.error(f"   Timeout executing iptables command for {src_ip}.")
            except Exception as e: logger.exception(f"   Failed to execute iptables command: {e}")
        elif sys.platform == "win32": logger.warning("   Automated blocking via netsh not implemented.")
        else: logger.warning(f"   Automated blocking not supported on {sys.platform} for src={src_ip}.")

    # --- start_visualization remains the same as last version ---
    def start_visualization(self):
        """Start a simple visualization of network traffic and anomalies"""
        logger.info("Starting visualization thread")
        try:
             fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8)); fig.suptitle('AI Network Protection - Real-time Monitoring')
             times = deque(maxlen=100); packet_counts = deque(maxlen=100); anomaly_counts = deque(maxlen=100); alert_counts = deque(maxlen=100) 
             def update(frame):
                 current_time = time.time(); times.append(current_time); packet_counts.append(self.stats.get('total_packets', 0))
                 anomaly_counts.append(self.stats.get('anomalies_detected', 0)); alert_counts.append(self.stats.get('alerts_generated', 0))
                 time_list = list(times) 
                 ax1.clear(); ax1.plot(time_list, list(packet_counts), 'b-'); ax1.set_title('Total Packets Processed'); ax1.set_ylabel('Count'); ax1.ticklabel_format(style='plain', axis='y')
                 ax2.clear(); ax2.plot(time_list, list(anomaly_counts), 'y-', label='Anomalies Detected (Any)'); ax2.plot(time_list, list(alert_counts), 'r-', label='Alerts Generated (HIGH)')
                 ax2.set_title('Anomalies & Alerts'); ax2.set_ylabel('Count'); ax2.set_xlabel('Time'); ax2.legend(loc='upper left'); ax2.ticklabel_format(style='plain', axis='y')
                 runtime = current_time - self.stats.get('start_time', current_time)
                 stats_text = f"Runtime: {runtime:.1f}s | Pkts: {self.stats.get('total_packets', 0)} | Anom: {self.stats.get('anomalies_detected', 0)} | Alerts(H): {self.stats.get('alerts_generated', 0)}"
                 for txt in fig.texts:
                      if hasattr(txt, 'set_ha') and txt.get_ha() == 'center': txt.set_visible(False)
                 fig.text(0.5, 0.01, stats_text, ha='center')
                 return ax1, ax2 
             ani = FuncAnimation(fig, update, interval=2000, cache_frame_data=False); plt.tight_layout(); plt.subplots_adjust(bottom=0.15) 
             plt.show(); logger.info("Visualization window closed.")
        except Exception as e: logger.error(f"Visualization thread error: {e}", exc_info=True)


def main():
    """Main function to parse arguments and start the monitor"""
    parser = argparse.ArgumentParser(description='AI Network Protection System')
    parser.add_argument('-i', '--interface', help='Network interface to monitor (e.g., eth0, "Ethernet")')
    parser.add_argument('-t', '--training', type=int, default=3600, help='Initial training period in seconds (default: 3600)')
    parser.add_argument('-m', '--model', default=None, help='Base path/name for model data file (e.g., my_model -> my_model.pkl)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose DEBUG logging')
    # --- ADDED DEVICE ARGUMENT ---
    parser.add_argument('--device', choices=['auto', 'gpu', 'cpu'], default='auto',
                        help='Device for TensorFlow models (auto, gpu, cpu). Default: auto')
    
    args = parser.parse_args()
    
    # --- Determine Hostname and Filenames ---
    try: hostname = socket.gethostname().split('.')[0] 
    except: hostname = "unknown_host"; logger.warning("Could not determine hostname.")
    model_base = args.model if args.model else f"network_{hostname}"
    model_filename = f"{model_base}_model.pkl"
    log_filename = f"{model_base}.log" 

    # --- Configure Logging Explicitly ---
    log_level = logging.DEBUG if args.verbose else logging.INFO
    log_formatter = logging.Formatter('%(asctime)s - %(threadName)s - %(name)s - %(levelname)s - %(message)s') # Added threadName
    logger.handlers.clear() 
    try: # File Handler
        file_handler = logging.FileHandler(log_filename); file_handler.setFormatter(log_formatter); logger.addHandler(file_handler)
    except Exception as e: print(f"Error setting up file logger for {log_filename}: {e}", file=sys.stderr)
    # Stream Handler (console)
    stream_handler = logging.StreamHandler(sys.stdout); stream_handler.setFormatter(log_formatter); logger.addHandler(stream_handler)
    logger.setLevel(log_level)
    logger.propagate = False # Prevent root logger from duplicating messages if configured
    logger.info(f"Logging configured. Level: {logging.getLevelName(log_level)}. File: {log_filename}")
    
    # --- Configure TensorFlow Device Preference ---
    if has_tensorflow and tf: # Check tf is not None
        logger.info(f"TensorFlow device preference set to: {args.device}")
        physical_gpus = [] # Keep track of actual GPUs
        try:
             physical_gpus = tf.config.list_physical_devices('GPU')
        except Exception as e:
             logger.error(f"Error listing physical GPUs: {e}")

        if args.device == 'cpu':
            try:
                tf.config.set_visible_devices([], 'GPU') # Hide all GPUs
                logical_gpus = tf.config.list_logical_devices('GPU')
                logger.info(f"TensorFlow configured to use CPU only. Visible logical GPUs: {len(logical_gpus)}")
            except Exception as e:
                logger.error(f"Failed to configure TensorFlow for CPU only: {e}")
        elif args.device == 'gpu':
            if not physical_gpus:
                logger.warning("GPU requested (--device gpu), but TensorFlow could not find any compatible GPUs. Falling back to CPU.")
            else:
                try:
                     # Explicitly make physical GPUs visible (usually default but good practice)
                     tf.config.set_visible_devices(physical_gpus, 'GPU') 
                     logical_gpus = tf.config.list_logical_devices('GPU')
                     logger.info(f"GPU requested (--device gpu). TensorFlow found {len(physical_gpus)} physical GPU(s). Visible logical GPUs: {len(logical_gpus)}.")
                except Exception as e:
                     logger.error(f"Error configuring TensorFlow for GPU: {e}. May fall back to CPU.")
        else: # 'auto'
            if physical_gpus:
                logger.info(f"Device preference 'auto'. TensorFlow found {len(physical_gpus)} physical GPU(s). Using GPU automatically.")
            else:
                logger.info("Device preference 'auto'. No compatible GPU found by TensorFlow. Using CPU.")
    elif args.device == 'gpu': # If user asked for GPU but TF isn't installed
         logger.warning("GPU requested (--device gpu), but TensorFlow is not installed/imported.")

    # --- Platform Specific Privilege Checks ---
    # ...(Same checks as before using ctypes/os.geteuid if desired)...
    # Simplified for brevity, relying on user running with correct privileges
    if sys.platform == "win32":
         try:
              import ctypes; is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
              if not is_admin: logger.warning("Script may need Administrator privileges on Windows for packet capture.")
         except Exception: logger.warning("Could not check for Administrator privileges.")
    elif sys.platform.startswith("linux") or sys.platform == "darwin":
         try:
              if os.geteuid() != 0: logger.warning("Script may need root privileges (sudo) on Linux/Mac for packet capture.")
         except AttributeError: logger.warning("Could not check user ID. Ensure privileges if capture fails.")
         except NameError: logger.warning("Could not check user ID (os module missing?). Ensure privileges.")


    # --- Create and start the monitor ---
    logger.info(f"Creating NetworkMonitor instance for interface '{args.interface}'")
    monitor = NetworkMonitor(
        interface=args.interface,
        training_period=args.training,
        model_path=model_filename 
    )
    
    main_thread = threading.current_thread(); main_thread.name = "MainThread"
    try:
        monitor.start() # Blocks here on sniff()
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received in main thread.")
    except Exception as e:
         logger.exception(f"An unexpected error occurred in main execution: {e}")
    finally:
        logger.info("Initiating shutdown sequence from main thread...")
        # Ensure monitor.stop() is called even if start() fails early
        if 'monitor' in locals() and isinstance(monitor, NetworkMonitor):
             monitor.stop() 
        else:
             logger.warning("Monitor object not fully initialized, skipping stop call.")

    logger.info("Main thread exiting.")


if __name__ == "__main__":
    if sys.version_info < (3, 8): print("Error: Python 3.8 or higher is required."); sys.exit(1)
    main()


