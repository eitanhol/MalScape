from flask import Flask, request, Response, jsonify, send_from_directory
import csv
import pandas as pd
from ipaddress import ip_address, ip_network
from io import StringIO
import re
import networkx as nx
import community.community_louvain as community_louvain
import numpy as np
from flask_cors import CORS
import argparse
import sys
import logging
import os
from scipy.cluster.hierarchy import linkage, to_tree
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE

global_df = None
global_start_time = None
global_end_time = None
global_duration_seconds = None
attack_detail_map_cache = {}
attack_pairs_for_anomaly_cache = set()

# Set up logging so that we only see errors (keeps things quiet during normal use)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(module)s - %(funcName)s - %(lineno)d - %(message)s"
)

# Precompute internal subnets with their ranges to quickly classify IP addresses
internal_subnets = [
    ip_network('172.28.0.0/16'),
    ip_network('192.168.61.0/24')
]
internal_ranges = [(int(net.network_address), int(net.broadcast_address)) for net in internal_subnets]

# Classify an IP as "Internal" or "External" based on precomputed subnet ranges
def classify_ip_vector(ip):
    try:
        ip_int = int(ip_address(ip))
    except Exception:
        return "External"
    for rmin, rmax in internal_ranges:
        if rmin <= ip_int <= rmax:
            return "Internal"
    return "External"


# Extract payload information using vectorized regex; returns a new DataFrame with parsed columns.
def parse_payload_vectorized(payload_series):
    cols = ["SourcePort", "DestinationPort", "Flags", "Seq", "Ack", "Win", "Len", "TSval", "TSecr"]
    df_extracted = pd.DataFrame(index=payload_series.index, columns=cols)
    
    # Updated regex that accepts either '>' or '→' between ports
    sp_dp_flags = payload_series.str.extract(r'^\s*:?\s*(\d+)\s*(?:>|→)\s*(\d+)\s*\[([^\]]+)\]', expand=True)
    
    df_extracted["SourcePort"]      = sp_dp_flags[0]
    df_extracted["DestinationPort"] = sp_dp_flags[1]
    df_extracted["Flags"]           = sp_dp_flags[2]
    df_extracted["Seq"]             = payload_series.str.extract(r'Seq=(\d+)',   expand=False)
    df_extracted["Ack"]             = payload_series.str.extract(r'Ack=(\d+)',   expand=False)
    df_extracted["Win"]             = payload_series.str.extract(r'Win=(\d+)',   expand=False)
    df_extracted["Len"]             = payload_series.str.extract(r'Len=(\d+)',   expand=False)
    df_extracted["TSval"]           = payload_series.str.extract(r'TSval=(\d+)', expand=False)
    df_extracted["TSecr"]           = payload_series.str.extract(r'TSecr=(\d+)', expand=False)
    df_extracted.fillna("N/A", inplace=True)
    return df_extracted

# Compute clusters using Louvain community detection on a graph of Source and Destination pairs
def compute_clusters(df, resolution=2.5): # df input now expects 'Source', 'Destination', 'Occurrences'
    G = nx.Graph()
    # Filter out self-connections BEFORE grouping
    # Ensure 'Occurrences' is carried over
    df_filtered = df[df["Source"] != df["Destination"]].copy()
    if df_filtered.empty:
        print("Warning: No non-self-connections found for clustering.")
        partition = {node: '0' for node in pd.concat([df['Source'], df['Destination']]).unique() if pd.notna(node)}
        return partition

    # Group by Source/Destination using the filtered DataFrame
    # Sum occurrences for each unique Source-Destination pair to use as weight
    edge_weights = df_filtered.groupby(["Source", "Destination"])["Occurrences"].sum().reset_index()

    for _, row in edge_weights.iterrows():
        src, dst, weight = row["Source"], row["Destination"], row["Occurrences"]
        if pd.notna(src) and pd.notna(dst):
            G.add_edge(src, dst, weight=weight) # Use sum of occurrences as weight

    all_nodes = pd.concat([df['Source'], df['Destination']]).unique()
    partition = {}
    if G.number_of_nodes() > 0:
         try:
             partition = community_louvain.best_partition(G, weight='weight', resolution=resolution)
         except Exception as e:
              print(f"Error during Louvain clustering: {e}. Proceeding without partition.")
              partition = {} 

    final_partition = {
        str(node): str(partition.get(node, 'N/A'))
        for node in all_nodes if pd.notna(node)
    }
    return final_partition

def load_attack_data(filename: str = "GroundTruth.csv", start_time_filter_str: str = None, end_time_filter_str: str = None) -> tuple[dict, set, set]:
    attack_details = {}
    attack_pairs = set()
    attacking_sources = set() 
    script_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(script_dir, filename)
    
    # === New Logging ===
    logging.info(f"load_attack_data called. GroundTruth path: {path}")
    logging.info(f"Time filters received: start_time_filter_str='{start_time_filter_str}', end_time_filter_str='{end_time_filter_str}'")
    # === End New Logging ===

    if os.path.exists(path):
        try:
            gt_dtypes = {
                "Event Type": "category", "C2S ID": "str", "Source IP": "str",
                "Source Port(s)": "str", "Destination IP": "str", "Destination Port(s)": "str",
                "Start Time": "str", "Stop Time": "str"
            }
            gt_usecols = ["Event Type", "Source IP", "Destination IP", "Start Time", "Stop Time"]
            gt = pd.read_csv(path, dtype=gt_dtypes, usecols=gt_usecols, keep_default_na=False, na_filter=False)
            
            # === New Logging ===
            logging.info(f"GroundTruth.csv loaded. Initial rows: {len(gt)}")
            if not gt.empty:
                logging.info(f"GroundTruth head (first 3 rows before time filtering):\n{gt.head(3).to_string()}")
            # === End New Logging ===


            if not gt.empty and start_time_filter_str and end_time_filter_str:
                logging.info(f"Attempting to apply time filter to GroundTruth: Dataset Start='{start_time_filter_str}', Dataset End='{end_time_filter_str}'")
                start_filter_dt = pd.to_datetime(start_time_filter_str, errors='coerce')
                end_filter_dt = pd.to_datetime(end_time_filter_str, errors='coerce')

                # === New Logging ===
                logging.info(f"Parsed dataset time filters: start_filter_dt='{start_filter_dt}', end_filter_dt='{end_filter_dt}'")
                # === End New Logging ===

                if pd.NaT is start_filter_dt or pd.NaT is end_filter_dt:
                    logging.warning("Invalid start or end time filter strings for GroundTruth, not applying time filter.")
                else:
                    gt["Start Time DT"] = pd.to_datetime(gt["Start Time"], errors='coerce')
                    gt["Stop Time DT"] = pd.to_datetime(gt["Stop Time"], errors='coerce')
                    
                    # === New Logging ===
                    logging.info(f"GroundTruth 'Start Time' and 'Stop Time' converted to datetime. Head with DT columns:\n{gt[['Start Time', 'Start Time DT', 'Stop Time', 'Stop Time DT']].head(3).to_string()}")
                    initial_rows_before_dt_dropna = len(gt)
                    # === End New Logging ===
                    
                    gt.dropna(subset=["Start Time DT", "Stop Time DT"], inplace=True)
                    
                    # === New Logging ===
                    logging.info(f"GroundTruth rows after dropping NaT in 'Start Time DT'/'Stop Time DT': {len(gt)} (was {initial_rows_before_dt_dropna})")
                    # === End New Logging ===

                    if not gt.empty:
                        initial_rows_before_overlap_filter = len(gt)
                        # Time overlap condition: (AttackStart <= DataEnd) and (AttackEnd >= DataStart)
                        gt = gt[
                            (gt["Start Time DT"] <= end_filter_dt) &
                            (gt["Stop Time DT"] >= start_filter_dt)
                        ]
                        logging.info(f"GroundTruth filtered from {initial_rows_before_overlap_filter} to {len(gt)} rows based on time overlap.")
                        if not gt.empty:
                             logging.info(f"GroundTruth head (first 3 rows AFTER time filtering):\n{gt.head(3).to_string()}")
                        else:
                             logging.info("GroundTruth became empty after time overlap filtering.")
                    else:
                        logging.info("GroundTruth became empty after attempting to parse time columns for filtering.")
            elif not gt.empty:
                logging.info("No time filters provided to load_attack_data, using all GroundTruth entries.")


            for _, row in gt.iterrows():
                s = str(row["Source IP"]).strip()
                d = str(row["Destination IP"]).strip()
                event_type = str(row["Event Type"]).strip()

                if s and d and event_type: # Ensure not empty after stripping
                    if s: # Check if source IP is not empty string
                        attack_details[(s, d)] = event_type
                        attack_pairs.add((s, d))
                        attack_pairs.add((d, s))
                        attacking_sources.add(s) 
            
            # === New Logging ===
            logging.info(f"Finished processing GroundTruth. Number of unique attack details: {len(attack_details)}")
            logging.info(f"Number of attack pairs: {len(attack_pairs)}")
            logging.info(f"Number of unique attacking sources found: {len(attacking_sources)}")
            if len(attacking_sources) < 10: # Log a few if the list is short
                logging.info(f"Attacking sources: {attacking_sources}")
            # === End New Logging ===

        except pd.errors.EmptyDataError:
            logging.error(f"File '{path}' is empty.")
            return {}, set(), set()
        except Exception as e:
            logging.error(f"Error reading or processing file '{path}': {e}", exc_info=True)
            return {}, set(), set()
    else:
        logging.warning(f"Attack data file not found at '{path}'. Anomaly detection will be based on an empty set of known attacks.")
    return attack_details, attack_pairs, attacking_sources

# Compute the entropy of a given pandas Series using its value distribution
def compute_entropy(series):
    counts = series.value_counts()
    probabilities = counts / counts.sum()
    # Filter out zero probabilities before taking the log
    probabilities = probabilities[probabilities > 0]
    if probabilities.empty:
        return 0.0 # Or np.nan, depending on how you want to treat empty/all-zero cases
    return -np.sum(probabilities * np.log(probabilities))

def parse_flags_string_from_payload(payload_series):
    df_extracted = pd.DataFrame(index=payload_series.index)
    flags_series = payload_series.str.extract(r'^\s*:?\s*\S+\s*(?:>|→)\s*\S+\s*\[([^\]]+)\]', expand=False)
    
    flags_series_fallback = payload_series.str.extract(r'\[([^\]]+)\]', expand=False)
    flags_series = flags_series.fillna(flags_series_fallback) # Fill NaNs from first regex with results from second
    
    df_extracted["Flags"] = flags_series.fillna("N/A") # If neither regex matches, fill with "N/A"
    return df_extracted

def process_csv_to_df(csv_text):
    uploaded_csv_dtypes = {
        "No.": "str", # Representative No. from converter.py
        "Time": "str", # Numeric epoch time, read as string initially
        "Source": "str",
        "Destination": "str",
        "Protocol": "str", 
        "Length": "str", 
        "Info_Orig": "str",
        "Occurrences": "str", # New column for counts
        "Direct_SourcePort": "str", 
        "Direct_DestinationPort": "str", 
        "Direct_IsSYN": "str", 
        "Direct_IsACK": "str",
        "Direct_IsPSH": "str",
        "Direct_IsRST": "str",
        "Direct_Seq": "str",
        "Direct_Ack": "str",
        "Direct_Win": "str",
        "Direct_PayloadLength": "str",
        "Direct_TSval": "str",
        "Direct_TSecr": "str",
    }
    df = pd.read_csv(StringIO(csv_text), dtype=uploaded_csv_dtypes, keep_default_na=False, na_filter=False)
    logging.info(f"Initial DataFrame shape after CSV load (aggregated rows): {df.shape}")

    # Handle Occurrences column
    df["Occurrences"] = pd.to_numeric(df.get("Occurrences"), errors='coerce').fillna(1).astype(int)

    if "Info_Orig" in df.columns:
        df.rename(columns={"Info_Orig": "Payload"}, inplace=True)
    
    if "Payload" in df.columns:
        df["Payload"] = df["Payload"].fillna("").astype(str).str.replace(',', '/', regex=False)
        extracted_flags_df = parse_flags_string_from_payload(df["Payload"])
        df = pd.concat([df, extracted_flags_df[["Flags"]]], axis=1)
        if "Flags" in df.columns:
             df["Flags"] = df["Flags"].astype('category')
    else:
        df["Payload"] = "" 
        df["Flags"] = pd.Series("N/A", index=df.index, dtype='category')

    if "Time" in df.columns:
        df["Time"] = pd.to_numeric(df.get("Time"), errors='coerce')
        df["Time"] = pd.to_datetime(df["Time"], unit='s', errors='coerce')
    else:
        logging.warning("Time column missing. Timing features will be unavailable.")
        df['Time'] = pd.NaT

    df["Length"] = pd.to_numeric(df.get("Length"), errors='coerce').fillna(0)
    df["SourcePort"] = pd.to_numeric(df.get("Direct_SourcePort"), errors='coerce')
    df["DestinationPort"] = pd.to_numeric(df.get("Direct_DestinationPort"), errors='coerce')
    df["Seq"] = pd.to_numeric(df.get("Direct_Seq"), errors='coerce')
    df["Ack"] = pd.to_numeric(df.get("Direct_Ack"), errors='coerce')
    df["Win"] = pd.to_numeric(df.get("Direct_Win"), errors='coerce')
    df["PayloadLength"] = pd.to_numeric(df.get("Direct_PayloadLength"), errors='coerce').fillna(0)
    df["TSval"] = pd.to_numeric(df.get("Direct_TSval"), errors='coerce')
    df["TSecr"] = pd.to_numeric(df.get("Direct_TSecr"), errors='coerce')

    df["IsSYN"] = pd.to_numeric(df.get("Direct_IsSYN"), errors='coerce').fillna(0).astype(np.uint8)
    df["IsRST"] = pd.to_numeric(df.get("Direct_IsRST"), errors='coerce').fillna(0).astype(np.uint8)
    df["IsACK"] = pd.to_numeric(df.get("Direct_IsACK"), errors='coerce').fillna(0).astype(np.uint8)
    df["IsPSH"] = pd.to_numeric(df.get("Direct_IsPSH"), errors='coerce').fillna(0).astype(np.uint8)
    
    if "Protocol" in df.columns:
        df["Protocol"] = df["Protocol"].astype("category")

    is_retransmission_only = False 
    if request and hasattr(request, 'get_json'): 
        request_data = request.get_json(silent=True) 
        if request_data and 'isRetransmissionOnly' in request_data: 
            is_retransmission_only = request_data['isRetransmissionOnly'] 

    if is_retransmission_only: 
            df["IsRetransmission"] = 0 

    df['Source'] = df['Source'].fillna('Unknown_IP').astype(str).str.strip() 
    df['Destination'] = df['Destination'].fillna('Unknown_IP').astype(str).str.strip() 

    if not df.empty: 
        # NodeWeight calculation now uses sum of Occurrences
        if 'Occurrences' not in df.columns: df['Occurrences'] = 1 # Safeguard
        df['Occurrences'] = pd.to_numeric(df['Occurrences'], errors='coerce').fillna(1).astype(int)
        
        # Calculate total occurrences for each Source-Destination pair
        # Store this temporarily to avoid recomputing if needed, or transform directly
        grouped_occurrences = df.groupby(["Source", "Destination"])['Occurrences'].transform("sum")
        
        if not grouped_occurrences.empty: 
            if grouped_occurrences.max() != grouped_occurrences.min(): 
                node_weights = (grouped_occurrences - grouped_occurrences.min()) / (grouped_occurrences.max() - grouped_occurrences.min()) 
            else: 
                node_weights = pd.Series(0.5, index=grouped_occurrences.index) 
        else: 
            node_weights = pd.Series(dtype=float) 
        df["NodeWeight"] = node_weights.reindex(df.index).fillna(0.5) 
    else: 
        df["NodeWeight"] = 0.5 

    unique_ips = pd.Series(pd.concat([df["Source"], df["Destination"]]).unique()) 
    unique_ips_cleaned = unique_ips.dropna().astype(str).str.strip()
    unique_ips_cleaned = unique_ips_cleaned[unique_ips_cleaned != ''] 
    
    classified_ips = unique_ips_cleaned.apply(classify_ip_vector) 
    classification_map = dict(zip(unique_ips_cleaned, classified_ips)) 
    
    df["SourceClassification"] = df["Source"].map(classification_map) 
    df["DestinationClassification"] = df["Destination"].map(classification_map) 
    df["SourceClassification"] = df["SourceClassification"].fillna("External").astype('category') 
    df["DestinationClassification"] = df["DestinationClassification"].fillna("External").astype('category') 

    df["ConnectionID"] = (df["Source"] + ":" + df["SourcePort"].astype(str) + "-" + 
                          df["Destination"] + ":" + df["DestinationPort"].astype(str)) 

    if pd.api.types.is_datetime64_any_dtype(df["Time"]) and "ConnectionID" in df.columns: 
        # Sort by ConnectionID and then Time (of the first packet in an aggregated group)
        df = df.sort_values(by=["ConnectionID", "Time"]) 
        # InterArrivalTime for aggregated rows is tricky. It's the time diff between
        # the first packet of this group and the first packet of the previous group *for the same ConnectionID*.
        df["InterArrivalTime"] = df.groupby("ConnectionID")["Time"].diff().dt.total_seconds() 
        df["InterArrivalTime"] = df["InterArrivalTime"].fillna(0) 
    else: 
        df["InterArrivalTime"] = 0.0 

    # BytesPerSecond: (Total Length of this group of packets) / InterArrivalTime
    # (Length * Occurrences) represents the sum of L2 lengths for the aggregated packets.
    df["BytesPerSecond"] = (df["Length"] * df["Occurrences"]) / df["InterArrivalTime"] 
    df["BytesPerSecond"] = df["BytesPerSecond"].replace([np.inf, -np.inf, np.nan], 0) 

    if "InterArrivalTime" in df.columns and "ConnectionID" in df.columns: 
         df["BurstID"] = df.groupby("ConnectionID")["InterArrivalTime"].transform(lambda x: (x.fillna(0) >= 0.01).cumsum()) 
    else: 
         df["BurstID"] = 0 

    logging.info("Starting ClusterID computation...") 
    cluster_time_start = pd.Timestamp.now() 
    if not df.empty: 
        try: 
            # compute_clusters needs to be aware of 'Occurrences' for edge weights
            node_cluster_map = compute_clusters(df[['Source', 'Destination', 'Occurrences']], resolution=2.5) 
            df["ClusterID"] = df["Source"].astype(str).map(node_cluster_map).fillna('N/A').astype('category') 
        except Exception as e: 
             logging.error(f"Error during initial clustering: {e}. Assigning 'N/A' to ClusterID.") 
             df["ClusterID"] = pd.Series(['N/A'] * len(df), dtype='category') 
    else: 
        df["ClusterID"] = pd.Series(dtype='category') 
    logging.info(f"ClusterID computation took: {pd.Timestamp.now() - cluster_time_start}") 

    cluster_entropy = {} 
    if not df.empty and "ClusterID" in df.columns and df["ClusterID"].nunique(dropna=False) > 0 : 
        if 'Occurrences' not in df.columns: df['Occurrences'] = 1 # Safeguard
        df['Occurrences'] = pd.to_numeric(df['Occurrences'], errors='coerce').fillna(1).astype(int)

        for cluster_id_val, group in df[df['ClusterID'] != 'N/A'].groupby("ClusterID", observed=True): 
            ent_protocol, ent_srcport, ent_dstport = 0.0, 0.0, 0.0 
            if "Protocol" in group.columns and not group["Protocol"].dropna().empty: 
                # Use weighted entropy
                clean_protocols = group["Protocol"].dropna()
                clean_weights_proto = group.loc[clean_protocols.index, "Occurrences"]
                ent_protocol = compute_weighted_entropy(clean_protocols, clean_weights_proto)
            if "SourcePort" in group.columns and not group["SourcePort"].dropna().empty: 
                clean_src_ports = group["SourcePort"].dropna()
                clean_weights_src = group.loc[clean_src_ports.index, "Occurrences"]
                ent_srcport = compute_weighted_entropy(clean_src_ports, clean_weights_src)
            if "DestinationPort" in group.columns and not group["DestinationPort"].dropna().empty: 
                clean_dst_ports = group["DestinationPort"].dropna()
                clean_weights_dst = group.loc[clean_dst_ports.index, "Occurrences"]
                ent_dstport = compute_weighted_entropy(clean_dst_ports, clean_weights_dst)
            valid_entropies = [e for e in [ent_protocol, ent_srcport, ent_dstport] if pd.notna(e) and np.isfinite(e) and e > 0] 
            cluster_entropy[cluster_id_val] = np.mean(valid_entropies) if valid_entropies else 0.0 
    df["ClusterEntropy"] = df["ClusterID"].map(cluster_entropy).fillna(0.0) 

    logging.info(f"CSV processing complete. DataFrame shape (aggregated): {df.shape}") 
    return df

def process_csv(csv_text):
    df = process_csv_to_df(csv_text)
    out = StringIO()
    df.to_csv(out, index=False, quoting=csv.QUOTE_MINIMAL)
    return out.getvalue()

def compute_weighted_entropy(value_series, weight_series):
    if value_series.empty or weight_series.empty:
        return 0.0
    
    # Ensure series are aligned and NaNs are handled if necessary before this point
    # For this function, we assume inputs are clean (e.g., dropna has been applied)
    # and weights correspond to values.
    
    df_temp = pd.DataFrame({'value': value_series, 'weight': weight_series})
    
    # Sum weights for each unique value
    weighted_counts = df_temp.groupby('value')['weight'].sum()
    
    total_weight = weighted_counts.sum()
    
    if total_weight == 0:
        return 0.0
        
    probabilities = weighted_counts / total_weight
    probabilities = probabilities[probabilities > 0] # Filter out zero probabilities
    
    if probabilities.empty:
        return 0.0
        
    return -np.sum(probabilities * np.log2(probabilities))

def group_port(port):
    if pd.isna(port):
        return "N/A"
    try:
        p = int(port)
        if 1 <= p <= 1023:
            return str(p)
        elif 1024 <= p <= 49151:
            return "Registered (1024-49151)"
        elif 49152 <= p <= 65535:
            return "Dyn/Priv (49152-65535)"
        else:
            return "Other" 
    except (ValueError, TypeError): 
        return "N/A"

def group_length(length):
    if pd.isna(length):
        return "N/A"
    try:
        l = int(length)
        if l < 0:  # Handle potential negative lengths as invalid
            return "N/A"
        elif l < 60:
            return "0-59 B"
        elif l < 100:
            return "60-99 B"
        elif l < 200:
            return "100-199 B"
        elif l < 500:
            return "200-499 B"
        elif l < 1000:
            return "500-999 B"
        elif l < 1500:
            return "1000-1499 B"
        else:  # l >= 1500
            return "1500+ B"
    except (ValueError, TypeError):  # Catch if length is not a number
        return "N/A"

# -------------------------------
# Flask endpoints and additional routes
app = Flask(__name__)
CORS(app)
logging.info("--- FLASK APP INITIALIZED, CORS(app) CALLED ---")
print("--- FLASK APP INITIALIZED, CORS(app) CALLED (print) ---")

# Endpoint to filter and aggregate data by different metrics based on user filters
@app.route('/filter_and_aggregate', methods=['POST'])
def filter_and_aggregate():
    global global_df
    if global_df is None:
        logging.warning("/filter_and_aggregate called but global_df is None.")
        return jsonify([])

    if 'Occurrences' not in global_df.columns:
        global_df['Occurrences'] = 1
    global_df['Occurrences'] = pd.to_numeric(global_df['Occurrences'], errors='coerce').fillna(1).astype(int)

    logging.info(f"Entering /filter_and_aggregate. global_df shape (aggregated): {global_df.shape}")

    anomaly_map = (
        global_df
        .groupby("ClusterID")["Anomaly"]
        .apply(lambda s: "anomaly" if (s == "anomaly").any() else "normal")
        .to_dict()
    )

    cluster_attack_types_map = {}
    if "AttackType" in global_df.columns and not global_df.empty:
        for cluster_id, group in global_df.groupby("ClusterID"):
            if cluster_id == 'N/A':
                continue
            unique_cluster_attacks = group["AttackType"][group["AttackType"] != "N/A"].unique()
            cluster_attack_types_map[cluster_id] = list(unique_cluster_attacks) if len(unique_cluster_attacks) > 0 else []

    data = request.get_json()
    logging.info(f"Request data for /filter_and_aggregate: {data}")

    payloadKeyword = data.get("payloadKeyword", "").lower()
    sourceFilter = data.get("sourceFilter", "").lower()
    destinationFilter = data.get("destinationFilter", "").lower()
    protocolFilter = data.get("protocolFilter", "").lower()

    try:
        entropyMin = float(data.get("entropyMin", float('-inf')))
    except (ValueError, TypeError):
        entropyMin = float('-inf')
    try:
        entropyMax = float(data.get("entropyMax", float('inf')))
    except (ValueError, TypeError):
        entropyMax = float('inf')

    isRetransmissionOnly = data.get("isRetransmissionOnly", False)
    metric = data.get("metric", "count")

    min_source_amt = int(data["minSourceAmt"]) if data.get("minSourceAmt","").strip() != "" else 0
    max_source_amt = int(data["maxSourceAmt"]) if data.get("maxSourceAmt","").strip() != "" else float('inf')
    min_dest_amt = int(data["minDestinationAmt"]) if data.get("minDestinationAmt","").strip() != "" else 0
    max_dest_amt = int(data["maxDestinationAmt"]) if data.get("maxDestinationAmt","").strip() != "" else float('inf')

    df = global_df.copy()
    logging.info(f"Initial df copy shape for filtering: {df.shape}")

    if payloadKeyword:
        df = df[df["Payload"].str.lower().str.contains(payloadKeyword, na=False)]
    if sourceFilter:
        df = df[df["Source"].str.lower().str.contains(sourceFilter, na=False)]
    if destinationFilter:
        df = df[df["Destination"].str.lower().str.contains(destinationFilter, na=False)]
    if protocolFilter and "Protocol" in df.columns:
        df = df[df["Protocol"].str.lower().str.contains(protocolFilter, na=False)]

    if "ClusterEntropy" in df.columns:
        df["ClusterEntropy"] = pd.to_numeric(df["ClusterEntropy"], errors='coerce')
        df = df[(df["ClusterEntropy"] >= entropyMin) & (df["ClusterEntropy"] <= entropyMax)]
    else:
        logging.warning("ClusterEntropy column not found in df for filtering.")

    if isRetransmissionOnly and "IsRetransmission" in df.columns:
        df = df[df["IsRetransmission"] == True]

    logging.info(f"df shape after filtering: {df.shape}, for metric: {metric}")
    if df.empty:
        logging.warning(f"DataFrame is empty after applying filters for metric '{metric}'. Returning empty list.")
        return jsonify([])

    agg = pd.Series(dtype=float)
    grouped_by_cluster = df.groupby("ClusterID")

    if metric == "count":
        agg = grouped_by_cluster["Occurrences"].sum()
    elif metric == "% SYN packets" and "IsSYN" in df.columns:
        df["WeightedIsSYN"] = df["IsSYN"] * df["Occurrences"]
        agg = grouped_by_cluster["WeightedIsSYN"].sum() / grouped_by_cluster["Occurrences"].sum().replace(0, 1) * 100
    elif metric == "% RST packets" and "IsRST" in df.columns:
        df["WeightedIsRST"] = df["IsRST"] * df["Occurrences"]
        agg = grouped_by_cluster["WeightedIsRST"].sum() / grouped_by_cluster["Occurrences"].sum().replace(0, 1) * 100
    elif metric == "% ACK packets" and "IsACK" in df.columns:
        df["WeightedIsACK"] = df["IsACK"] * df["Occurrences"]
        agg = grouped_by_cluster["WeightedIsACK"].sum() / grouped_by_cluster["Occurrences"].sum().replace(0, 1) * 100
    elif metric == "% PSH packets" and "IsPSH" in df.columns:
        df["WeightedIsPSH"] = df["IsPSH"] * df["Occurrences"]
        agg = grouped_by_cluster["WeightedIsPSH"].sum() / grouped_by_cluster["Occurrences"].sum().replace(0, 1) * 100
    elif metric == "Unique Destinations":
        agg = grouped_by_cluster["Destination"].nunique()
    elif metric == "Unique Sources":
        agg = grouped_by_cluster["Source"].nunique()
    elif metric == "Unique IPs":
        agg = grouped_by_cluster.apply(
            lambda g: len(set(g["Source"]).union(set(g["Destination"])))
        )
    elif metric == "Payload Size Variance" and "PayloadLength" in df.columns:
        df["PayloadLength"] = pd.to_numeric(df["PayloadLength"], errors="coerce").fillna(0)
        # This calculates variance of the PayloadLength values of the unique (aggregated) rows.
        # True weighted variance reflecting original packets would require a more complex calculation.
        agg = grouped_by_cluster["PayloadLength"].var(ddof=0)
    elif metric == "Packets per Second" and "Time" in df.columns:
        df['Time'] = pd.to_datetime(df['Time'], errors='coerce')
        def packets_per_second(g):
            if g["Time"].count() < 1: return 0
            min_time = g["Time"].min()
            max_time = g["Time"].max()
            duration = (max_time - min_time).total_seconds() if pd.notna(min_time) and pd.notna(max_time) else 0
            total_packets = g["Occurrences"].sum()
            return total_packets / duration if duration > 0 else (total_packets if duration == 0 and total_packets > 0 else 0)
        agg = grouped_by_cluster.apply(packets_per_second)
    elif metric == "Total Data Sent" and "Length" in df.columns: # Length is L2 frame length
        df["Length"] = pd.to_numeric(df["Length"], errors='coerce').fillna(0)
        df["WeightedLength"] = df["Length"] * df["Occurrences"]
        agg = grouped_by_cluster["WeightedLength"].sum()
    elif metric == "Start Time" and "Time" in df.columns:
        df['Time'] = pd.to_datetime(df['Time'], errors='coerce')
        overall_min_time = df['Time'].dropna().min()
        agg_time = grouped_by_cluster["Time"].min()
        if pd.api.types.is_datetime64_any_dtype(overall_min_time) and not agg_time.empty:
            agg = (agg_time - overall_min_time).dt.total_seconds()
        else:
            agg = pd.Series(0, index=agg_time.index, dtype=float)
        agg = agg.fillna(0)
    elif metric == "Duration" and "Time" in df.columns:
        df['Time'] = pd.to_datetime(df['Time'], errors='coerce')
        time_grouped = grouped_by_cluster["Time"]
        agg = (time_grouped.max() - time_grouped.min()).dt.total_seconds()
        agg = agg.fillna(0)
    elif metric == "Average Inter-Arrival Time" and "InterArrivalTime" in df.columns:
        df["InterArrivalTime"] = pd.to_numeric(df["InterArrivalTime"], errors='coerce')
        df["WeightedInterArrivalTime"] = df["InterArrivalTime"] * df["Occurrences"]
        agg = grouped_by_cluster["WeightedInterArrivalTime"].sum() / grouped_by_cluster["Occurrences"].sum().replace(0,1)
        agg = agg.fillna(0)
    elif metric in df.columns and pd.api.types.is_numeric_dtype(df[metric]):
        df[metric] = pd.to_numeric(df[metric], errors='coerce').fillna(0)
        df[f"Weighted_{metric}"] = df[metric] * df["Occurrences"]
        agg = grouped_by_cluster[f"Weighted_{metric}"].sum()
    else:
        logging.warning(f"Metric '{metric}' not found or not supported with Occurrences. Returning zeros.")
        unique_cluster_ids = df["ClusterID"].unique() if not df.empty else []
        agg = pd.Series(0, index=unique_cluster_ids, dtype=float)

    agg = agg.fillna(0)

    logging.info(f"Metric: {metric}, Number of items in agg: {len(agg) if hasattr(agg, '__len__') else 'N/A'}")
    if isinstance(agg, pd.Series) and not agg.empty:
        logging.info(f"Aggregated data (agg) head for metric '{metric}': \n{agg.head().to_string()}")
        if agg.isnull().any():
            logging.warning(f"Agg for metric '{metric}' contains NaNs: \n{agg[agg.isnull()]}")
        if not np.isfinite(agg).all():
            logging.warning(f"Agg for metric '{metric}' contains non-finite values (inf): \n{agg[~np.isfinite(agg)]}")
    elif not isinstance(agg, pd.Series):
         logging.info(f"Aggregated data (agg) for metric '{metric}' is not a Pandas Series. Type: {type(agg)}, Value (first 200 chars): {str(agg)[:200]}")
    else:
        logging.info(f"Aggregated data (agg) for metric '{metric}' is an empty Series.")

    unique_sources = df.groupby("ClusterID")["Source"].nunique()
    unique_destinations = df.groupby("ClusterID")["Destination"].nunique()

    filtered_pivot = []
    for cluster_id_val, value in agg.items():
        src_count = unique_sources.get(cluster_id_val, 0)
        dst_count = unique_destinations.get(cluster_id_val, 0)
        if src_count < min_source_amt or src_count > max_source_amt:
            continue
        if dst_count < min_dest_amt or dst_count > max_dest_amt:
            continue

        if len(filtered_pivot) < 3 :
            logging.info(f"Adding to filtered_pivot: cluster={cluster_id_val}, value={value}, anomaly={anomaly_map.get(cluster_id_val, 'normal')}")

        filtered_pivot.append({
            "cluster": str(cluster_id_val),
            "value": float(value) if pd.notnull(value) and np.isfinite(value) else 0.0,
            "clusterAnomaly": anomaly_map.get(str(cluster_id_val), "normal"),
            "ClusterAttackTypes": cluster_attack_types_map.get(str(cluster_id_val), [])
        })
    logging.info(f"Number of items in filtered_pivot for metric '{metric}': {len(filtered_pivot)}")
    if filtered_pivot:
        logging.info(f"First item in filtered_pivot for metric '{metric}': {filtered_pivot[0]}")
        if len(filtered_pivot) > 1:
             logging.info(f"Last item in filtered_pivot for metric '{metric}': {filtered_pivot[-1]}")
    else:
        logging.info(f"filtered_pivot is empty for metric '{metric}'.")
    return jsonify(filtered_pivot)

@app.route('/hierarchical_clusters', methods=['GET'])
def hierarchical_clusters():
    global global_df
    if global_df is None or global_df.empty:
        logging.warning("/hierarchical_clusters called but global_df is None or empty.")
        return jsonify({"id": "empty_root_no_data", "dist": 0, "no_tree": True, "error": "No data loaded"}), 200

    resolution = 2.5
    try:
        resolution_param = request.args.get("resolution")
        if resolution_param is not None:
            resolution = float(resolution_param)
            if resolution <= 0:
                raise ValueError("Resolution must be positive")
            logging.info(f"Using custom resolution for hierarchical_clusters: {resolution}")
    except (TypeError, ValueError) as e:
        logging.warning(f"Invalid resolution parameter in hierarchical_clusters, using default 2.5: {e}")
        resolution = 2.5

    df_for_dendro = global_df.copy()

    # Ensure Occurrences column is present, default to 1 if not (for safety, though it should be from process_csv_to_df)
    if 'Occurrences' not in df_for_dendro.columns:
        logging.warning("'Occurrences' column not found in df_for_dendro. Defaulting to 1 for this dendrogram calculation.")
        df_for_dendro['Occurrences'] = 1
    else:
        # Ensure it's numeric, as compute_clusters will sum it
        df_for_dendro['Occurrences'] = pd.to_numeric(df_for_dendro['Occurrences'], errors='coerce').fillna(1).astype(int)


    try:
        if 'Source' in df_for_dendro.columns:
            df_for_dendro['Source'] = df_for_dendro['Source'].fillna('Unknown_IP').astype(str).str.strip()
        if 'Destination' in df_for_dendro.columns:
            df_for_dendro['Destination'] = df_for_dendro['Destination'].fillna('Unknown_IP').astype(str).str.strip()

        # Pass 'Source', 'Destination', AND 'Occurrences' to compute_clusters
        # as compute_clusters now uses 'Occurrences' for edge weighting.
        columns_for_clustering = ['Source', 'Destination']
        if 'Occurrences' in df_for_dendro.columns:
            columns_for_clustering.append('Occurrences')
            logging.info("Passing 'Occurrences' to compute_clusters for hierarchical view.")
            node_cluster_map_dendro = compute_clusters(df_for_dendro[columns_for_clustering], resolution=resolution)
        else:
            # Fallback if Occurrences is somehow still missing, though the above safeguard should prevent this
            logging.warning("Executing compute_clusters for hierarchical view WITHOUT 'Occurrences' (should not happen).")
            node_cluster_map_dendro = compute_clusters(df_for_dendro[['Source', 'Destination']], resolution=resolution)
        
        df_for_dendro["DendroClusterID"] = df_for_dendro["Source"].astype(str).map(node_cluster_map_dendro).fillna('N/A')

        cluster_entropy_map_dendro = {}
        if "DendroClusterID" in df_for_dendro.columns and not df_for_dendro.empty:
            # Ensure Occurrences is available for weighted entropy if compute_weighted_entropy is used here.
            # The current compute_entropy is not weighted. If it were, 'Occurrences' would be needed.
            for cluster_id_val, group in df_for_dendro.groupby("DendroClusterID"):
                if cluster_id_val == 'N/A':
                    continue
                entropies = []
                # Assuming compute_entropy is the original one, not compute_weighted_entropy for this specific block.
                # If compute_weighted_entropy IS used here, group['Occurrences'] must be passed.
                if "Protocol" in group.columns and not group["Protocol"].dropna().empty:
                     # If using weighted: compute_weighted_entropy(group["Protocol"].dropna(), group["Occurrences"].loc[group["Protocol"].dropna().index])
                    entropies.append(compute_entropy(group["Protocol"].dropna()))
                if "SourcePort" in group.columns and not group["SourcePort"].dropna().empty:
                    entropies.append(compute_entropy(group["SourcePort"].dropna()))
                if "DestinationPort" in group.columns and not group["DestinationPort"].dropna().empty:
                    entropies.append(compute_entropy(group["DestinationPort"].dropna()))
                
                valid_entropies = [e for e in entropies if e > 0 and pd.notna(e) and np.isfinite(e)]
                cluster_entropy_map_dendro[cluster_id_val] = np.mean(valid_entropies) if valid_entropies else 0.0
        df_for_dendro["DendroClusterEntropy"] = df_for_dendro["DendroClusterID"].map(cluster_entropy_map_dendro).fillna(0.0)
        
        logging.info(f"Computed local clusters for hierarchical view. Resolution {resolution}. "
                     f"{df_for_dendro['DendroClusterID'].nunique(dropna=False)} unique DendroClusterIDs.")

    except Exception as e:
        logging.error(f"Error during local re-clustering or feature calculation in /hierarchical_clusters: {e}", exc_info=True)
        return jsonify({"id": "error_root", "dist": 0, "error": f"Failed to recluster or recalculate features: {str(e)}", "no_tree": True}), 500

    if 'DendroClusterID' not in df_for_dendro.columns or df_for_dendro['DendroClusterID'].nunique(dropna=False) == 0 or \
       (df_for_dendro['DendroClusterID'].nunique(dropna=False) == 1 and df_for_dendro['DendroClusterID'].unique()[0] == 'N/A'):
        logging.warning("No valid DendroClusterIDs available for hierarchical clustering stats.")
        return jsonify({"id": "empty_root_no_clusters", "dist": 0, "no_tree": True, "error": "No valid clusters found for dendrogram"}), 200

    # When aggregating for linkage_data, 'total_packets' should now sum 'Occurrences'
    stats = (
        df_for_dendro[df_for_dendro['DendroClusterID'] != 'N/A']
        .groupby('DendroClusterID')
        .agg(
            # total_packets=('DendroClusterID', 'size'), # OLD
            total_packets=('Occurrences', 'sum'),      # NEW: Sum of original packet counts
            avg_entropy=('DendroClusterEntropy', 'mean') 
        )
        .reset_index()
    )
    stats.rename(columns={'DendroClusterID': 'ClusterID'}, inplace=True)
    stats['avg_entropy'] = stats['avg_entropy'].fillna(0.0)
    stats['total_packets'] = stats['total_packets'].fillna(0).astype(int)


    if stats.empty:
        logging.warning("Stats DataFrame is empty after filtering N/A DendroClusterIDs. Cannot perform hierarchical clustering.")
        return jsonify({"id": "empty_root_no_valid_stats", "dist": 0, "no_tree": True, "error": "No valid clusters for statistics"}), 200

    try:
        stats['ClusterID_num'] = pd.to_numeric(stats['ClusterID'])
        stats = stats.sort_values('ClusterID_num').reset_index(drop=True)
    except ValueError:
        stats = stats.sort_values('ClusterID').reset_index(drop=True)

    linkage_data = stats[['total_packets', 'avg_entropy']].to_numpy()
    if linkage_data.shape[0] < 2:
        logging.warning(f"Not enough distinct dendro-clusters ({linkage_data.shape[0]}) to perform hierarchical clustering in /hierarchical_clusters.")
        cluster_id_val = "N/A"
        if not stats.empty: 
            cluster_id_val = str(stats.loc[0, 'ClusterID']) 

        minimal_tree_response = {
            "id": f"Cluster {cluster_id_val}", "cluster_id": cluster_id_val,
            "dist": 0, "is_minimal": True, "children": [] 
        }
        logging.info(f"Returning minimal tree structure: {minimal_tree_response}")
        return jsonify(minimal_tree_response)
    
    try:
        Z = linkage(linkage_data, method='average')
        root_node_obj, _ = to_tree(Z, rd=True)
    except Exception as e:
        logging.error(f"Error during SciPy hierarchical clustering (linkage or to_tree): {e}", exc_info=True)
        return jsonify({"id": "error_scipy_tree", "dist": 0, "error": f"Hierarchical clustering failed: {str(e)}", "no_tree": True}), 500

    def node_to_dict(node):
        if node.is_leaf():
            try:
                cluster_id_val = str(stats.loc[node.id, 'ClusterID']) 
                return {
                    "id": f"Cluster {cluster_id_val}", "cluster_id": cluster_id_val,     
                    "dist": float(node.dist)          
                }
            except IndexError as ie:
                logging.error(f"IndexError in node_to_dict for leaf: node.id={node.id}, stats len={len(stats)}. Error: {ie}")
                return {"id": f"ErrorLeaf_{node.id}", "cluster_id": "ERROR_ID", "dist": float(node.dist)}
            except KeyError as ke:
                logging.error(f"KeyError in node_to_dict for leaf: stats columns are {stats.columns}. Error: {ke}")
                return {"id": f"ErrorLeaf_{node.id}", "cluster_id": "ERROR_ID_KEY", "dist": float(node.dist)}
        else:
            left_child = node_to_dict(node.get_left())
            right_child = node_to_dict(node.get_right())
            children_list = []
            if left_child: children_list.append(left_child)
            if right_child: children_list.append(right_child)

            return {
                "id": f"Internal_{node.id}", "dist": float(node.dist),    
                "children": children_list
            }

    tree_dict = node_to_dict(root_node_obj)
    logging.info(f"Hierarchical tree_dict successfully generated. Preview: {str(tree_dict)[:1000]}")
    return jsonify(tree_dict)

@app.route('/louvain_ip_graph_data', methods=['GET'])
def louvain_ip_graph_data():
    global global_df, attacking_sources_cache
    if global_df is None or global_df.empty:
        logging.warning("/louvain_ip_graph_data called but global_df is None.")
        return jsonify({"nodes": [], "edges": [], "error": "No data loaded"}), 400

    df_for_graph = global_df.copy()

    if 'Occurrences' not in df_for_graph.columns:
        df_for_graph['Occurrences'] = 1
    df_for_graph['Occurrences'] = pd.to_numeric(df_for_graph['Occurrences'], errors='coerce').fillna(1).astype(int)

    df_for_graph['Source'] = df_for_graph['Source'].astype(str).str.strip()
    df_for_graph['Destination'] = df_for_graph['Destination'].astype(str).str.strip()
    df_for_graph['Length'] = pd.to_numeric(df_for_graph['Length'], errors='coerce').fillna(0)
    
    if 'Anomaly' not in df_for_graph.columns:
        logging.warning("'Anomaly' column missing in df_for_graph for IP graph. Defaulting to 'normal'.")
        df_for_graph['Anomaly'] = 'normal'

    df_for_louvain_clustering_structure = df_for_graph[['Source', 'Destination']].drop_duplicates()
    # Pass Occurrences to compute_clusters if edge weights for community detection should be based on traffic volume
    # For now, using structural communities. If weighted:
    # temp_df_for_community_weights = df_for_graph.groupby(['Source', 'Destination'])['Occurrences'].sum().reset_index()
    # ip_to_louvain_community_map = compute_clusters(temp_df_for_community_weights[['Source', 'Destination', 'Occurrences']], resolution=2.5)
    ip_to_louvain_community_map = compute_clusters(df_for_louvain_clustering_structure[['Source', 'Destination']], resolution=2.5)


    all_ips_involved_series = pd.concat([df_for_graph['Source'], df_for_graph['Destination']]).unique()
    all_ips_involved = [ip for ip in all_ips_involved_series if ip and pd.notna(ip) and str(ip).strip()]

    if not all_ips_involved:
        logging.warning("No valid IPs for IP graph.")
        return jsonify({"nodes": [], "edges": [], "error": "No IP data to process."}), 200

    louvain_community_to_ips = {}
    for ip, comm_id in ip_to_louvain_community_map.items():
        if comm_id not in louvain_community_to_ips:
            louvain_community_to_ips[comm_id] = set()
        louvain_community_to_ips[comm_id].add(ip)

    louvain_community_anomaly_status = {comm_id: False for comm_id in louvain_community_to_ips.keys()}
    anomalous_source_ips_in_df = set(df_for_graph[df_for_graph['Anomaly'] == 'anomaly']['Source'])

    for comm_id, ips_in_community in louvain_community_to_ips.items():
        if not anomalous_source_ips_in_df.isdisjoint(ips_in_community):
             louvain_community_anomaly_status[comm_id] = True

    unique_community_ids = sorted([uid for uid in list(set(ip_to_louvain_community_map.values())) if uid != 'N/A'])
    community_id_to_color = {}
    color_palette = ["#e6194B", "#3cb44b", "#ffe119", "#4363d8", "#f58231", "#911eb4", "#46f0f0", "#f032e6", "#bcf60c", "#fabebe", "#008080", "#e6beff", "#9A6324", "#fffac8", "#800000", "#aaffc3", "#808000", "#ffd8b1", "#000075", "#808080"]
    for i, community_id_val in enumerate(unique_community_ids):
        community_id_to_color[community_id_val] = color_palette[i % len(color_palette)]
    community_id_to_color['N/A'] = '#CCCCCC'

    df_for_graph["WeightedLength"] = df_for_graph["Length"] * df_for_graph["Occurrences"]
    edges_df_agg = df_for_graph.groupby(["Source", "Destination"], observed=True).agg(
        aggregated_packet_count=('Occurrences', 'sum'),
        aggregated_total_length=('WeightedLength', 'sum')
    ).reset_index()

    ip_features_dict = {ip_val: {'outgoing_packet_count': 0, 'incoming_packet_count': 0,
                                 'outgoing_length': 0, 'incoming_length': 0,
                                 'distinct_dest_contacted': 0, 'distinct_sources_contacted_by': 0,
                                 'is_source_sessions': 0, 'is_dest_sessions': 0}
                        for ip_val in all_ips_involved}

    for _, row in edges_df_agg.iterrows():
        src, dst = str(row["Source"]), str(row["Destination"])
        pkt_count = int(row["aggregated_packet_count"])
        total_len = float(row["aggregated_total_length"])
        
        if src in ip_features_dict:
            ip_features_dict[src]['outgoing_packet_count'] += pkt_count
            ip_features_dict[src]['outgoing_length'] += total_len
            ip_features_dict[src]['is_source_sessions'] += 1
        if dst in ip_features_dict:
            ip_features_dict[dst]['incoming_packet_count'] += pkt_count
            ip_features_dict[dst]['incoming_length'] += total_len
            ip_features_dict[dst]['is_dest_sessions'] += 1

    source_to_dest_counts = df_for_graph.groupby('Source', observed=True)['Destination'].nunique()
    dest_to_source_counts = df_for_graph.groupby('Destination', observed=True)['Source'].nunique()
    for ip_val in all_ips_involved:
        if ip_val in source_to_dest_counts:
            ip_features_dict[ip_val]['distinct_dest_contacted'] = source_to_dest_counts[ip_val]
        if ip_val in dest_to_source_counts:
            ip_features_dict[ip_val]['distinct_sources_contacted_by'] = dest_to_source_counts[ip_val]

    feature_matrix_list, ordered_ips_for_matrix = [], [ip for ip in all_ips_involved if ip in ip_features_dict]
    if not ordered_ips_for_matrix:
        return jsonify({"nodes": [], "edges": [], "error": "No processable IP data."}), 200
    
    for ip_val in ordered_ips_for_matrix:
        f = ip_features_dict[ip_val]
        feature_matrix_list.append([
            f['outgoing_packet_count'], f['incoming_packet_count'],
            f['outgoing_length'], f['incoming_length'],
            f['distinct_dest_contacted'], f['distinct_sources_contacted_by'],
            f['is_source_sessions'], f['is_dest_sessions']
        ])

    ip_to_coords, coords_2d = {}, None
    scaling_factor = 100
    random_fallback_scaling = 200

    if feature_matrix_list:
        feature_matrix = np.array(feature_matrix_list)
        if feature_matrix.shape[0] > 0:
            scaler = StandardScaler(); scaled_features = scaler.fit_transform(feature_matrix)
            if scaled_features.shape[0] >= 2 and scaled_features.shape[1] >= 2:
                pca = PCA(n_components=2, random_state=42)
                coords_2d = pca.fit_transform(scaled_features)
                logging.info(f"PCA Explained Variance Ratio: {pca.explained_variance_ratio_}, Total: {sum(pca.explained_variance_ratio_)}")
            elif scaled_features.shape[0] >=1 and scaled_features.shape[1] == 1:
                 coords_2d = np.hstack([scaled_features, np.zeros_like(scaled_features)])
                 logging.info("PCA: Single feature detected, using it as X-axis.")
            else:
                logging.warning(f"Not enough data for PCA (Samples: {scaled_features.shape[0]}, Features: {scaled_features.shape[1]}). Using random positions.")
                num_coords = scaled_features.shape[0] if scaled_features.shape[0] > 0 else len(ordered_ips_for_matrix)
                coords_2d = np.random.rand(num_coords, 2) * random_fallback_scaling
            if coords_2d is not None: coords_2d = coords_2d * scaling_factor
            ip_to_coords = {ip: coords_2d[i] for i, ip in enumerate(ordered_ips_for_matrix)}
    else:
        logging.warning("Empty feature matrix. Using Random for coordinates.");
        temp_coords = np.random.rand(len(ordered_ips_for_matrix), 2) * random_fallback_scaling
        ip_to_coords = {ip: temp_coords[i] for i, ip in enumerate(ordered_ips_for_matrix)}

    nodes_list = []
    for i, ip_str in enumerate(ordered_ips_for_matrix):
        louvain_id = ip_to_louvain_community_map.get(ip_str, 'N/A')
        node_clr = community_id_to_color.get(louvain_id, '#CCCCCC')
        is_anomalous_comm = louvain_community_anomaly_status.get(louvain_id, False)
        classification = classify_ip_vector(ip_str)
        
        node_c_raw = ip_to_coords.get(ip_str, np.array([np.random.uniform(-50,50), np.random.uniform(-50,50)]))
        
        pos_x, pos_y = 0.0, 0.0
        if isinstance(node_c_raw, (np.ndarray, list)) and len(node_c_raw) == 2:
            x_coord_raw, y_coord_raw = node_c_raw[0], node_c_raw[1]
            
            if isinstance(x_coord_raw, (float, np.floating)) and not (np.isnan(x_coord_raw) or np.isinf(x_coord_raw)):
                pos_x = float(x_coord_raw)
            elif pd.notnull(x_coord_raw):
                try: pos_x = float(x_coord_raw)
                except (ValueError, TypeError): logging.warning(f"Could not convert x-coordinate {x_coord_raw} for IP {ip_str}, defaulting to 0.0.")
            
            if isinstance(y_coord_raw, (float, np.floating)) and not (np.isnan(y_coord_raw) or np.isinf(y_coord_raw)):
                pos_y = float(y_coord_raw)
            elif pd.notnull(y_coord_raw):
                try: pos_y = float(y_coord_raw)
                except (ValueError, TypeError): logging.warning(f"Could not convert y-coordinate {y_coord_raw} for IP {ip_str}, defaulting to 0.0.")
        
        raw_features = ip_features_dict.get(ip_str, {})
        total_packet_count_for_node = raw_features.get('outgoing_packet_count', 0) + raw_features.get('incoming_packet_count', 0)

        nodes_list.append({
            "data": {
                "id": ip_str, "label": ip_str, "clusterId": str(louvain_id),
                "classification": str(classification),
                "packet_count": int(total_packet_count_for_node),
                "node_color": node_clr, "is_community_anomalous": is_anomalous_comm,
                "is_attacker": ip_str in attacking_sources_cache,
                "x_original": pos_x, "y_original": pos_y,
                "features_for_pca": {k: int(v) if pd.notnull(v) and np.isfinite(v) else 0 for k, v in raw_features.items()}
            },
            "position": {"x": pos_x, "y": pos_y}
        })

    edges_list = []
    valid_ips_for_edges = set(ordered_ips_for_matrix)
    for _, row in edges_df_agg.iterrows():
        src, dst = str(row["Source"]), str(row["Destination"])
        if src in valid_ips_for_edges and dst in valid_ips_for_edges:
            edges_list.append({
                "data": {
                    "id": f"edge_{src}_{dst}_{np.random.randint(100000)}",
                    "source": src, "target": dst,
                    "packet_count": int(row["aggregated_packet_count"]),
                    "total_length": float(row["aggregated_total_length"])
                }
            })

    logging.info(f"/louvain_ip_graph_data: Nodes {len(nodes_list)}, Edges {len(edges_list)}")
    return jsonify({"nodes": nodes_list, "edges": edges_list})

# Endpoint to return network data for a given cluster
@app.route('/cluster_network', methods=['GET'])
def cluster_network():
    global global_df, attacking_sources_cache # Ensure access to the cache
    if global_df is None:
        logging.error("/cluster_network called but global_df is None.")
        return jsonify({"nodes": [], "edges": [], "error": "No data loaded"}), 500

    cluster_id_param = request.args.get("cluster_id")
    logging.info(f"Processing /cluster_network for cluster_id: {cluster_id_param}")

    if not cluster_id_param:
        logging.error("/cluster_network called without cluster_id.")
        return jsonify({"nodes": [], "edges": [], "error": "cluster_id parameter is missing"}), 400

    try:
        for col in ["Source", "Destination", "Protocol", "ClusterID", "NodeWeight", "SourceClassification", "DestinationClassification", "AttackType", "Length"]:
            if col not in global_df.columns:
                logging.warning(f"Column '{col}' missing in global_df for /cluster_network.")

        df_cluster = global_df[global_df["ClusterID"] == str(cluster_id_param)].copy()
        logging.info(f"df_cluster for {cluster_id_param} shape: {df_cluster.shape}")
        if df_cluster.empty:
            logging.warning(f"df_cluster is empty for cluster_id: {cluster_id_param}. Returning empty network.")
            return jsonify({"nodes": [], "edges": []})

        if 'NodeWeight' not in df_cluster.columns:
            df_cluster.loc[:, 'NodeWeight'] = 0.5
        else:
            df_cluster.loc[:, 'NodeWeight'] = pd.to_numeric(df_cluster['NodeWeight'], errors='coerce').fillna(0.5)

        df_cluster.loc[:, "Source"] = df_cluster["Source"].astype(str).str.strip()
        df_cluster.loc[:, "Destination"] = df_cluster["Destination"].astype(str).str.strip()
        df_cluster.loc[:, "Protocol"] = df_cluster["Protocol"].astype(str).str.strip()

        all_ips_in_cluster_series = pd.concat([df_cluster["Source"], df_cluster["Destination"]]).drop_duplicates()
        all_ips_in_cluster = [str(ip).strip() for ip in all_ips_in_cluster_series if str(ip).strip() and str(ip).strip().lower() != 'nan']

        node_avg_weights = {}
        node_packet_counts = {}
        source_counts = df_cluster["Source"].value_counts()
        destination_counts = df_cluster["Destination"].value_counts()

        for ip_val in all_ips_in_cluster:
            source_weights = df_cluster.loc[df_cluster["Source"] == ip_val, "NodeWeight"]
            dest_weights = df_cluster.loc[df_cluster["Destination"] == ip_val, "NodeWeight"]
            all_weights_for_ip = pd.concat([source_weights, dest_weights]).dropna()
            node_avg_weights[ip_val] = all_weights_for_ip.mean() if not all_weights_for_ip.empty else 0.5
            node_packet_counts[ip_val] = len(df_cluster[(df_cluster["Source"] == ip_val) | (df_cluster["Destination"] == ip_val)])

        nodes_data = {}
        edges_data = {}
        edge_attack_types_map = {}

        if "AttackType" in df_cluster.columns:
            df_cluster.loc[:, "AttackType"] = df_cluster["AttackType"].astype(str)
            for (src, dst, proto), group in df_cluster.groupby(["Source", "Destination", "Protocol"]):
                attack_type_for_edge = "N/A"
                unique_attacks_on_edge = group["AttackType"][group["AttackType"].str.upper() != "N/A"].unique()
                if len(unique_attacks_on_edge) > 0:
                    attack_type_for_edge = unique_attacks_on_edge[0]
                edge_key_for_lookup = f"{src}|{dst}|{proto}"
                edge_attack_types_map[edge_key_for_lookup] = attack_type_for_edge

        node_involved_attack_types = {}
        if "AttackType" in df_cluster.columns and not df_cluster.empty:
            for node_ip_str in all_ips_in_cluster:
                involved_rows = df_cluster[(df_cluster["Source"] == node_ip_str) | (df_cluster["Destination"] == node_ip_str)]
                unique_node_attacks = involved_rows["AttackType"].astype(str)[involved_rows["AttackType"].str.upper() != "N/A"].unique()
                node_involved_attack_types[node_ip_str] = list(unique_node_attacks) if len(unique_node_attacks) > 0 else []

        for idx, row in df_cluster.iterrows():
            source_ip = row["Source"]
            destination_ip = row["Destination"]
            protocol = row["Protocol"]

            if not source_ip or not destination_ip or not protocol:
                logging.warning(f"Skipping row {idx} due to empty source/dest/protocol: S='{source_ip}', D='{destination_ip}', P='{protocol}'")
                continue

            source_classification = str(row.get("SourceClassification", "")).strip()
            if not source_classification or source_classification.lower() == 'nan':
                source_classification = classify_ip_vector(source_ip)

            destination_classification = str(row.get("DestinationClassification", "")).strip()
            if not destination_classification or destination_classification.lower() == 'nan':
                destination_classification = classify_ip_vector(destination_ip)

            if source_ip not in nodes_data:
                nodes_data[source_ip] = {
                    "id": source_ip,
                    "label": source_ip,
                    "Classification": source_classification,
                    "NodeWeight": node_avg_weights.get(source_ip, 0.5),
                    "packetCount": node_packet_counts.get(source_ip, 0),
                    "InvolvedAttackTypes": node_involved_attack_types.get(source_ip, []),
                    "is_attacker": source_ip in attacking_sources_cache # New flag
                }

            if destination_ip not in nodes_data:
                nodes_data[destination_ip] = {
                    "id": destination_ip,
                    "label": destination_ip,
                    "Classification": destination_classification,
                    "NodeWeight": node_avg_weights.get(destination_ip, 0.5),
                    "packetCount": node_packet_counts.get(destination_ip, 0),
                    "InvolvedAttackTypes": node_involved_attack_types.get(destination_ip, []),
                    "is_attacker": destination_ip in attacking_sources_cache # New flag
                }

            edge_key = f"{source_ip}|{destination_ip}|{protocol}"
            if edge_key not in edges_data:
                edges_data[edge_key] = {
                    "data": {
                        "id": f"edge-{source_ip}-{destination_ip}-{protocol}-{np.random.randint(10000)}", # Ensure more unique ID
                        "source": source_ip, "target": destination_ip, "Protocol": protocol,
                        "EdgeWeight": 0, "processCount": 0,
                        "AttackType": edge_attack_types_map.get(edge_key, "N/A")
                    }
                }
            current_length = 0
            try:
                current_length = float(row.get("Length", 0))
                if pd.isna(current_length): current_length = 0
            except (ValueError, TypeError):
                current_length = 0
            edges_data[edge_key]["data"]["EdgeWeight"] += current_length
            edges_data[edge_key]["data"]["processCount"] += 1

        final_nodes_list = [{"data": node_info} for node_info in nodes_data.values()]
        network_data = {"nodes": final_nodes_list, "edges": list(edges_data.values())}

        logging.info(f"Successfully prepared network data for cluster {cluster_id_param}. Nodes: {len(final_nodes_list)}, Edges: {len(edges_data)}")
        return jsonify(convert_nan_to_none(network_data)) # Assumes convert_nan_to_none is defined

    except Exception as e:
        logging.exception(f"Critical error in /cluster_network for cluster_id {cluster_id_param}:")
        return jsonify({"nodes": [], "edges": [], "error": f"Server error processing cluster {cluster_id_param}: {str(e)}"}), 500

# Endpoint to return rows of a cluster in JSON format (for pagination)
@app.route('/get_cluster_rows', methods=['GET'])
def get_cluster_rows():
    global global_df
    if global_df is None:
        return jsonify({"rows": [], "total": 0})
    cluster_id = request.args.get("cluster_id")
    try:
        page = int(request.args.get("page", 1))
    except Exception as e:
        logging.error(f"Error parsing page: {e}")
        page = 1
    try:
        page_size = int(request.args.get("page_size", 50))
    except Exception as e:
        logging.error(f"Error parsing page_size: {e}")
        page_size = 50
    df_cluster = global_df[global_df["ClusterID"] == str(cluster_id)]
    total = len(df_cluster)
    start = (page - 1) * page_size
    end = start + page_size
    rows = df_cluster.iloc[start:end].replace({np.nan: None}).to_dict(orient="records")
    return jsonify({"rows": rows, "total": total})

# Endpoint to return an HTML table for a given cluster (for use in the web UI)
@app.route('/get_cluster_table', methods=['GET'])
def get_cluster_table():
    global global_df
    if global_df is None:
        return "<p>No data available.</p>"
    cluster_id = request.args.get("cluster_id")
    try:
        page = int(request.args.get("page", 1))
    except Exception as e:
        logging.error(f"Error parsing page: {e}")
        page = 1
    try:
        page_size = int(request.args.get("page_size", 50))
    except Exception as e:
        logging.error(f"Error parsing page_size: {e}")
        page_size = 50

    df_cluster = global_df[global_df["ClusterID"] == str(cluster_id)]
    total = len(df_cluster)
    start = (page - 1) * page_size
    end = start + page_size
    rows = df_cluster.iloc[start:end].replace({np.nan: None}).to_dict(orient="records")
    
    if not rows:
        return "<p>No rows found for this cluster.</p>"
    
    columns = list(rows[0].keys())
    html = "<table style='width:100%; border-collapse: collapse; border:1px solid #ddd;'>"
    html += "<thead><tr>"
    for col in columns:
        html += f"<th style='padding:8px; border:1px solid #ddd; text-align:left;'>{col}</th>"
    html += "</tr></thead>"
    html += "<tbody>"
    for row in rows:
        html += "<tr>"
        for col in columns:
            cell = row[col] if row[col] is not None else ""
            html += f"<td style='padding:8px; border:1px solid #ddd;'>{cell}</td>"
        html += "</tr>"
    html += "</tbody></table>"
    html += f"<p id='table-summary' data-total='{total}'>Showing rows {start + 1} to {min(end, total)} of {total}.</p>"
    return html

@app.route('/sankey_data', methods=['GET'])
def sankey_data():
    global global_df
    if global_df is None or global_df.empty:
        return jsonify({"nodes": [], "links": [], "error": "No data loaded"}), 400

    dimensions_str = request.args.get('dimensions', 'Protocol,SourceClassification') # Default dimensions
    dimensions = [d.strip() for d in dimensions_str.split(',') if d.strip()]

    if not dimensions or len(dimensions) < 2:
        return jsonify({"nodes": [], "links": [], "error": "At least two dimensions are required for Sankey diagram"}), 400
    
    for k in range(len(dimensions) - 1):
        if dimensions[k] == dimensions[k+1]:
            return jsonify({"nodes": [], "links": [], "error": f"Consecutive dimensions cannot be the same: {dimensions[k]}"}), 400
    # (Further duplicate checks can be added if needed, e.g. A-C-A vs A-A-B)

    df_sankey = global_df.copy()
    temp_dim_cols = []

    for i, dim in enumerate(dimensions):
        temp_col_name = f"sankey_dim_{i}_{dim}" # Temporary column name in the DataFrame
        if dim == "SourcePort_Group":
            if "SourcePort" in df_sankey.columns:
                df_sankey[temp_col_name] = df_sankey["SourcePort"].apply(group_port)
            else:
                df_sankey[temp_col_name] = "N/A"
        elif dim == "DestinationPort_Group":
            if "DestinationPort" in df_sankey.columns:
                df_sankey[temp_col_name] = df_sankey["DestinationPort"].apply(group_port)
            else:
                df_sankey[temp_col_name] = "N/A"
        elif dim == "Len_Group":
            if "Len" in df_sankey.columns and not df_sankey["Len"].isna().all():
                 df_sankey[temp_col_name] = df_sankey["Len"].apply(group_length)
            elif "Length" in df_sankey.columns:
                 df_sankey[temp_col_name] = df_sankey["Length"].apply(group_length)
            else:
                df_sankey[temp_col_name] = "N/A"
        elif dim in df_sankey.columns:
            df_sankey[temp_col_name] = df_sankey[dim].astype(str).fillna("N/A")
        else:
            logging.error(f"Sankey dimension '{dim}' not found or derivable from global_df columns: {global_df.columns.tolist()}")
            return jsonify({"nodes": [], "links": [], "error": f"Dimension '{dim}' not found or could not be derived"}), 400
        temp_dim_cols.append(temp_col_name)

    nodes_map = {} 
    nodes_list = []
    links_list = []

    for i in range(len(temp_dim_cols) - 1):
        source_dim_original_name = dimensions[i]
        target_dim_original_name = dimensions[i+1]
        
        source_data_col = temp_dim_cols[i]
        target_data_col = temp_dim_cols[i+1]

        # Determine the prefix for node display names
        def get_display_prefix(original_dim_name):
            if original_dim_name == "SourceClassification":
                return "Source"
            elif original_dim_name == "DestinationClassification":
                return "Destination"
            # For grouped ports/length, you might want a shorter prefix too
            elif original_dim_name == "SourcePort_Group":
                return "SrcPortGrp"
            elif original_dim_name == "DestinationPort_Group":
                return "DstPortGrp"
            elif original_dim_name == "Len_Group":
                return "LenGrp"
            return original_dim_name # Default to the original dimension name

        source_display_prefix = get_display_prefix(source_dim_original_name)
        target_display_prefix = get_display_prefix(target_dim_original_name)

        current_source_prefixed_col = f"{source_data_col}_prefixed_sankey_node_name"
        current_target_prefixed_col = f"{target_data_col}_prefixed_sankey_node_name"

        df_sankey[current_source_prefixed_col] = source_display_prefix + ": " + df_sankey[source_data_col].astype(str)
        df_sankey[current_target_prefixed_col] = target_display_prefix + ": " + df_sankey[target_data_col].astype(str)
        
        grouped = df_sankey.groupby([current_source_prefixed_col, current_target_prefixed_col]).size().reset_index(name='value')

        for _, row in grouped.iterrows():
            source_name = str(row[current_source_prefixed_col])
            target_name = str(row[current_target_prefixed_col])
            value = int(row['value'])

            if source_name not in nodes_map:
                nodes_map[source_name] = len(nodes_list)
                nodes_list.append({"name": source_name})
            if target_name not in nodes_map:
                nodes_map[target_name] = len(nodes_list)
                nodes_list.append({"name": target_name})
            
            links_list.append({
                "source": nodes_map[source_name],
                "target": nodes_map[target_name],
                "value": value
            })
    
    for idx, node_obj in enumerate(nodes_list):
        node_obj["node"] = idx 

    return jsonify({"nodes": nodes_list, "links": links_list})

@app.route('/process_csv', methods=['POST'])
def process_csv_endpoint():
    global global_df, global_start_time, global_end_time, global_duration_seconds
    global attack_detail_map_cache, attack_pairs_for_anomaly_cache, attacking_sources_cache

    try:
        data = request.get_json()
        if not data or "csv_text" not in data:
            logging.warning("Process CSV request missing 'csv_text'.")
            return jsonify({"error": "No CSV data provided."}), 400

        csv_text = data.get("csv_text", "")
        if not csv_text.strip():
            logging.warning("Process CSV request received empty 'csv_text'.")
            return jsonify({"error": "CSV data is empty."}), 400

        df = process_csv_to_df(csv_text) # This df MUST have 'Occurrences'

        # === Verify 'Occurrences' column after process_csv_to_df ===
        if 'Occurrences' in df.columns:
            logging.info(f"process_csv_to_df returned df with 'Occurrences'. Head: \n{df[['Source', 'Time', 'Occurrences']].head().to_string()}")
            logging.info(f"Data type of 'Occurrences': {df['Occurrences'].dtype}")
            # Ensure it's numeric; process_csv_to_df should handle this, but this is a safeguard.
            df['Occurrences'] = pd.to_numeric(df['Occurrences'], errors='coerce').fillna(1).astype(int)
        else:
            logging.error("'Occurrences' column is MISSING from df after process_csv_to_df. This is a critical issue. Adding default.")
            df['Occurrences'] = 1 # Add default if missing, though the root cause should be fixed.
        # === End 'Occurrences' verification ===

        global_start_time = None
        global_end_time = None
        global_duration_seconds = None

        if "Time" in df.columns and pd.api.types.is_datetime64_any_dtype(df["Time"]):
            valid_times = df["Time"].dropna()
            if not valid_times.empty:
                min_time = valid_times.min()
                max_time = valid_times.max()
                global_start_time = min_time.isoformat()
                global_end_time = max_time.isoformat()
                global_duration_seconds = (max_time - min_time).total_seconds()
                logging.info(f"Time info calculated: Start='{global_start_time}', End='{global_end_time}', Duration={global_duration_seconds}s")

                logging.info(f"Reloading attack data with time filters: global_start_time='{global_start_time}', global_end_time='{global_end_time}'")
                attack_detail_map_cache, attack_pairs_for_anomaly_cache, attacking_sources_cache = load_attack_data(
                    start_time_filter_str=global_start_time,
                    end_time_filter_str=global_end_time
                )
                logging.info(f"load_attack_data returned. Attacking sources cache size: {len(attacking_sources_cache)}")
                if len(attacking_sources_cache) < 20 and len(attacking_sources_cache) > 0 :
                    logging.info(f"Attacking sources in cache: {list(attacking_sources_cache)[:20]}")

            else:
                logging.warning("Time column contains only NaT values. Attack data will not be time-filtered.")
                attack_detail_map_cache, attack_pairs_for_anomaly_cache, attacking_sources_cache = load_attack_data()
        else:
            logging.warning("Time column missing or not datetime. Attack data will not be time-filtered.")
            attack_detail_map_cache, attack_pairs_for_anomaly_cache, attacking_sources_cache = load_attack_data()

        if not df.empty:
            attack_keys = list(zip(df["Source"].astype(str), df["Destination"].astype(str)))
            df["AttackType"] = pd.Series(attack_keys, index=df.index).map(attack_detail_map_cache).fillna("N/A").astype('category')

            df["Anomaly"] = pd.Series(
                np.where(df["Source"].isin(list(attacking_sources_cache)), "anomaly", "normal"),
                index=df.index
            ).astype('category')
            
            logging.info(f"Row-level Anomaly assignment counts: \n{df['Anomaly'].value_counts().to_string()}")
            anomalous_rows_sample = df[df['Anomaly'] == 'anomaly']
            if not anomalous_rows_sample.empty:
                logging.info(f"Sample of rows marked as anomalous (first 3): \n{anomalous_rows_sample[['Source', 'Destination', 'Time', 'Occurrences', 'Anomaly']].head(3).to_string()}")
            else:
                logging.info("No rows were marked as 'anomaly'.")

            if "ClusterID" in df.columns and df["ClusterID"].nunique(dropna=False) > 0:
                df["ClusterAnomaly"] = df.groupby("ClusterID")["Anomaly"].transform(
                    lambda s: "anomaly" if (s == "anomaly").any() else "normal"
                ).astype('category')
                logging.info(f"Cluster-level Anomaly assignment counts: \n{df['ClusterAnomaly'].value_counts().to_string()}")
            else:
                df["ClusterAnomaly"] = pd.Series(["normal"]*len(df) if not df.empty else None, dtype='category', index=df.index)
        else:
            df["AttackType"] = pd.Series(dtype='category')
            df["Anomaly"] = pd.Series(dtype='category')
            df["ClusterAnomaly"] = pd.Series(dtype='category')

        # Define expected columns (ensure 'Occurrences' is included if it's now standard)
        expected_cols = [
            "Source", "Destination", "Payload", "SourcePort", "DestinationPort", "Flags",
            "Seq", "Ack", "Win", "PayloadLength", "TSval", "TSecr", "Protocol", "Length", "Time", # Note: 'Len' was replaced by 'PayloadLength'
            "SourceClassification", "DestinationClassification", "ClusterID",
            "ConnectionID", "BurstID", "NodeWeight", "Occurrences", # Added Occurrences
            "ClusterEntropy", "Anomaly", "ClusterAnomaly", "AttackType",
            "IsSYN", "IsRST", "IsACK", "IsPSH", "InterArrivalTime", "BytesPerSecond"
        ]
        # IsRetransmission is conditional in process_csv_to_df, handle similarly
        if "IsRetransmission" in df.columns:
            if "IsRetransmission" not in expected_cols:
                 expected_cols.append("IsRetransmission")
        # Note: 'Len' from original payload parsing is replaced by 'PayloadLength' from Direct_PayloadLength
        # If your app still uses a column named 'Len' specifically, ensure it's handled or renamed.


        for col in expected_cols:
            if col not in df.columns:
                logging.warning(f"Expected column '{col}' not found in DataFrame after processing. Adding with default.")
                if col in ["SourcePort", "DestinationPort", "Seq", "Ack", "Win", "PayloadLength", "TSval", "TSecr", "Length", "InterArrivalTime", "BytesPerSecond", "NodeWeight", "ClusterEntropy", "Occurrences"]:
                    df[col] = 0 # Default for numeric, Occurrences defaults to 0 if missing (though should be 1 min)
                elif col in ["Protocol", "Flags", "SourceClassification", "DestinationClassification", "ClusterID", "Anomaly", "ClusterAnomaly", "AttackType"]:
                    df[col] = pd.Series(dtype='category', index=df.index).fillna("N/A")
                elif col == "Time":
                    df[col] = pd.NaT
                else:
                    df[col] = "" # Default for string columns

        global_df = df # Assign the fully processed df to global_df
        
        logging.info(f"CSV fully processed. global_df populated. Shape: {global_df.shape}")
        logging.info(f"global_df columns: {global_df.columns.tolist()}")
        logging.info(f"Data types of global_df: \n{global_df.dtypes.to_string()}")
        if "ClusterID" in global_df.columns:
            logging.info(f"Unique ClusterIDs in global_df: {global_df['ClusterID'].nunique(dropna=False)}")
        if "Anomaly" in global_df.columns:
            logging.info(f"Anomaly counts in global_df: \n{global_df['Anomaly'].value_counts(dropna=False).to_string()}")
        if "ClusterAnomaly" in global_df.columns:
            logging.info(f"ClusterAnomaly counts in global_df: \n{global_df['ClusterAnomaly'].value_counts(dropna=False).to_string()}")
        if "Occurrences" in global_df.columns:
            logging.info(f"Occurrences summary in global_df: \n{global_df['Occurrences'].describe().to_string()}")
            logging.info(f"Top 5 Occurrences values: \n{global_df['Occurrences'].value_counts().nlargest(5).to_string()}")


        try:
            logging.info(f"Final DataFrame memory usage: {global_df.memory_usage(deep=True).sum() / (1024*1024):.2f} MB")
        except Exception:
            logging.info("Could not retrieve exact DataFrame memory usage.")

        return jsonify({"message": f"CSV processed successfully. {len(global_df)} aggregated rows loaded (representing more original packets)."}), 200

    except ValueError as ve:
        logging.error(f"Value Error during CSV processing: {ve}", exc_info=True)
        global_df, global_start_time, global_end_time, global_duration_seconds = None, None, None, None
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        logging.exception("Unexpected error processing CSV")
        global_df, global_start_time, global_end_time, global_duration_seconds = None, None, None, None
        return jsonify({"error": "An unexpected server error occurred during CSV processing."}), 500
    
@app.route('/download_csv', methods=['GET'])
def download_csv():
    global global_df
    if global_df is None:
        return jsonify({"error": "No processed data available."}), 400
    csv_io = StringIO()
    global_df.to_csv(csv_io, index=False, quoting=csv.QUOTE_MINIMAL)
    csv_io.seek(0)
    return Response(csv_io.getvalue(), 
                    mimetype='text/csv', 
                    headers={'Content-Disposition': 'attachment;filename=processed.csv'})

@app.route('/')
def serve_index():
    return send_from_directory('../frontend', 'MalscapeDev.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('../frontend', path)


@app.route('/protocol_percentages', methods=['GET'])
def protocol_percentages():
    logging.info("--- /protocol_percentages ROUTE ACCESSED ---")
    print("--- /protocol_percentages ROUTE ACCESSED (print) ---")
    global global_df
    if global_df is None:
        logging.warning("/protocol_percentages: global_df is None")
        return jsonify({})

    df = global_df.copy()

    if 'Protocol' not in df.columns:
        logging.warning("/protocol_percentages: 'Protocol' column not found in DataFrame.")
        return jsonify({})

    df['Protocol'] = df['Protocol'].astype(str).fillna('').str.strip()
    
    if 'processCount' in df.columns:
        df['processCount'] = pd.to_numeric(df['processCount'], errors='coerce').fillna(1)
        protocol_counts = df.groupby('Protocol')['processCount'].sum()
    else:
        protocol_counts = df.groupby('Protocol').size()
        
    total = protocol_counts.sum()
    
    if total == 0:
        logging.warning("/protocol_percentages: total protocol count is 0 after grouping.")
        return jsonify({})
        
    percentages = {
        proto: round((count / total) * 100, 5)
        for proto, count in protocol_counts.items() 
        if proto # Ensure protocol name is not empty
    }
    
    logging.info(f"/protocol_percentages: returning percentages: {percentages}")
    return jsonify(percentages)

@app.route('/time_info', methods=['GET'])
def get_time_info():
    """Returns the calculated start time, end time, and duration."""
    # Check if globals were successfully populated
    if global_df is None or global_start_time is None or global_end_time is None or global_duration_seconds is None:
        if global_df is None:
             return jsonify({"error": "No data has been processed yet."}), 404
        else:
             return jsonify({"error": "Time information could not be determined from the data."}), 404

    return jsonify({
        "start_time": global_start_time,
        "end_time": global_end_time,
        "duration_seconds": global_duration_seconds
    })

@app.route('/get_edge_table', methods=['GET'])
def get_edge_table():
    global global_df
    if global_df is None:
        return "<p>No data available.</p>"

    source = request.args.get("source")
    destination = request.args.get("destination")
    protocol = request.args.get("protocol")

    try:
        page = int(request.args.get("page", 1))
    except:
        page = 1
    try:
        page_size = int(request.args.get("page_size", 50))
    except:
        page_size = 50

    df_filtered = global_df[
        (global_df["Source"] == source) & 
        (global_df["Destination"] == destination) & 
        (global_df["Protocol"] == protocol)
    ]

    total = len(df_filtered)
    start = (page - 1) * page_size
    end = start + page_size
    rows = df_filtered.iloc[start:end].replace({np.nan: None}).to_dict(orient="records")

    if not rows:
        return "<p>No rows found for this edge.</p>"

    columns = list(rows[0].keys())
    html = "<table style='width:100%; border-collapse: collapse; border:1px solid #ddd;'>"
    html += "<thead><tr>"
    for col in columns:
        html += f"<th style='padding:8px; border:1px solid #ddd; text-align:left;'>{col}</th>"
    html += "</tr></thead><tbody>"
    for row in rows:
        html += "<tr>"
        for col in columns:
            val = row[col] if row[col] is not None else ""
            html += f"<td style='padding:8px; border:1px solid #ddd;'>{val}</td>"
        html += "</tr>"
    html += "</tbody></table>"
    html += f"<p id='table-summary' data-total='{total}'>Showing rows {start + 1} to {min(end, total)} of {total}.</p>"
    return html

@app.route('/get_multi_edge_table', methods=['POST'])
def get_multi_edge_table():
    global global_df
    if global_df is None:
        return "<p>No data available.</p>"

    try:
        data = request.get_json()
        edges = data.get("edges", [])
        page = int(data.get("page", 1))
        page_size = int(data.get("page_size", 50))
    except Exception as e:
        return f"<p>Error parsing request: {str(e)}</p>"

    if not edges:
        return "<p>No edges selected.</p>"

    mask = False
    for edge in edges:
        try:
            source = edge["source"]
            destination = edge["destination"]
            protocol = edge["protocol"]
            condition = (
                (global_df["Source"] == source) &
                (global_df["Destination"] == destination) &
                (global_df["Protocol"] == protocol)
            )
            mask |= condition
        except KeyError:
            continue  # skip malformed edge dict

    filtered_df = global_df[mask]
    total = len(filtered_df)
    start = (page - 1) * page_size
    end = start + page_size
    rows = filtered_df.iloc[start:end].replace({np.nan: None}).to_dict(orient="records")

    if not rows:
        return "<p>No rows found for selected edges.</p>"

    columns = list(rows[0].keys())
    html = "<table style='width:100%; border-collapse: collapse; border:1px solid #ddd;'>"
    html += "<thead><tr>"
    for col in columns:
        html += f"<th style='padding:8px; border:1px solid #ddd; text-align:left;'>{col}</th>"
    html += "</tr></thead><tbody>"
    for row in rows:
        html += "<tr>"
        for col in columns:
            val = row[col] if row[col] is not None else ""
            html += f"<td style='padding:8px; border:1px solid #ddd;'>{val}</td>"
        html += "</tr>"
    html += "</tbody></table>"
    html += f"<p id='table-summary' data-total='{total}'>Showing rows {start + 1} to {min(end, total)} of {total}.</p>"
    return html

def convert_nan_to_none(obj):
    """
    Recursively converts any np.nan found in dicts or lists to None.
    """
    if isinstance(obj, dict):
        return {k: convert_nan_to_none(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_nan_to_none(item) for item in obj]
    elif isinstance(obj, float) and np.isnan(obj):
        return None
    else:
        return obj

# Main CLI function to process a CSV file from the command line and save the output
def main_cli(cli_args=None):
    parser = argparse.ArgumentParser(
        description="Process CSV files for network traffic analysis (CLI mode)."
    )

    args = parser.parse_args(cli_args)

    try:
        with open(args.input_file, 'r') as f:
            csv_text = f.read()
        logging.info(f"CLI: Successfully read input file: {args.input_file}")
    except FileNotFoundError:
        logging.error(f"CLI Error: Input file '{args.input_file}' not found.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"CLI Error: Could not read input file '{args.input_file}': {e}")
        sys.exit(1)

    try:
        # The process_csv function uses the global attack_detail_map_cache
        # Ensure it's loaded as expected, or pass the path if you made load_attack_data more flexible
        logging.info("CLI: Starting CSV processing...")
        processed_csv_text = process_csv(csv_text) # process_csv returns the CSV string
        logging.info("CLI: CSV processing complete.")
    except Exception as e:
        logging.error(f"CLI Error: Error during CSV processing: {e}")
        sys.exit(1)

    try:
        with open(args.output_file, 'w') as f:
            f.write(processed_csv_text)
        # Changed to logging.info for success, as it's not an error.
        logging.info(f"CLI: Processed CSV saved to {args.output_file}")
    except Exception as e:
        logging.error(f"CLI Error: Could not save output file '{args.output_file}': {e}")
        sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1].lower() == 'cli':
        # CLI mode: python app.py cli <input_file> -o <output_file>
        cli_arguments = sys.argv[2:] 
        main_cli(cli_arguments)
    else:
        # Server mode: python app.py
        port = int(os.environ.get("PORT", 5000))
        logging.info(f"Starting Flask server on host 0.0.0.0 port {port}")
        app.run(debug=True, host='0.0.0.0', port=port)