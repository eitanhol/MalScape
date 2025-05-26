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
def compute_clusters(df, resolution=2.5):
    G = nx.Graph()
    # Filter out self-connections BEFORE grouping
    df_filtered = df[df["Source"] != df["Destination"]].copy() # Added this line
    if df_filtered.empty: # Handle case where only self-connections exist
        print("Warning: No non-self-connections found for clustering.")
        # Return an empty partition or handle as appropriate
        # For now, let's assign all nodes to a default cluster 'N/A' or '0'
        # This part might need adjustment based on desired behavior for pure self-connection data
        partition = {node: '0' for node in pd.concat([df['Source'], df['Destination']]).unique() if pd.notna(node)}
        return partition

    # Group by Source/Destination using the filtered DataFrame
    groups = df_filtered.groupby(["Source", "Destination"])
    for (src, dst), group in groups:
        # Basic check for non-null src/dst (already implicitly handled by groupby but good practice)
        if pd.notna(src) and pd.notna(dst):
            # No need to check src != dst here anymore, as df_filtered ensures it
            weight = group.shape[0] # Use number of connections as weight
            G.add_edge(src, dst, weight=weight)

    # Handle nodes that might only appear in self-connections (and were filtered out)
    # or nodes that don't form edges in the filtered graph. Assign them a default cluster.
    all_nodes = pd.concat([df['Source'], df['Destination']]).unique()
    partition = {}
    if G.number_of_nodes() > 0: # Only run Louvain if graph has nodes/edges
         # Run Louvain community detection on the graph without self-loops
         try:
             partition = community_louvain.best_partition(G, weight='weight', resolution=resolution)
         except Exception as e:
              print(f"Error during Louvain clustering: {e}. Proceeding without partition.")
              partition = {} # Fallback to empty partition on error

    # Ensure all nodes from the original dataframe get a cluster ID
    # Nodes not in the partition (e.g., isolated nodes or those only in self-loops) get 'N/A'
    final_partition = {
        str(node): str(partition.get(node, 'N/A'))
        for node in all_nodes if pd.notna(node)
    }

    return final_partition

def load_attack_data(filename: str = "GroundTruth.csv") -> tuple[dict, set]:
    attack_details = {}
    attack_pairs = set()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(script_dir, filename)
    logging.info(f"Attempting to load attack data from: {path}")

    if os.path.exists(path):
        try:
            gt_dtypes = {
                "Event Type": "category",
                "C2S ID": "str",
                "Source IP": "str",
                "Source Port(s)": "str",
                "Destination IP": "str",
                "Destination Port(s)": "str",
                "Start Time": "str",
                "Stop Time": "str"
            }
            gt_usecols = ["Event Type", "Source IP", "Destination IP"]
            gt = pd.read_csv(path, dtype=gt_dtypes, usecols=gt_usecols, keep_default_na=False)

            for _, row in gt.iterrows(): # Using _ for index as it's not used
                s = str(row["Source IP"]).strip()
                d = str(row["Destination IP"]).strip()
                event_type = str(row["Event Type"]).strip()

                if s and d and event_type:
                    attack_details[(s, d)] = event_type
                    attack_pairs.add((s, d))
                    attack_pairs.add((d, s))
            logging.info(f"Successfully loaded {len(attack_details)} unique attack details and {len(attack_pairs)} attack pairs (bi-directional) from '{path}'.")
        except pd.errors.EmptyDataError:
            logging.error(f"File '{path}' is empty.")
            return {}, set()
        except Exception as e:
            logging.error(f"Error reading or processing file '{path}': {e}", exc_info=True)
            return {}, set()
    else:
        logging.warning(f"Attack data file not found at '{path}'. Anomaly detection will be based on an empty set of known attacks.")
    return attack_details, attack_pairs

attack_detail_map_cache, attack_pairs_for_anomaly_cache = load_attack_data()


# Compute the entropy of a given pandas Series using its value distribution
def compute_entropy(series):
    counts = series.value_counts()
    probabilities = counts / counts.sum()
    # Filter out zero probabilities before taking the log
    probabilities = probabilities[probabilities > 0]
    if probabilities.empty:
        return 0.0 # Or np.nan, depending on how you want to treat empty/all-zero cases
    return -np.sum(probabilities * np.log(probabilities))

def process_csv_to_df(csv_text):
    uploaded_csv_dtypes = {
        "No.": "str",
        "Time": "str",
        "Source": "str",
        "Destination": "str",
        "Protocol": "category",
        "Length": "str",
        "Payload": "str"
    }
    df = pd.read_csv(StringIO(csv_text), dtype=uploaded_csv_dtypes, keep_default_na=False)
    logging.info(f"Initial DataFrame shape after CSV load: {df.shape}")

    if "Info" in df.columns and "Payload" not in df.columns:
        df.rename(columns={"Info": "Payload"}, inplace=True)

    if "Payload" in df.columns:
        df["Payload"] = df["Payload"].fillna("").astype(str).str.replace(',', '/', regex=False)
        extracted_payload_df = parse_payload_vectorized(df["Payload"]) # Assumes parse_payload_vectorized is defined

        for col in ["SourcePort", "DestinationPort", "Seq", "Ack", "Win", "Len", "TSval", "TSecr"]:
            if col in extracted_payload_df.columns:
                extracted_payload_df[col] = pd.to_numeric(extracted_payload_df[col], errors='coerce')
        if "Flags" in extracted_payload_df.columns:
             extracted_payload_df["Flags"] = extracted_payload_df["Flags"].astype('category')
        df = pd.concat([df, extracted_payload_df], axis=1)

        if "Flags" in df.columns:
            flags_str_series = df["Flags"].astype(str)
            df["IsSYN"] = flags_str_series.str.contains("SYN", na=False, regex=False).astype(np.uint8)
            df["IsRST"] = flags_str_series.str.contains("RST", na=False, regex=False).astype(np.uint8)
            df["IsACK"] = flags_str_series.str.contains("ACK", na=False, regex=False).astype(np.uint8)
            df["IsPSH"] = flags_str_series.str.contains("PSH", na=False, regex=False).astype(np.uint8)
            
            # Check if request object is available and has get_json method
            is_retransmission_only = False
            if request and hasattr(request, 'get_json'):
                request_data = request.get_json(silent=True)
                if request_data and 'isRetransmissionOnly' in request_data:
                    is_retransmission_only = request_data['isRetransmissionOnly']

            if is_retransmission_only:
                 df["IsRetransmission"] = 0 # Default to 0, or your specific logic

    df['Source'] = df['Source'].fillna('Unknown_IP').astype(str).str.strip()
    df['Destination'] = df['Destination'].fillna('Unknown_IP').astype(str).str.strip()

    if not df.empty:
        connection_counts = df.groupby(["Source", "Destination"])["Source"].transform("count")
        if not connection_counts.empty:
            if connection_counts.max() != connection_counts.min():
                node_weights = (connection_counts - connection_counts.min()) / (connection_counts.max() - connection_counts.min())
            else:
                node_weights = pd.Series(0.5, index=connection_counts.index)
        else:
            node_weights = pd.Series(dtype=float)
        df["NodeWeight"] = node_weights.reindex(df.index).fillna(0.5)
    else:
        df["NodeWeight"] = 0.5


    unique_ips = pd.Series(pd.concat([df["Source"], df["Destination"]]).unique())
    # classify_ip_vector must be defined elsewhere
    classified_ips = unique_ips.apply(classify_ip_vector)
    classification_map = dict(zip(unique_ips, classified_ips))
    df["SourceClassification"] = df["Source"].map(classification_map).astype('category')
    df["DestinationClassification"] = df["Destination"].map(classification_map).astype('category')

    # Ensure SourcePort and DestinationPort are strings for concatenation if they were numeric
    df["ConnectionID"] = (df["Source"] + ":" + df["SourcePort"].astype(str) + "-" +
                          df["Destination"] + ":" + df["DestinationPort"].astype(str))
    # df["ConnectionID"] = df["ConnectionID"].astype('category') # Optional optimization

    if "Time" in df.columns:
        df["Time"] = pd.to_datetime(df["Time"], errors='coerce')
    else:
        logging.warning("Time column missing. Timing features will be unavailable.")
        df['Time'] = pd.NaT

    if "Length" in df.columns:
        df["Length"] = pd.to_numeric(df["Length"], errors='coerce').fillna(0)
    else:
        df["Length"] = 0


    if pd.api.types.is_datetime64_any_dtype(df["Time"]) and "ConnectionID" in df.columns:
        df = df.sort_values(by=["ConnectionID", "Time"]) # This is a known potential bottleneck
        df["InterArrivalTime"] = df.groupby("ConnectionID")["Time"].diff().dt.total_seconds()
        df["InterArrivalTime"] = df["InterArrivalTime"].fillna(0)
    else:
        df["InterArrivalTime"] = 0.0

    df["BytesPerSecond"] = df["Length"] / df["InterArrivalTime"]
    df["BytesPerSecond"] = df["BytesPerSecond"].replace([np.inf, -np.inf, np.nan], 0)

    if "Len" in df.columns: # This is 'PayloadLength'
        df["PayloadLength"] = df["Len"].fillna(0)
    else:
        df["PayloadLength"] = 0

    if "InterArrivalTime" in df.columns and "ConnectionID" in df.columns:
         df["BurstID"] = df.groupby("ConnectionID")["InterArrivalTime"].transform(lambda x: (x.fillna(0) >= 0.01).cumsum())
    else:
         df["BurstID"] = 0

    logging.info("Starting ClusterID computation...")
    cluster_time_start = pd.Timestamp.now()
    if not df.empty:
        try:
            # compute_clusters must be defined elsewhere
            node_cluster_map = compute_clusters(df[['Source', 'Destination']], resolution=2.5)
            df["ClusterID"] = df["Source"].astype(str).map(node_cluster_map).fillna('N/A').astype('category')
        except Exception as e:
             logging.error(f"Error during initial clustering: {e}. Assigning 'N/A' to ClusterID.")
             df["ClusterID"] = pd.Series(['N/A'] * len(df), dtype='category')
    else:
        df["ClusterID"] = pd.Series(dtype='category')
    logging.info(f"ClusterID computation took: {pd.Timestamp.now() - cluster_time_start}")

    cluster_entropy = {}
    if not df.empty and "ClusterID" in df.columns and df["ClusterID"].nunique(dropna=False) > 0 :
        # Iterate over actual clusters present in the DataFrame, excluding 'N/A' more explicitly
        for cluster_id_val, group in df[df['ClusterID'] != 'N/A'].groupby("ClusterID", observed=True):
            ent_protocol, ent_srcport, ent_dstport = 0.0, 0.0, 0.0 # Initialize as float
            if "Protocol" in group.columns and not group["Protocol"].dropna().empty:
                ent_protocol = compute_entropy(group["Protocol"].dropna()) # compute_entropy must be defined
            if "SourcePort" in group.columns and not group["SourcePort"].dropna().empty:
                ent_srcport = compute_entropy(group["SourcePort"].dropna())
            if "DestinationPort" in group.columns and not group["DestinationPort"].dropna().empty:
                ent_dstport = compute_entropy(group["DestinationPort"].dropna())
            valid_entropies = [e for e in [ent_protocol, ent_srcport, ent_dstport] if pd.notna(e) and np.isfinite(e) and e > 0]
            cluster_entropy[cluster_id_val] = np.mean(valid_entropies) if valid_entropies else 0.0
    df["ClusterEntropy"] = df["ClusterID"].map(cluster_entropy).fillna(0.0)


    # attack_detail_map_cache and attack_pairs_for_anomaly_cache must be loaded globally
    attack_keys = list(zip(df["Source"], df["Destination"]))
    df["AttackType"] = pd.Series(attack_keys, index=df.index).map(attack_detail_map_cache).fillna("N/A").astype('category')

    s_d_pairs = pd.Series(attack_keys, index=df.index) # Re-use attack_keys Series
    is_in_attack_pairs = s_d_pairs.apply(lambda x: x in attack_pairs_for_anomaly_cache) # This apply can be slow for very large series
    
    conditions = (df["Source"] != df["Destination"]) & is_in_attack_pairs
    df["Anomaly"] = pd.Series(np.where(conditions, "anomaly", "normal"), index=df.index).astype('category')


    if not df.empty and "ClusterID" in df.columns and "Anomaly" in df.columns and df["ClusterID"].nunique(dropna=False) > 0:
        df["ClusterAnomaly"] = df.groupby("ClusterID")["Anomaly"].transform(
            lambda s: "anomaly" if (s == "anomaly").any() else "normal"
        ).astype('category')
    else:
        # Ensure ClusterAnomaly column exists and is of category type even if empty or no clusters
        df["ClusterAnomaly"] = pd.Series(["normal"]*len(df) if not df.empty else None, dtype='category', index=df.index)


    expected_cols = ["Source", "Destination", "Payload", "SourcePort", "DestinationPort", "Flags",
                     "Seq", "Ack", "Win", "Len", "TSval", "TSecr", "Protocol", "Length", "Time",
                     "SourceClassification", "DestinationClassification", "ClusterID",
                     "ConnectionID", "BurstID", "NodeWeight",
                     "ClusterEntropy", "Anomaly", "ClusterAnomaly", "AttackType",
                     "IsSYN", "IsRST", "IsACK", "IsPSH", "InterArrivalTime", "BytesPerSecond", "PayloadLength"]
    if "IsRetransmission" in df.columns: # If IsRetransmission was conditionally added
        if "IsRetransmission" not in expected_cols:
             expected_cols.append("IsRetransmission")


    for col in expected_cols:
        if col not in df.columns:
            # Assign appropriate empty/default types
            if col in ["SourcePort", "DestinationPort", "Seq", "Ack", "Win", "Len", "TSval", "TSecr", "Length", "InterArrivalTime", "BytesPerSecond", "PayloadLength", "NodeWeight", "ClusterEntropy"]:
                df[col] = 0 # Or np.nan if 0 is a meaningful value
            elif col in ["Protocol", "Flags", "SourceClassification", "DestinationClassification", "ClusterID", "Anomaly", "ClusterAnomaly", "AttackType"]:
                df[col] = pd.Series(dtype='category')
            elif col == "Time":
                df[col] = pd.NaT
            else: # String columns
                df[col] = "" # Or None

    try:
        logging.info(f"Final DataFrame memory usage: {df.memory_usage(deep=True).sum() / (1024*1024):.2f} MB")
    except Exception:
        logging.info("Could not retrieve exact DataFrame memory usage.")

    logging.info(f"CSV processing complete. Final DataFrame shape: {df.shape}")
    return df

def process_csv(csv_text):
    df = process_csv_to_df(csv_text)
    out = StringIO()
    df.to_csv(out, index=False, quoting=csv.QUOTE_MINIMAL)
    return out.getvalue()

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

    # ---- START MODIFIED SECTION FOR INITIAL LOGGING ----
    logging.info(f"Entering /filter_and_aggregate. global_df shape: {global_df.shape}")
    # ---- END MODIFIED SECTION FOR INITIAL LOGGING ----

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
    # ---- START ADDED DEBUG LOGS ----
    logging.info(f"Request data for /filter_and_aggregate: {data}")
    # ---- END ADDED DEBUG LOGS ----

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

    if "ClusterEntropy" in df.columns: # Ensure column exists before filtering
        df["ClusterEntropy"] = pd.to_numeric(df["ClusterEntropy"], errors='coerce')
        df = df[(df["ClusterEntropy"] >= entropyMin) & (df["ClusterEntropy"] <= entropyMax)]
    else:
        logging.warning("ClusterEntropy column not found in df for filtering.")


    if isRetransmissionOnly and "IsRetransmission" in df.columns:
        df = df[df["IsRetransmission"] == True] # Boolean comparison

    logging.info(f"df shape after filtering: {df.shape}, for metric: {metric}")
    if df.empty:
        logging.warning(f"DataFrame is empty after applying filters for metric '{metric}'. Returning empty list.")
        return jsonify([])

    agg = pd.Series(dtype=float) # Ensure agg is initialized

    if metric == "count":
        agg = df.groupby("ClusterID").size()
    elif metric == "% SYN packets" and "IsSYN" in df.columns:
        grouped = df.groupby("ClusterID")
        agg = grouped["IsSYN"].sum() / grouped.size().replace(0, 1) * 100
    elif metric == "% RST packets" and "IsRST" in df.columns:
        grouped = df.groupby("ClusterID")
        agg = grouped["IsRST"].sum() / grouped.size().replace(0, 1) * 100
    elif metric == "% ACK packets" and "IsACK" in df.columns:
        grouped = df.groupby("ClusterID")
        agg = grouped["IsACK"].sum() / grouped.size().replace(0, 1) * 100
    elif metric == "% PSH packets" and "IsPSH" in df.columns:
        grouped = df.groupby("ClusterID")
        agg = grouped["IsPSH"].sum() / grouped.size().replace(0, 1) * 100
    elif metric == "Unique Destinations":
        agg = df.groupby("ClusterID")["Destination"].nunique()
    elif metric == "Unique Sources":
        agg = df.groupby("ClusterID")["Source"].nunique()
    elif metric == "Unique IPs":
        agg = df.groupby("ClusterID").apply(
            lambda g: len(set(g["Source"]).union(set(g["Destination"])))
        )
    elif metric == "Payload Size Variance" and "PayloadLength" in df.columns:
        df["PayloadLength"] = pd.to_numeric(df["PayloadLength"], errors="coerce").fillna(0)
        agg = df.groupby("ClusterID")["PayloadLength"].var(ddof=0) # ddof=0 for population variance
    elif metric == "Packets per Second" and "Time" in df.columns:
        df['Time'] = pd.to_datetime(df['Time'], errors='coerce')
        grouped = df.groupby("ClusterID")
        def packets_per_second(g):
            if g["Time"].count() < 2: return 0
            duration = (g["Time"].max() - g["Time"].min()).total_seconds()
            return len(g) / duration if duration > 0 else 0
        agg = grouped.apply(packets_per_second)
    elif metric == "Total Data Sent" and "Length" in df.columns:
        df["Length"] = pd.to_numeric(df["Length"], errors='coerce').fillna(0)
        agg = df.groupby("ClusterID")["Length"].sum()
    elif metric == "Start Time" and "Time" in df.columns:
        df['Time'] = pd.to_datetime(df['Time'], errors='coerce')
        overall_min_time = df['Time'].dropna().min()
        agg_time = df.groupby("ClusterID")["Time"].min()
        if pd.api.types.is_datetime64_any_dtype(overall_min_time) and not agg_time.empty:
            agg = (agg_time - overall_min_time).dt.total_seconds()
        else:
            agg = pd.Series(0, index=agg_time.index, dtype=float)
        agg = agg.fillna(0)
    elif metric == "Duration" and "Time" in df.columns:
        df['Time'] = pd.to_datetime(df['Time'], errors='coerce')
        grouped = df.groupby("ClusterID")["Time"]
        agg = (grouped.max() - grouped.min()).dt.total_seconds()
        agg = agg.fillna(0)
    elif metric == "Average Inter-Arrival Time" and "InterArrivalTime" in df.columns:
        df["InterArrivalTime"] = pd.to_numeric(df["InterArrivalTime"], errors='coerce')
        agg = df.groupby("ClusterID")["InterArrivalTime"].mean()
        agg = agg.fillna(0)
    elif metric in df.columns: # Generic sum for other numeric columns
        df[metric] = pd.to_numeric(df[metric], errors='coerce').fillna(0)
        agg = df.groupby("ClusterID")[metric].sum()
    else:
        logging.warning(f"Metric '{metric}' not found or not supported. Returning zeros.")
        unique_cluster_ids = df["ClusterID"].unique() if not df.empty else []
        agg = pd.Series(0, index=unique_cluster_ids, dtype=float) # Ensure it's a Series

    agg = agg.fillna(0) # Ensure NaNs in final agg are 0 for JSON compatibility

    # ---- START ADDED DEBUG LOGS ----
    logging.info(f"Metric: {metric}, Number of items in agg: {len(agg) if hasattr(agg, '__len__') else 'N/A (not a Series/list)'}")
    if isinstance(agg, pd.Series) and not agg.empty:
        logging.info(f"Aggregated data (agg) head for metric '{metric}': \n{agg.head().to_string()}")
        logging.info(f"Aggregated data (agg) describe for metric '{metric}': \n{agg.describe().to_string()}")
        # Check for non-finite values
        if agg.isnull().any():
            logging.warning(f"Agg for metric '{metric}' contains NaNs: \n{agg[agg.isnull()]}")
        if not np.isfinite(agg).all():
            logging.warning(f"Agg for metric '{metric}' contains non-finite values (inf): \n{agg[~np.isfinite(agg)]}")

    elif not isinstance(agg, pd.Series):
         logging.info(f"Aggregated data (agg) for metric '{metric}' is not a Pandas Series. Type: {type(agg)}, Value (first 200 chars): {str(agg)[:200]}")
    else:
        logging.info(f"Aggregated data (agg) for metric '{metric}' is an empty Series.")
    # ---- END ADDED DEBUG LOGS ----

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

        # ---- START ADDED DEBUG LOG ----
        # Log a few entries to see what values are being prepared
        if len(filtered_pivot) < 3 : # Log first 3 entries
            logging.info(f"Adding to filtered_pivot: cluster={cluster_id_val}, value={value}, anomaly={anomaly_map.get(cluster_id_val, 'normal')}")
        # ---- END ADDED DEBUG LOG ----

        filtered_pivot.append({
            "cluster": str(cluster_id_val), # Ensure cluster_id is string for consistency
            "value": float(value) if pd.notnull(value) and np.isfinite(value) else 0.0, # Ensure value is float and finite
            "clusterAnomaly": anomaly_map.get(str(cluster_id_val), "normal"), # Ensure key is string
            "ClusterAttackTypes": cluster_attack_types_map.get(str(cluster_id_val), []) # Ensure key is string
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
    global global_df # Assuming global_df is populated by your /process_csv endpoint
    if global_df is None or global_df.empty:
        logging.warning("/hierarchical_clusters called but global_df is None or empty.")
        # Return a structure indicating no data, which frontend should handle
        return jsonify({"id": "empty_root_no_data", "dist": 0, "no_tree": True, "error": "No data loaded"}), 200

    resolution = 2.5 # Default resolution
    try:
        resolution_param = request.args.get("resolution")
        if resolution_param is not None:
            resolution = float(resolution_param)
            if resolution <= 0:
                raise ValueError("Resolution must be positive")
            logging.info(f"Using custom resolution for hierarchical_clusters: {resolution}")
    except (TypeError, ValueError) as e:
        logging.warning(f"Invalid resolution parameter in hierarchical_clusters, using default 2.5: {e}")
        resolution = 2.5 # Fallback to default

    try:
        # Ensure Source/Destination are clean strings before re-clustering or anomaly detection
        # This is crucial if data types might have changed or if NaNs are present
        if 'Source' in global_df.columns:
            global_df['Source'] = global_df['Source'].fillna('Unknown_IP').astype(str).str.strip()
        if 'Destination' in global_df.columns:
            global_df['Destination'] = global_df['Destination'].fillna('Unknown_IP').astype(str).str.strip()

        # Re-compute clusters with the current (possibly new) resolution
        node_cluster = compute_clusters(global_df, resolution=resolution)
        global_df["ClusterID"] = global_df["Source"].astype(str).map(node_cluster).fillna('N/A') # Use map for efficiency, ensure it's string

        # Re-calculate ClusterEntropy
        cluster_entropy_map = {} # Use a different variable name to avoid confusion if 'cluster_entropy' is used elsewhere
        if "ClusterID" in global_df.columns and not global_df.empty:
            for cluster_id_val, group in global_df.groupby("ClusterID"):
                if cluster_id_val == 'N/A':
                    continue
                entropies = []
                if "Protocol" in group.columns and not group["Protocol"].dropna().empty:
                    entropies.append(compute_entropy(group["Protocol"].dropna()))
                if "SourcePort" in group.columns and not group["SourcePort"].dropna().empty:
                    entropies.append(compute_entropy(group["SourcePort"].dropna()))
                if "DestinationPort" in group.columns and not group["DestinationPort"].dropna().empty:
                    entropies.append(compute_entropy(group["DestinationPort"].dropna()))
                
                valid_entropies = [e for e in entropies if e > 0 and pd.notna(e) and np.isfinite(e)]
                cluster_entropy_map[cluster_id_val] = np.mean(valid_entropies) if valid_entropies else 0.0
        global_df["ClusterEntropy"] = global_df["ClusterID"].map(cluster_entropy_map).fillna(0.0)

        # Re-apply Anomaly and ClusterAnomaly based on current ClusterIDs and global attack data
        # Assuming attack_detail_map_cache and attack_pairs_for_anomaly_cache are loaded globally
        global_df["AttackType"] = global_df.apply(
            lambda r: attack_detail_map_cache.get((r["Source"], r["Destination"]), "N/A"), axis=1
        )
        global_df["Anomaly"] = global_df.apply(
            lambda r: "anomaly" if (r["Source"] != r["Destination"]) and \
                                  ((r["Source"], r["Destination"]) in attack_pairs_for_anomaly_cache) else "normal",
            axis=1
        )
        if "ClusterID" in global_df.columns and "Anomaly" in global_df.columns and not global_df.empty:
            global_df["ClusterAnomaly"] = global_df.groupby("ClusterID")["Anomaly"].transform(
                lambda s: "anomaly" if (s == "anomaly").any() else "normal"
            )
        else:
            global_df["ClusterAnomaly"] = "normal"

        logging.info(f"Recomputed clusters for hierarchical view. Resolution {resolution}. "
                     f"{global_df['ClusterID'].nunique(dropna=False)} unique clusters. "
                     f"Anomaly counts: \n{global_df.get('Anomaly', pd.Series(dtype=str)).value_counts(dropna=False)}. "
                     f"ClusterAnomaly counts: \n{global_df.get('ClusterAnomaly', pd.Series(dtype=str)).value_counts(dropna=False)}")

    except Exception as e:
        logging.error(f"Error during re-clustering or feature calculation in /hierarchical_clusters: {e}", exc_info=True)
        return jsonify({"id": "error_root", "dist": 0, "error": f"Failed to recluster or recalculate features: {str(e)}", "no_tree": True}), 500

    # Prepare data for SciPy linkage
    # Ensure 'ClusterID' is present and not all 'N/A'
    if 'ClusterID' not in global_df.columns or global_df['ClusterID'].nunique(dropna=False) == 0 or \
       (global_df['ClusterID'].nunique(dropna=False) == 1 and global_df['ClusterID'].unique()[0] == 'N/A'):
        logging.warning("No valid ClusterIDs available for hierarchical clustering stats.")
        return jsonify({"id": "empty_root_no_clusters", "dist": 0, "no_tree": True, "error": "No valid clusters found"}), 200

    stats = (
        global_df[global_df['ClusterID'] != 'N/A'] # Exclude 'N/A' clusters from stats for linkage
        .groupby('ClusterID')
        .agg(
            total_packets=('ClusterID', 'size'),
            avg_entropy=('ClusterEntropy', 'mean') # .mean() will ignore NaNs by default
        )
        .reset_index()
    )
    stats['avg_entropy'] = stats['avg_entropy'].fillna(0.0) # Ensure no NaNs for linkage

    if stats.empty:
        logging.warning("Stats DataFrame is empty after filtering N/A ClusterIDs. Cannot perform hierarchical clustering.")
        return jsonify({"id": "empty_root_no_valid_stats", "dist": 0, "no_tree": True, "error": "No valid clusters for statistics"}), 200

    # Sort stats by ClusterID to ensure consistent node indexing for SciPy
    # Convert ClusterID to numeric for sorting if possible, otherwise sort as string
    try:
        stats['ClusterID_num'] = pd.to_numeric(stats['ClusterID'])
        stats = stats.sort_values('ClusterID_num').reset_index(drop=True)
    except ValueError:
        stats = stats.sort_values('ClusterID').reset_index(drop=True)

    linkage_data = stats[['total_packets', 'avg_entropy']].to_numpy() # Already filled NaNs

    # SciPy linkage requires at least 2 samples
    if linkage_data.shape[0] < 2:
        logging.warning(f"Not enough distinct clusters ({linkage_data.shape[0]}) to perform hierarchical clustering in /hierarchical_clusters.")
        cluster_id_val = "N/A"
        if not stats.empty: # If stats has one row
            cluster_id_val = str(stats.loc[0, 'ClusterID'])

        minimal_tree_response = {
            "id": f"Cluster {cluster_id_val}",
            "cluster_id": cluster_id_val,
            "dist": 0,
            "is_minimal": True, # Flag for the frontend
            "children": [] # Explicitly empty children for single node
        }
        logging.info(f"Returning minimal tree structure: {minimal_tree_response}")
        return jsonify(minimal_tree_response)

    try:
        Z = linkage(linkage_data, method='average') # 'average' is a common linkage method
        # rd=True gives root_node, node_list where root_node is the root of the tree.
        root_node_obj, _ = to_tree(Z, rd=True)
    except Exception as e:
        logging.error(f"Error during SciPy hierarchical clustering (linkage or to_tree): {e}", exc_info=True)
        return jsonify({"id": "error_scipy_tree", "dist": 0, "error": f"Hierarchical clustering failed: {str(e)}", "no_tree": True}), 500

    # Recursive function to convert SciPy tree object to the nested dictionary format
    def node_to_dict(node):
        if node.is_leaf():
            try:
                # node.id is an index into the original linkage_data (which came from the sorted stats DataFrame)
                cluster_id_val = str(stats.loc[node.id, 'ClusterID']) # Ensure string
                return {
                    "id": f"Cluster {cluster_id_val}", # Used by D3 for display/linking, often unique
                    "cluster_id": cluster_id_val,     # The actual ClusterID value
                    "dist": float(node.dist)          # Distance for this leaf (often 0 or its own properties)
                    # "children" is implicitly empty for leaves
                }
            except IndexError as ie:
                logging.error(f"IndexError in node_to_dict for leaf: node.id={node.id}, stats len={len(stats)}. Error: {ie}")
                return {"id": f"ErrorLeaf_{node.id}", "cluster_id": "ERROR_ID", "dist": float(node.dist)}
            except KeyError as ke:
                logging.error(f"KeyError in node_to_dict for leaf: stats columns are {stats.columns}. Error: {ke}")
                return {"id": f"ErrorLeaf_{node.id}", "cluster_id": "ERROR_ID_KEY", "dist": float(node.dist)}
        else:
            # For internal nodes
            left_child = node_to_dict(node.get_left())
            right_child = node_to_dict(node.get_right())
            children_list = []
            if left_child: children_list.append(left_child)
            if right_child: children_list.append(right_child)

            return {
                "id": f"Internal_{node.id}", # Unique ID for the internal node
                "dist": float(node.dist),    # Distance (height) of this merge
                "children": children_list
            }

    tree_dict = node_to_dict(root_node_obj)
    logging.info(f"Hierarchical tree_dict successfully generated. Preview: {str(tree_dict)[:1000]}")
    return jsonify(tree_dict)

@app.route('/louvain_ip_graph_data', methods=['GET'])
def louvain_ip_graph_data():
    global global_df
    if global_df is None or global_df.empty:
        logging.warning("/louvain_ip_graph_data called but global_df is None.")
        return jsonify({"nodes": [], "edges": [], "error": "No data loaded"}), 400

    # Ensure ClusterID is present and correctly typed (it should be from process_csv_to_df)
    if 'ClusterID' not in global_df.columns:
        logging.error("ClusterID column is missing from global_df. Cannot generate IP graph.")
        return jsonify({"nodes": [], "edges": [], "error": "ClusterID not found in processed data."}), 500

    # To get a canonical ClusterID for each IP, we need the map used during process_csv
    # For simplicity, we'll re-derive a node_cluster_map here or assume the one implicitly
    # used by global_df['ClusterID'] (which is source-ip based) is sufficient for node coloring,
    # but for parent grouping, we need a map for *all* unique IPs.

    # Create a fresh node_cluster_map based on the current global_df structure
    # This ensures that if resolution changes, this graph reflects it.
    # Note: The global_df['ClusterID'] is packet-based (from source IP). We need an IP-to-ClusterID map.
    current_resolution = 2.5 # Default, or you could try to get it from a global state if it changes
    # Potentially, you could pass the current resolution from frontend if this endpoint is dynamic

    # Ensure Source and Destination are clean for compute_clusters
    df_for_clustering = global_df[['Source', 'Destination']].copy()
    df_for_clustering['Source'] = df_for_clustering['Source'].astype(str).str.strip()
    df_for_clustering['Destination'] = df_for_clustering['Destination'].astype(str).str.strip()
    ip_to_cluster_map = compute_clusters(df_for_clustering, resolution=current_resolution)

    df_for_graph = global_df.copy()
    df_for_graph['Source'] = df_for_graph['Source'].astype(str).str.strip()
    df_for_graph['Destination'] = df_for_graph['Destination'].astype(str).str.strip()

    nodes_dict = {} # Using dict to ensure unique nodes with their data

    # Aggregate packet count for each IP
    source_packet_counts = df_for_graph.groupby('Source').size()
    dest_packet_counts = df_for_graph.groupby('Destination').size()

    all_ips_involved = pd.concat([df_for_graph['Source'], df_for_graph['Destination']]).unique()

    for ip in all_ips_involved:
        if not ip or pd.isna(ip):
            continue

        cluster_id = ip_to_cluster_map.get(ip, 'N/A') # Get canonical ClusterID for this IP

        # Determine classification (take from first appearance or re-classify)
        classification = "Unknown"
        src_class = df_for_graph.loc[df_for_graph['Source'] == ip, 'SourceClassification'].iloc[0] if not df_for_graph.loc[df_for_graph['Source'] == ip, 'SourceClassification'].empty else None
        dst_class = df_for_graph.loc[df_for_graph['Destination'] == ip, 'DestinationClassification'].iloc[0] if not df_for_graph.loc[df_for_graph['Destination'] == ip, 'DestinationClassification'].empty else None

        if src_class and src_class != "Unknown":
            classification = src_class
        elif dst_class and dst_class != "Unknown":
            classification = dst_class
        else: # If still unknown, re-classify
            classification = classify_ip_vector(ip)


        packet_involvement_count = source_packet_counts.get(ip, 0) + dest_packet_counts.get(ip, 0)

        nodes_dict[ip] = {
            "data": {
                "id": ip,
                "label": ip, # Cytoscape uses 'label' for display by default
                "clusterId": str(cluster_id),
                "classification": classification,
                "packet_count": int(packet_involvement_count) # Total times IP appears as source or dest
            }
        }

    nodes_list = list(nodes_dict.values())

    # Aggregate Edges
    df_for_graph['Length'] = pd.to_numeric(df_for_graph['Length'], errors='coerce').fillna(0)

    # Group by Source, Destination, and include Protocol if you want protocol-specific edges
    # For now, let's aggregate all traffic between two IPs
    edges_df = df_for_graph.groupby(["Source", "Destination"]).agg(
        packet_count=('Time', 'count'), 
        total_length=('Length', 'sum')
    ).reset_index()

    edges_list = []
    for _, row in edges_df.iterrows():
        src = str(row["Source"])
        dst = str(row["Destination"])

        if not src or pd.isna(src) or not dst or pd.isna(dst): # Skip if IPs are invalid
            continue
        if src == dst: # Skip self-loops for this graph type
            continue

        edges_list.append({
            "data": {
                "id": f"edge_{src}_{dst}", # Create a unique edge ID
                "source": src,
                "target": dst,
                "packet_count": int(row["packet_count"]),
                "total_length": float(row["total_length"])
            }
        })

    logging.info(f"/louvain_ip_graph_data: Nodes: {len(nodes_list)}, Edges: {len(edges_list)}")
    return jsonify({"nodes": nodes_list, "edges": edges_list})

# Endpoint to return network data for a given cluster
@app.route('/cluster_network', methods=['GET'])
def cluster_network():
    global global_df
    if global_df is None:
        logging.error("/cluster_network called but global_df is None.")
        return jsonify({"nodes": [], "edges": [], "error": "No data loaded"}), 500 # Send error back

    cluster_id_param = request.args.get("cluster_id")
    logging.info(f"Processing /cluster_network for cluster_id: {cluster_id_param}")

    if not cluster_id_param:
        logging.error("/cluster_network called without cluster_id.")
        return jsonify({"nodes": [], "edges": [], "error": "cluster_id parameter is missing"}), 400

    try:
        # Ensure global_df has necessary columns; provide defaults if not already robustly handled
        # This is more of a safeguard; ideally, process_csv_to_df ensures these.
        for col in ["Source", "Destination", "Protocol", "ClusterID", "NodeWeight", "SourceClassification", "DestinationClassification", "AttackType", "Length"]:
            if col not in global_df.columns:
                logging.warning(f"Column '{col}' missing in global_df. This might cause issues downstream.")
                # Depending on the column, you might initialize it here, e.g., global_df[col] = default_value
                # For now, we'll let it proceed and see if specific cluster data slice fails.

        df_cluster = global_df[global_df["ClusterID"] == str(cluster_id_param)].copy() # Use .copy() to avoid SettingWithCopyWarning
        logging.info(f"df_cluster for {cluster_id_param} shape: {df_cluster.shape}")
        if df_cluster.empty:
            logging.warning(f"df_cluster is empty for cluster_id: {cluster_id_param}. Returning empty network.")
            return jsonify({"nodes": [], "edges": []})

        if 'NodeWeight' not in df_cluster.columns:
            logging.warning(f"NodeWeight column missing in df_cluster for cluster {cluster_id_param}. Defaulting to 0.5 for nodes.")
            df_cluster.loc[:, 'NodeWeight'] = 0.5
        else:
            df_cluster.loc[:, 'NodeWeight'] = pd.to_numeric(df_cluster['NodeWeight'], errors='coerce').fillna(0.5)

        # Ensure key columns are strings for reliable operations
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

            s_count = source_counts.get(ip_val, 0)
            d_count = destination_counts.get(ip_val, 0)
            # How many rows this IP is involved in
            node_packet_counts[ip_val] = len(df_cluster[(df_cluster["Source"] == ip_val) | (df_cluster["Destination"] == ip_val)])
            if node_packet_counts[ip_val] == 0: # Should not happen if ip_val came from all_ips_in_cluster
                logging.warning(f"IP {ip_val} from all_ips_in_cluster resulted in 0 packet count from df_cluster query.")


        nodes_data = {} 
        edges_data = {}

        edge_attack_types_map = {}
        if "AttackType" in df_cluster.columns:
             # Ensure 'AttackType' is string before groupby
            df_cluster.loc[:, "AttackType"] = df_cluster["AttackType"].astype(str)
            for (src, dst, proto), group in df_cluster.groupby(["Source", "Destination", "Protocol"]):
                attack_type_for_edge = "N/A" # Default
                # Filter out "N/A" strings before finding unique attack types
                unique_attacks_on_edge = group["AttackType"][group["AttackType"].str.upper() != "N/A"].unique()
                if len(unique_attacks_on_edge) > 0:
                    attack_type_for_edge = unique_attacks_on_edge[0] 
                edge_key_for_lookup = f"{src}|{dst}|{proto}"
                edge_attack_types_map[edge_key_for_lookup] = attack_type_for_edge


        node_involved_attack_types = {}
        if "AttackType" in df_cluster.columns and not df_cluster.empty:
            for node_ip_str in all_ips_in_cluster: 
                involved_rows = df_cluster[
                    (df_cluster["Source"] == node_ip_str) | (df_cluster["Destination"] == node_ip_str)
                ]
                # Ensure 'AttackType' is string and filter out "N/A" before unique
                unique_node_attacks = involved_rows["AttackType"].astype(str)[involved_rows["AttackType"].str.upper() != "N/A"].unique()
                node_involved_attack_types[node_ip_str] = list(unique_node_attacks) if len(unique_node_attacks) > 0 else []


        for idx, row in df_cluster.iterrows():
            source_ip = row["Source"] # Already str.strip()'d
            destination_ip = row["Destination"] # Already str.strip()'d
            protocol = row["Protocol"] # Already str.strip()'d

            # Basic check for empty strings (should be redundant if handled above but safe)
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
                    "InvolvedAttackTypes": node_involved_attack_types.get(source_ip, [])
                }

            if destination_ip not in nodes_data:
                nodes_data[destination_ip] = {
                    "id": destination_ip, 
                    "label": destination_ip, 
                    "Classification": destination_classification, 
                    "NodeWeight": node_avg_weights.get(destination_ip, 0.5),
                    "packetCount": node_packet_counts.get(destination_ip, 0),
                    "InvolvedAttackTypes": node_involved_attack_types.get(destination_ip, [])
                }

            edge_key = f"{source_ip}|{destination_ip}|{protocol}"
            if edge_key not in edges_data:
                edges_data[edge_key] = {
                    "data": {
                        "id": f"edge-{source_ip}-{destination_ip}-{protocol}", # Ensure unique enough
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
        return jsonify(convert_nan_to_none(network_data))

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

# GroundTruth.csv is automatically read from the same folder.
# Endpoint to process CSV data: parses, processes, and stores in global_df.
@app.route('/process_csv', methods=['POST'])
def process_csv_endpoint():
    """ Endpoint to process uploaded CSV data. """
    global global_df, global_start_time, global_end_time, global_duration_seconds

    try:
        data = request.get_json()
        if not data or "csv_text" not in data:
            logging.warning("Process CSV request missing 'csv_text'.")
            return jsonify({"error": "No CSV data provided."}), 400

        csv_text = data.get("csv_text", "")
        if not csv_text.strip():
            logging.warning("Process CSV request received empty 'csv_text'.")
            return jsonify({"error": "CSV data is empty."}), 400

        df = process_csv_to_df(csv_text)
        global_df = df
        logging.info(f"CSV processed into DataFrame with shape: {global_df.shape}")

        # ---- START ADDED DEBUG LOGS ----
        if global_df is not None and not global_df.empty:
            logging.info(f"global_df populated. Shape: {global_df.shape}")
            logging.info(f"global_df columns: {global_df.columns.tolist()}")
            logging.info(f"dtypes of global_df: \n{global_df.dtypes}") # Corrected log message
            if "ClusterID" in global_df.columns:
                logging.info(f"Unique ClusterIDs in global_df: {global_df['ClusterID'].nunique(dropna=False)}") # Added dropna=False
                logging.info(f"Top 5 ClusterID value counts in global_df: \n{global_df['ClusterID'].value_counts(dropna=False).head()}") # Added dropna=False
            else:
                logging.warning("Column 'ClusterID' not found in global_df.")
            if "Anomaly" in global_df.columns:
                logging.info(f"Anomaly counts in global_df: \n{global_df['Anomaly'].value_counts(dropna=False)}")
            else:
                logging.warning("Column 'Anomaly' not found in global_df.")
            if "ClusterAnomaly" in global_df.columns:
                logging.info(f"ClusterAnomaly counts in global_df: \n{global_df['ClusterAnomaly'].value_counts(dropna=False)}")
            else:
                logging.warning("Column 'ClusterAnomaly' not found in global_df.")
            # Log a sample of the data
            logging.info(f"global_df head (first 3 rows): \n{global_df.head(3).to_string()}")
        else:
            logging.warning("global_df is None or empty after CSV processing.")
        # ---- END ADDED DEBUG LOGS ----

        global_start_time = None
        global_end_time = None
        global_duration_seconds = None

        if "Time" in global_df.columns and pd.api.types.is_datetime64_any_dtype(global_df["Time"]):
            valid_times = global_df["Time"].dropna()
            if not valid_times.empty:
                min_time = valid_times.min()
                max_time = valid_times.max()
                global_start_time = min_time.isoformat()
                global_end_time = max_time.isoformat()
                global_duration_seconds = (max_time - min_time).total_seconds()
                logging.info(f"Time info calculated: Start={global_start_time}, End={global_end_time}, Duration={global_duration_seconds}s")
            else:
                logging.warning("Time column contains only NaT values.")
        else:
            logging.warning("Time column missing, not datetime type, or could not be parsed correctly during processing.")

        return jsonify({"message": f"CSV processed successfully. {len(global_df)} rows loaded."}), 200

    except ValueError as ve:
        logging.error(f"Value Error during CSV processing: {ve}", exc_info=True) # Added exc_info
        global_df, global_start_time, global_end_time, global_duration_seconds = None, None, None, None
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        logging.exception("Unexpected error processing CSV")
        global_df, global_start_time, global_end_time, global_duration_seconds = None, None, None, None
        return jsonify({"error": "An unexpected server error occurred during CSV processing."}), 500
    
# New endpoint for downloading the processed CSV file
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