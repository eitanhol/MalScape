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

import cProfile
import pstats
import io

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
    """
    Loads attack data from a CSV file.

    Args:
        filename (str): The name of the CSV file (e.g., "GroundTruth.csv")
                        expected to be in the same directory as this script.

    Returns:
        tuple[dict, set]: A tuple containing:
            - attack_details (dict): A dictionary mapping (source_ip, dest_ip) to event_type.
            - attack_pairs (set): A set of (source_ip, dest_ip) tuples and their reverse
                                  for quick bi-directional anomaly lookup.
    """
    attack_details = {}
    attack_pairs = set()
    
    # Construct path relative to the current script's directory (app.py)
    script_dir = os.path.dirname(os.path.abspath(__file__)) # Gets the directory of app.py
    path = os.path.join(script_dir, filename) # Joins with the filename
    
    # Use logging.INFO for these messages so they appear if your Heroku logging level is INFO or DEBUG
    logging.info(f"Attempting to load attack data from: {path}")

    if os.path.exists(path):
        try:
            # Ensure IPs are read as strings and handle potential NaN before stripping
            gt = pd.read_csv(path, dtype=str, keep_default_na=False) # keep_default_na=False treats empty strings as "" not NaN

            required_columns = ["Event Type", "Source IP", "Destination IP"]
            missing_columns = [col for col in required_columns if col not in gt.columns]

            if missing_columns:
                logging.error(f"File '{path}' is missing required columns: {', '.join(missing_columns)}")
                return {}, set() # Return empty if critical columns are missing

            for index, row in gt.iterrows():
                # Strip whitespace and handle empty strings explicitly after reading as str
                s = str(row["Source IP"]).strip()
                d = str(row["Destination IP"]).strip()
                event_type = str(row["Event Type"]).strip()

                if s and d and event_type: # Ensure all are non-empty strings after stripping
                    attack_details[(s, d)] = event_type
                    attack_pairs.add((s, d))
                    attack_pairs.add((d, s)) # For bi-directional check
                # else: # Optional: log if a row has missing crucial data after stripping
                #     logging.debug(f"Skipping row {index} in '{path}' due to missing Source IP, Destination IP, or Event Type after stripping.")

            logging.info(f"Successfully loaded {len(attack_details)} unique attack details and {len(attack_pairs)} attack pairs (bi-directional) from '{path}'.")
        except pd.errors.EmptyDataError:
            logging.error(f"File '{path}' is empty.")
            return {}, set()
        except Exception as e:
            logging.error(f"Error reading or processing file '{path}': {e}", exc_info=True) # exc_info=True logs the traceback
            return {}, set()
    else:
        logging.warning(f"Attack data file not found at '{path}'. Anomaly detection will be based on an empty set of known attacks.")
    
    return attack_details, attack_pairs

attack_detail_map_cache, attack_pairs_for_anomaly_cache = load_attack_data()


# Compute the entropy of a given pandas Series using its value distribution
def compute_entropy(series):
    counts = series.value_counts()
    p = counts / counts.sum()
    return -np.sum(p * np.log(p))

def process_csv_to_df(csv_text):
    """
    Processes raw CSV text into a pandas DataFrame with computed features.
    # ... (rest of the docstring) ...
    """
    df = pd.read_csv(StringIO(csv_text), dtype=str)
    logging.info(f"Initial DataFrame shape after CSV load: {df.shape}")
    if not all(col in df.columns for col in ["Source", "Destination"]):
        error_msg = "Missing required column: Source or Destination"
        logging.error(error_msg)
        raise ValueError(error_msg)

    processed_cols_subset = ["SourceClassification", "DestinationClassification",
                             "ClusterID", "ConnectionID", "ClusterAnomaly", "AttackType"]
    if all(col in df.columns for col in processed_cols_subset):
        logging.info("DataFrame appears to be already processed. Skipping reprocessing.")
        return df

    if "Info" in df.columns and "Payload" not in df.columns:
        df.rename(columns={"Info": "Payload"}, inplace=True)

    if "Payload" in df.columns:
        df["Payload"] = df["Payload"].fillna("").astype(str).str.replace(',', '/', regex=False)
        extracted = parse_payload_vectorized(df["Payload"])
        df = pd.concat([df, extracted], axis=1)

        if "Flags" in df.columns:
            flags_str = df["Flags"].fillna("").astype(str)
            df["IsSYN"] = flags_str.str.contains("SYN", na=False).astype(int)
            df["IsRST"] = flags_str.str.contains("RST", na=False).astype(int)
            df["IsACK"] = flags_str.str.contains("ACK", na=False).astype(int)
            df["IsPSH"] = flags_str.str.contains("PSH", na=False).astype(int)
            if 'isRetransmissionOnly' in request.get_json() if request else False:
                 df["IsRetransmission"] = 0

    df['Source'] = df['Source'].fillna('Unknown_IP').astype(str).str.strip()
    df['Destination'] = df['Destination'].fillna('Unknown_IP').astype(str).str.strip()
    logging.info(f"DataFrame shape after IP fillna/astype/strip: {df.shape}")


    connection_counts = df.groupby(["Source", "Destination"])["Source"].transform("count")
    if not connection_counts.empty and connection_counts.max() != connection_counts.min():
        node_weights = (connection_counts - connection_counts.min()) / (connection_counts.max() - connection_counts.min())
    elif not connection_counts.empty:
         node_weights = pd.Series(1.0, index=connection_counts.index)
    else:
         node_weights = pd.Series(dtype=float)
    df["NodeWeight"] = node_weights.reindex(df.index).fillna(0.5)

    df["SourceClassification"] = df["Source"].apply(classify_ip_vector)
    df["DestinationClassification"] = df["Destination"].apply(classify_ip_vector)

    df["ConnectionID"] = (df["Source"] + ":" + df["SourcePort"].fillna("N/A").astype(str) + "-" +
                          df["Destination"] + ":" + df["DestinationPort"].fillna("N/A").astype(str))

    if "Time" in df.columns:
        df["Time"] = pd.to_datetime(df["Time"], errors='coerce')
    else:
        logging.warning("Time column missing. Timing features will be unavailable.")
        df['Time'] = pd.NaT

    numeric_cols = ["Length", "Seq", "Ack", "Win", "Len", "TSval", "TSecr"]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        else:
            df[col] = np.nan

    if pd.api.types.is_datetime64_any_dtype(df["Time"]):
        df = df.sort_values(by=["ConnectionID", "Time"])
        df["InterArrivalTime"] = df.groupby("ConnectionID")["Time"].diff().dt.total_seconds()
        df["InterArrivalTime"] = df["InterArrivalTime"].fillna(0)
    else:
        df["InterArrivalTime"] = 0.0

    df["Length"] = pd.to_numeric(df["Length"], errors='coerce').fillna(0) # Keep this line
    df["BytesPerSecond"] = df.apply(lambda row: row["Length"] / row["InterArrivalTime"] if row["InterArrivalTime"] and row["InterArrivalTime"] > 0 else 0, axis=1)
    df["BytesPerSecond"] = df["BytesPerSecond"].replace([np.inf, -np.inf], 0)

    df["PayloadLength"] = df["Len"].fillna(0)

    if "InterArrivalTime" in df.columns:
         df["BurstID"] = df.groupby("ConnectionID")["InterArrivalTime"].transform(lambda x: (x.fillna(0) >= 0.01).cumsum())
    else:
         df["BurstID"] = 0

    logging.info("Starting ClusterID computation...")
    cluster_time_start = pd.Timestamp.now()
    if not df.empty:
        try:
            node_cluster = compute_clusters(df, resolution=2.5)
            df["ClusterID"] = df["Source"].astype(str).apply(lambda x: str(node_cluster.get(x, 'N/A')))
        except Exception as e:
             logging.error(f"Error during initial clustering: {e}. Assigning 'N/A' to ClusterID.")
             df["ClusterID"] = 'N/A'
    else:
        df["ClusterID"] = 'N/A'
    logging.info(f"ClusterID computation took: {pd.Timestamp.now() - cluster_time_start}")
    logging.info(f"Number of unique ClusterIDs: {df['ClusterID'].nunique(dropna=False)}")
    logging.info(f"ClusterID value counts (top 5): \n{df['ClusterID'].value_counts(dropna=False).nlargest(5)}")


    cluster_entropy = {}
    if not df.empty and "ClusterID" in df.columns:
        for cluster, group in df.groupby("ClusterID"):
            if cluster == 'N/A': continue
            ent_protocol, ent_srcport, ent_dstport = 0, 0, 0
            if "Protocol" in group.columns and not group["Protocol"].dropna().empty:
                ent_protocol = compute_entropy(group["Protocol"].dropna())
            if "SourcePort" in group.columns and not group["SourcePort"].dropna().empty:
                ent_srcport = compute_entropy(group["SourcePort"].dropna())
            if "DestinationPort" in group.columns and not group["DestinationPort"].dropna().empty:
                ent_dstport = compute_entropy(group["DestinationPort"].dropna())
            valid_entropies = [e for e in [ent_protocol, ent_srcport, ent_dstport] if e > 0]
            cluster_entropy[cluster] = np.mean(valid_entropies) if valid_entropies else 0
    df["ClusterEntropy"] = df["ClusterID"].map(cluster_entropy).fillna(0)

    logging.info(f"DataFrame shape before Anomaly calculation: {df.shape}")
    logging.info(f"Source dtypes: {df['Source'].dtype}, Destination dtypes: {df['Destination'].dtype}")

    df["AttackType"] = df.apply(
        lambda r: attack_detail_map_cache.get((r["Source"], r["Destination"]), "N/A"),
        axis=1
    )
    df["Anomaly"] = df.apply(
        lambda r: "anomaly" if (r["Source"] != r["Destination"]) and \
                              ((r["Source"], r["Destination"]) in attack_pairs_for_anomaly_cache) else "normal",
        axis=1
    )
    anomaly_counts = df["Anomaly"].value_counts(dropna=False)
    logging.info(f"Anomaly column value counts: \n{anomaly_counts}")
    if 'anomaly' not in anomaly_counts:
        logging.warning("No rows were marked as 'anomaly'. Check GroundTruth data and IP matching.")

    if not df.empty and "ClusterID" in df.columns and "Anomaly" in df.columns:
        logging.info("Calculating ClusterAnomaly...")
        df["ClusterAnomaly"] = df.groupby("ClusterID")["Anomaly"].transform(
            lambda s: "anomaly" if (s == "anomaly").any() else "normal"
        )
        cluster_anomaly_counts = df["ClusterAnomaly"].value_counts(dropna=False)
        logging.info(f"ClusterAnomaly column value counts: \n{cluster_anomaly_counts}")
        if 'anomaly' not in cluster_anomaly_counts and 'anomaly' in anomaly_counts :
             logging.warning("Individual anomalies exist, but no ClusterAnomaly was marked. Check ClusterID grouping with anomalous rows.")
    else:
        df["ClusterAnomaly"] = "normal"
        logging.info("DataFrame empty or ClusterID/Anomaly column missing before ClusterAnomaly. Defaulted to 'normal'.")

    expected_cols = ["Source", "Destination", "Payload", "SourcePort", "DestinationPort", "Flags",
                     "Seq", "Ack", "Win", "Len", "TSval", "TSecr", "Protocol", "Length", "Time",
                     "SourceClassification", "DestinationClassification", "ClusterID",
                     "ConnectionID", "BurstID", "NodeWeight",
                     "ClusterEntropy", "Anomaly", "ClusterAnomaly", "AttackType",
                     "IsSYN", "IsRST", "IsACK", "IsPSH", "InterArrivalTime", "BytesPerSecond", "PayloadLength"]
    if "IsRetransmission" in df.columns:
        expected_cols.append("IsRetransmission")

    for col in expected_cols:
        if col not in df.columns:
            df[col] = None

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
CORS(app)  # Enable CORS so that requests from our web app can be processed

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

# Endpoint to return network data for a given cluster
@app.route('/cluster_network', methods=['GET'])
def cluster_network():
    global global_df
    if global_df is None:
        return jsonify({"nodes": [], "edges": []})
    
    cluster_id_param = request.args.get("cluster_id")
    df_cluster = global_df[global_df["ClusterID"] == str(cluster_id_param)]
    
    nodes_data = {} # Use a temporary dict to build node details
    edges_data = {}
    
    # Pre-calculate attack types for edges in the cluster
    edge_attack_types_map = {}
    if "AttackType" in df_cluster.columns:
        for (src, dst, proto), group in df_cluster.groupby(["Source", "Destination", "Protocol"]):
            attack_type_for_edge = "N/A"
            unique_attacks_on_edge = group["AttackType"][group["AttackType"] != "N/A"].unique()
            if len(unique_attacks_on_edge) > 0:
                attack_type_for_edge = unique_attacks_on_edge[0] 
            edge_key_for_lookup = f"{src}|{dst}|{proto}"
            edge_attack_types_map[edge_key_for_lookup] = attack_type_for_edge

    # Pre-calculate involved attack types for nodes in the cluster
    node_involved_attack_types = {}
    if "AttackType" in df_cluster.columns and not df_cluster.empty:
        all_nodes_in_cluster = pd.concat([df_cluster["Source"], df_cluster["Destination"]]).unique()
        for node_ip_str in all_nodes_in_cluster:
            if pd.isna(node_ip_str): # Skip if node_ip is NaN
                continue
            
            # Find rows where this node is either source or destination
            involved_rows = df_cluster[
                (df_cluster["Source"] == node_ip_str) | (df_cluster["Destination"] == node_ip_str)
            ]
            # Get unique attack types from these rows, excluding "N/A"
            unique_node_attacks = involved_rows["AttackType"][involved_rows["AttackType"] != "N/A"].unique()
            
            if len(unique_node_attacks) > 0:
                node_involved_attack_types[node_ip_str] = list(unique_node_attacks)
            else:
                node_involved_attack_types[node_ip_str] = []


    for idx, row in df_cluster.iterrows():
        source_ip = str(row.get("Source", "")).strip()
        destination_ip = str(row.get("Destination", "")).strip()
        protocol = str(row.get("Protocol", "")).strip()

        if not source_ip or not destination_ip or not protocol:
            continue
            
        source_classification = row.get("SourceClassification") or classify_ip_vector(source_ip)
        destination_classification = row.get("DestinationClassification") or classify_ip_vector(destination_ip)
        
        # Add/Update Source Node
        if source_ip not in nodes_data:
            nodes_data[source_ip] = {
                "id": source_ip, 
                "label": source_ip, 
                "Classification": source_classification, 
                "NodeWeight": row.get("NodeWeight", 0), # Typically, NodeWeight might be pre-calculated
                "InvolvedAttackTypes": node_involved_attack_types.get(source_ip, [])
            }
        
        # Add/Update Destination Node
        if destination_ip not in nodes_data:
            nodes_data[destination_ip] = {
                "id": destination_ip, 
                "label": destination_ip, 
                "Classification": destination_classification, 
                "NodeWeight": row.get("NodeWeight", 0), # Or look up based on IP if pre-calculated
                "InvolvedAttackTypes": node_involved_attack_types.get(destination_ip, [])
            }
            
        edge_key = f"{source_ip}|{destination_ip}|{protocol}"
        
        if edge_key not in edges_data:
            current_edge_attack_type = edge_attack_types_map.get(edge_key, "N/A")
            edges_data[edge_key] = {
                "data": {
                    "id": f"edge-{source_ip}-{destination_ip}-{protocol}",
                    "source": source_ip,
                    "target": destination_ip,
                    "Protocol": protocol,
                    "EdgeWeight": 0,
                    "processCount": 0,
                    "AttackType": current_edge_attack_type
                }
            }
        
        try:
            length = float(row.get("Length", 0))
        except (ValueError, TypeError):
            length = 0
            
        edges_data[edge_key]["data"]["EdgeWeight"] += length
        edges_data[edge_key]["data"]["processCount"] += 1

    # Format nodes for Cytoscape
    final_nodes_list = [{"data": node_info} for node_info in nodes_data.values()]

    network_data = {"nodes": final_nodes_list, "edges": list(edges_data.values())}
    return jsonify(convert_nan_to_none(network_data))

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
    global global_df, global_start_time, global_end_time, global_duration_seconds
    
    # --- PROFILING CODE START (for local testing only) ---
    profiler = cProfile.Profile()
    profiler.enable()
    # --- PROFILING CODE END ---

    try:
        data = request.get_json()
        if not data or "csv_text" not in data:
            logging.warning("Process CSV request missing 'csv_text'.")
            return jsonify({"error": "No CSV data provided."}), 400

        csv_text = data.get("csv_text", "")
        if not csv_text.strip():
            logging.warning("Process CSV request received empty 'csv_text'.")
            return jsonify({"error": "CSV data is empty."}), 400

        # This is the function call you want to profile
        df = process_csv_to_df(csv_text) 
        
        if df is None or df.empty:
            logging.error("CSV processing resulted in an empty or None DataFrame.")
            # Clear global vars if df is bad
            global_df = None
            global_start_time = None
            global_end_time = None
            global_duration_seconds = None
            return jsonify({"error": "Failed to process CSV data into a valid structure."}), 500
        
        global_df = df # Assign to global

        # Calculate and set global time variables from the processed df
        if "Time" in global_df.columns and pd.api.types.is_datetime64_any_dtype(global_df["Time"]):
            valid_times = global_df["Time"].dropna()
            if not valid_times.empty:
                global_start_time = valid_times.min().isoformat()
                global_end_time = valid_times.max().isoformat()
                global_duration_seconds = (valid_times.max() - valid_times.min()).total_seconds()
                logging.info(f"Time info calculated: Start={global_start_time}, End={global_end_time}, Duration={global_duration_seconds}s")
            else:
                logging.warning("Time column in DataFrame contains only NaT values. Time info not set.")
                global_start_time, global_end_time, global_duration_seconds = None, None, None
        else:
            logging.warning("Time column missing or not datetime type in DataFrame. Time info not set.")
            global_start_time, global_end_time, global_duration_seconds = None, None, None
        
        logging.info(f"CSV processed successfully. global_df shape: {global_df.shape}")

        # --- PROFILING CODE START (for local testing only) ---
        profiler.disable()
        s = io.StringIO()
        # Sort by cumulative time spent in the function and its sub-functions
        ps = pstats.Stats(profiler, stream=s).sort_stats('cumtime')
        ps.print_stats(30)  # Print the top 30 time-consuming functions
        logging.info(f"\n\nCPROFILE RESULTS FOR /process_csv:\n{s.getvalue()}\n")
        s.close()
        # --- PROFILING CODE END ---

        return jsonify({"message": f"CSV processed successfully. {len(df)} rows loaded."}), 200

    except ValueError as ve: # Catch errors from process_csv_to_df or data validation
        logging.error(f"Value Error during CSV processing: {ve}", exc_info=True)
        global_df = None # Clear potentially inconsistent global state
        global_start_time, global_end_time, global_duration_seconds = None, None, None
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        logging.error(f"Unexpected error processing CSV: {e}", exc_info=True)
        global_df = None # Clear potentially inconsistent global state
        global_start_time, global_end_time, global_duration_seconds = None, None, None
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
    global global_df
    if global_df is None:
        return jsonify({})
    df = global_df.copy()
    df['Protocol'] = df['Protocol'].fillna('').str.strip()
    
    if 'processCount' in df.columns:
        df['processCount'] = pd.to_numeric(df['processCount'], errors='coerce').fillna(1)
        protocol_counts = df.groupby('Protocol')['processCount'].sum()
    else:
        protocol_counts = df.groupby('Protocol').size()
        
    total = protocol_counts.sum()
    percentages = {proto: round(count / total * 100, 5)
                   for proto, count in protocol_counts.items() if proto}
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