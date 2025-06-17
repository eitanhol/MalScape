from flask import Flask, request, Response, jsonify, send_from_directory
import csv
import pandas as pd
from ipaddress import ip_address, ip_network # Used for IP classification
from io import StringIO, BytesIO # BytesIO for reading uploaded file
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
import time

# --- Global Variables ---
global_df = None
global_start_time = None
global_end_time = None
global_duration_seconds = None
attack_detail_map_cache = {}
attack_pairs_for_anomaly_cache = set()
attacking_sources_cache = set() # Added to store attacking sources from GroundTruth
global_backend_csv_processing_time_seconds = None # Will now represent Parquet processing time

# Expected columns after all processing in app.py, for final global_df
expected_cols = [
    "Time", "Length", "Protocol", "SourcePort", "DestinationPort", "Source", "Destination", "Flags", "processCount",
    "IsSYN", "IsRST", "IsACK", "IsPSH", "IsFIN",
    "Payload",
    "No.",
    "NodeWeight", "SourceClassification", "DestinationClassification", "ConnectionID",
    "InterArrivalTime", "BytesPerSecond", "PayloadLength",
    "BurstID", "ClusterID", "ClusterEntropy",
    "Anomaly", "ClusterAnomaly", "AttackType",
    "SourcePort_Group", "DestinationPort_Group", "Len_Group"
]

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(module)s - %(funcName)s - %(lineno)d - %(message)s"
)

# Precompute internal subnets
internal_subnets = [
    ip_network('172.28.0.0/16'), # Example, adjust to your network
    ip_network('192.168.61.0/24') # Example
]
internal_ranges = [(int(net.network_address), int(net.broadcast_address)) for net in internal_subnets]

# --- Core Data Processing Functions ---

def classify_ip_vector(ip_str):
    """Classify an IP as 'Internal' or 'External'."""
    try:
        # Ensure ip_str is a string and handle potential direct IP object if necessary
        ip_int = int(ip_address(str(ip_str)))
    except ValueError: # Catches invalid IP string format
        return "External" 
    for rmin, rmax in internal_ranges:
        if rmin <= ip_int <= rmax:
            return "Internal"
    return "External"

def compute_entropy(series):
    """Compute the entropy of a given pandas Series."""
    counts = series.value_counts(dropna=False) # Include NaNs in counts for robustness if they appear
    probabilities = counts / counts.sum()
    probabilities = probabilities[probabilities > 0] # Filter out zero probabilities
    if probabilities.empty:
        return 0.0
    return -np.sum(probabilities * np.log2(probabilities)) # Using log base 2 for bits


def compute_clusters(df, resolution=2.5):
    """Compute clusters using Louvain community detection."""
    G = nx.Graph()
    # Filter out self-connections and rows with NaN in Source/Destination
    df_filtered = df.dropna(subset=["Source", "Destination"])
    df_filtered = df_filtered[df_filtered["Source"] != df_filtered["Destination"]].copy()
    
    if df_filtered.empty:
        logging.warning("No non-self-connections with valid IPs found for clustering.")
        # Create a default partition: each node in its own cluster 'N/A' or '0'
        all_nodes_for_fallback = pd.concat([df.get('Source', pd.Series(dtype=str)), df.get('Destination', pd.Series(dtype=str))]).unique()
        partition = {str(node): '0' for node in all_nodes_for_fallback if pd.notna(node)}
        return partition

    # Group by Source/Destination using the filtered DataFrame
    # Use 'processCount' for edge weight if available, otherwise count occurrences
    if 'processCount' in df_filtered.columns:
        # Ensure processCount is numeric for sum()
        df_filtered['processCount'] = pd.to_numeric(df_filtered['processCount'], errors='coerce').fillna(1)
        groups = df_filtered.groupby(["Source", "Destination"], observed=True) # observed=True for category performance
        for (src, dst), group in groups:
            if pd.notna(src) and pd.notna(dst): # Should be true due to earlier dropna
                weight = group['processCount'].sum()
                G.add_edge(src, dst, weight=weight)
    else:
        groups = df_filtered.groupby(["Source", "Destination"], observed=True)
        for (src, dst), group in groups:
            if pd.notna(src) and pd.notna(dst):
                weight = group.shape[0]
                G.add_edge(src, dst, weight=weight)
    
    # Get all unique nodes that should be in the partition, even if isolated
    all_nodes_in_df = pd.concat([df.get('Source', pd.Series(dtype=str)), df.get('Destination', pd.Series(dtype=str))]).unique()
    partition = {}
    if G.number_of_nodes() > 0:
        try:
            partition = community_louvain.best_partition(G, weight='weight', resolution=resolution, random_state=42)
        except Exception as e:
            logging.error(f"Error during Louvain clustering: {e}. Proceeding without partition for some nodes.")
            # Fallback for nodes in G but not partitioned
            for node_in_g in G.nodes():
                if node_in_g not in partition:
                    partition[str(node_in_g)] = 'N/A_Error'
    
    # Ensure all nodes from the original DataFrame get a cluster ID, even if 'N/A'
    final_partition = {
        str(node): str(partition.get(node, 'N/A_Isolated')) # Use specific N/A for isolated nodes
        for node in all_nodes_in_df if pd.notna(node)
    }
    return final_partition


def load_attack_data(filename: str = "GroundTruth.csv", start_time_filter_str: str = None, end_time_filter_str: str = None) -> tuple[dict, list, set]:
    """
    Loads attack data, filtering by time and returning a list of attack timeframes.
    Returns: A tuple containing (attack_details_map, attack_timeframes_list, attacking_sources_set)
    """
    attack_details_map = {}
    attack_timeframes_list = [] # CHANGED: This is now a list of dicts
    attacking_sources_set = set()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(script_dir, filename)
    logging.info(f"Attempting to load attack data from: {path}")

    if not os.path.exists(path):
        logging.warning(f"Attack data file not found at '{path}'.")
        return {}, [], set()

    try:
        gt_dtypes = {"Event Type": "category", "Source IP": "str", "Destination IP": "str", "Start Time": "str", "Stop Time": "str"}
        gt_usecols = ["Event Type", "Source IP", "Destination IP", "Start Time", "Stop Time"]
        gt = pd.read_csv(path, dtype=gt_dtypes, usecols=gt_usecols, keep_default_na=False, na_filter=False)

        gt["Start Time DT"] = pd.to_datetime(gt["Start Time"], errors='coerce', utc=True)
        gt["Stop Time DT"] = pd.to_datetime(gt["Stop Time"], errors='coerce', utc=True)
        gt.dropna(subset=["Start Time DT", "Stop Time DT"], inplace=True) # Drop rows with invalid dates

        if not gt.empty and start_time_filter_str and end_time_filter_str:
            start_filter_dt = pd.to_datetime(start_time_filter_str, errors='coerce', utc=True)
            end_filter_dt = pd.to_datetime(end_time_filter_str, errors='coerce', utc=True)
            if pd.notna(start_filter_dt) and pd.notna(end_filter_dt):
                initial_rows = len(gt)
                gt = gt[(gt["Start Time DT"] <= end_filter_dt) & (gt["Stop Time DT"] >= start_filter_dt)]
                logging.info(f"GroundTruth filtered from {initial_rows} to {len(gt)} rows based on capture time.")
        
        for _, row in gt.iterrows():
            s_ip = str(row["Source IP"]).strip()
            d_ip = str(row["Destination IP"]).strip()
            event = str(row["Event Type"]).strip()

            if s_ip and d_ip and event:
                attack_details_map[(s_ip, d_ip)] = event
                # CHANGED: Store each attack as a dictionary with its specific timeframe
                attack_timeframes_list.append({
                    'source': s_ip,
                    'destination': d_ip,
                    'start': row["Start Time DT"],
                    'stop': row["Stop Time DT"]
                })
                attacking_sources_set.add(s_ip)
        
        logging.info(f"Successfully loaded {len(attack_timeframes_list)} attack timeframes and {len(attacking_sources_set)} attacking sources.")
        
    except Exception as e:
        logging.error(f"Error reading or processing attack data file '{path}': {e}", exc_info=True)
    
    return attack_details_map, attack_timeframes_list, attacking_sources_set

def generate_tree_from_df(df_input, resolution=2.5, is_subtree=False):
    """
    Generates a hierarchical tree dictionary from a given DataFrame.
    This function encapsulates the logic for clustering, statistics calculation,
    and tree structure generation.
    """
    if df_input.empty:
        return {"id": "empty_root_no_data", "dist": 0, "no_tree": True, "error": "No data provided for tree generation"}

    # Use the original ClusterID for sub-trees, or compute a new one for main trees
    cluster_col_name = 'ClusterID' if is_subtree else 'DendroClusterID'
    
    if not is_subtree:
        # For main trees, perform Louvain clustering to get fresh cluster IDs for the dendrogram
        try:
            cols_for_clustering = ['Source', 'Destination', 'processCount']
            node_cluster_map = compute_clusters(df_input[cols_for_clustering], resolution=resolution)
            df_input[cluster_col_name] = df_input["Source"].astype(str).map(node_cluster_map).fillna('N/A')
        except Exception as e:
            logging.error(f"Error during clustering in generate_tree_from_df: {e}", exc_info=True)
            return {"id": "error_root", "dist": 0, "error": f"Failed to cluster: {str(e)}", "no_tree": True}
    
    # Calculate Cluster Entropy
    cluster_entropy_map = {}
    valid_clusters_df = df_input[df_input[cluster_col_name] != 'N/A']
    if not valid_clusters_df.empty:
        for cluster_id_val, group in valid_clusters_df.groupby(cluster_col_name, observed=True):
            entropies = [compute_entropy(group[col].dropna()) for col in ["Protocol", "SourcePort", "DestinationPort"] if col in group and not group[col].dropna().empty]
            valid_entropies = [e for e in entropies if pd.notna(e) and np.isfinite(e) and e > 0]
            cluster_entropy_map[cluster_id_val] = np.mean(valid_entropies) if valid_entropies else 0.0
    df_input["ClusterEntropy"] = df_input[cluster_col_name].map(cluster_entropy_map).fillna(0.0)

    # Check for sufficient clusters to build a tree
    if df_input[cluster_col_name].nunique(dropna=False) <= 1:
        single_cluster_id = "N/A"
        if df_input[cluster_col_name].nunique() == 1:
            single_cluster_id = df_input[cluster_col_name].unique()[0]
        return {"id": f"Cluster {single_cluster_id}", "cluster_id": str(single_cluster_id), "dist": 0, "is_minimal": True, "children": []}

    # Aggregate stats for linkage
    stats = (df_input[df_input[cluster_col_name] != 'N/A']
             .groupby(cluster_col_name, observed=True)
             .agg(avg_entropy=('ClusterEntropy', 'mean'),
                  total_packets=('processCount', 'sum'))
             .reset_index()
             .rename(columns={cluster_col_name: 'ClusterID'}))

    if stats.empty or stats.shape[0] < 2:
        return {"id": "empty_root_no_valid_stats", "dist": 0, "no_tree": True, "error": "No valid clusters for statistics"}

    stats = stats.sort_values(by='ClusterID', key=lambda x: x.astype(str)).reset_index(drop=True)
    linkage_data = stats[['total_packets', 'avg_entropy']].to_numpy()

    try:
        Z = linkage(linkage_data, method='average', metric='euclidean')
        root_node_obj, _ = to_tree(Z, rd=True)
    except Exception as e:
        return {"id": "error_scipy_tree", "dist": 0, "error": f"Hierarchical clustering failed: {str(e)}", "no_tree": True}

    def node_to_dict_local(node):
        if node.is_leaf():
            cluster_id_val = str(stats.loc[node.id, 'ClusterID'])
            return {"id": f"Cluster {cluster_id_val}", "cluster_id": cluster_id_val, "dist": float(node.dist)}
        else:
            left_child = node_to_dict_local(node.get_left()) if node.get_left() else None
            right_child = node_to_dict_local(node.get_right()) if node.get_right() else None
            children = [c for c in [left_child, right_child] if c is not None]
            return {"id": f"Internal_{node.id}_dist{node.dist:.2f}", "dist": float(node.dist), "children": children}
            
    return node_to_dict_local(root_node_obj)

def prepare_dataframe_from_upload(df: pd.DataFrame):
    """
    Processes a DataFrame (expected from Parquet upload) to add engineered features.
    The input DataFrame should have columns like:
    Time, No., Source, Destination, Protocol, Length, SourcePort, DestinationPort, Flags_temp, Payload
    """
    logging.info(f"Initial DataFrame shape from uploaded Parquet: {df.shape}")
    overall_start_time = time.perf_counter()

    if df.empty:
        logging.warning("Input DataFrame is empty. Returning empty DataFrame.")
        return pd.DataFrame(columns=["Time", "No.", "Source", "Destination", "Protocol", "Length", "SourcePort", "DestinationPort", "Flags_temp", "Payload", "processCount", "IsSYN", "IsRST", "IsACK", "IsPSH", "IsFIN", "Flags", "SourceClassification", "DestinationClassification", "ConnectionID", "InterArrivalTime", "BytesPerSecond", "PayloadLength", "NodeWeight", "BurstID", "ClusterID", "ClusterEntropy"])

    current_time_section = time.perf_counter()
    # --- Verify and Coerce Basic Data Types ---
    if "Time" not in df.columns:
        df["Time"] = pd.NaT
        logging.warning("'Time' column missing, added as NaT.")
    else:
        if not pd.api.types.is_datetime64_any_dtype(df["Time"]):
            df["Time"] = pd.to_datetime(df["Time"], errors='coerce')
        
        if df["Time"].dt.tz is None:
            df["Time"] = df["Time"].dt.tz_localize('UTC')
            logging.info("Localized naive 'Time' column to UTC.")
        else:
            df["Time"] = df["Time"].dt.tz_convert('UTC')
            logging.info("Converted timezone-aware 'Time' column to UTC.")

    for col, col_type in [("Length", int), ("SourcePort", "Int64"), ("DestinationPort", "Int64"), ("Flags_temp", int), ("No.", int)]:
        if col not in df.columns:
            df[col] = 0 if col_type == int else pd.NA
            logging.warning(f"'{col}' column missing, added with default/NA values.")
        else:
            df[col] = pd.to_numeric(df[col], errors='coerce')
            if col_type == "Int64":
                df[col] = df[col].astype("Int64")
            else:
                df[col] = df[col].fillna(0).astype(int)
    
    for col_str in ["Source", "Destination", "Protocol", "Payload"]:
        if col_str not in df.columns:
            df[col_str] = "" if col_str != "Protocol" else "Unknown"
            logging.warning(f"'{col_str}' column missing, added with default empty/Unknown string.")
        else:
            df[col_str] = df[col_str].astype(str).fillna("" if col_str != "Protocol" else "Unknown")
    logging.info(f"PROFILE: Type Coercion took: {time.perf_counter() - current_time_section:.4f} seconds")
    current_time_section = time.perf_counter()

    # --- Feature Engineering ---
    if 'processCount' not in df.columns:
        df['processCount'] = 1
    else:
        df['processCount'] = pd.to_numeric(df['processCount'], errors='coerce').fillna(1).astype(int)
    logging.info(f"PROFILE: processCount setup took: {time.perf_counter() - current_time_section:.4f} seconds")
    current_time_section = time.perf_counter()

    df["IsSYN"] = ((df["Flags_temp"] & 2) > 0)
    df["IsRST"] = ((df["Flags_temp"] & 4) > 0)
    df["IsACK"] = ((df["Flags_temp"] & 16) > 0)
    df["IsPSH"] = ((df["Flags_temp"] & 8) > 0)
    df["IsFIN"] = ((df["Flags_temp"] & 1) > 0)
    
    df["Flags"] = "" 
    if df["IsSYN"].any(): df.loc[df["IsSYN"], "Flags"] = df.loc[df["IsSYN"], "Flags"] + "SYN,"
    if df["IsACK"].any(): df.loc[df["IsACK"], "Flags"] = df.loc[df["IsACK"], "Flags"] + "ACK,"
    if df["IsPSH"].any(): df.loc[df["IsPSH"], "Flags"] = df.loc[df["IsPSH"], "Flags"] + "PSH,"
    if df["IsRST"].any(): df.loc[df["IsRST"], "Flags"] = df.loc[df["IsRST"], "Flags"] + "RST,"
    if df["IsFIN"].any(): df.loc[df["IsFIN"], "Flags"] = df.loc[df["IsFIN"], "Flags"] + "FIN,"
    
    df["Flags"] = df["Flags"].str.rstrip(',')
    df.loc[df["Flags"] == "", "Flags"] = "N/A"
    df["Flags"] = df["Flags"].astype('category')
    
    df["IsSYN"] = df["IsSYN"].astype(np.uint8)
    df["IsRST"] = df["IsRST"].astype(np.uint8)
    df["IsACK"] = df["IsACK"].astype(np.uint8)
    df["IsPSH"] = df["IsPSH"].astype(np.uint8)
    df["IsFIN"] = df["IsFIN"].astype(np.uint8)

    logging.info(f"PROFILE: Flag Parsing (Advanced Vectorized) took: {time.perf_counter() - current_time_section:.4f} seconds")
    current_time_section = time.perf_counter()

    df['Source'] = df['Source'].astype(str).str.strip()
    df['Destination'] = df['Destination'].astype(str).str.strip()
    
    unique_ips_series = pd.concat([df["Source"], df["Destination"]]).unique()
    valid_unique_ips = [ip for ip in unique_ips_series if isinstance(ip, str) and ip.strip() and ip.lower() != 'nan' and ip.lower() != 'unknown_ip' and ip != "0.0.0.0"]
    
    classification_map = {ip_str: classify_ip_vector(ip_str) for ip_str in valid_unique_ips}
    
    df["SourceClassification"] = df["Source"].map(classification_map).fillna("External").astype('category')
    df["DestinationClassification"] = df["Destination"].map(classification_map).fillna("External").astype('category')
    logging.info(f"PROFILE: IP Classification took: {time.perf_counter() - current_time_section:.4f} seconds")
    current_time_section = time.perf_counter()

    df["ConnectionID"] = (df["Source"] + ":" + df["SourcePort"].astype(str).replace('<NA>', 'N/A') + "-" +
                          df["Destination"] + ":" + df["DestinationPort"].astype(str).replace('<NA>', 'N/A'))
    df["ConnectionID"] = df["ConnectionID"].astype('category')
    logging.info(f"PROFILE: ConnectionID Generation took: {time.perf_counter() - current_time_section:.4f} seconds")
    current_time_section = time.perf_counter()

    if pd.api.types.is_datetime64_any_dtype(df["Time"]) and not df["Time"].isnull().all():
        df = df.sort_values(by=["ConnectionID", "Time"]) 
        df["InterArrivalTime"] = df.groupby("ConnectionID", observed=True)["Time"].diff().dt.total_seconds()
        df["InterArrivalTime"] = df["InterArrivalTime"].fillna(0.0) 
    else:
        df["InterArrivalTime"] = 0.0
        logging.warning("InterArrivalTime set to 0.0 due to missing or invalid 'Time' column.")

    df["BytesPerSecond"] = df["Length"] / df["InterArrivalTime"]
    df["BytesPerSecond"] = df["BytesPerSecond"].replace([np.inf, -np.inf], 0) 
    df["BytesPerSecond"] = df["BytesPerSecond"].fillna(0.0)
    logging.info(f"PROFILE: InterArrivalTime & BytesPerSecond took: {time.perf_counter() - current_time_section:.4f} seconds")
    current_time_section = time.perf_counter()

    df["PayloadLength"] = df["Length"] 
    if not df.empty:
        source_counts = df['Source'].value_counts()
        dest_counts = df['Destination'].value_counts()
        ip_total_activity = source_counts.add(dest_counts, fill_value=0)

        if not ip_total_activity.empty:
            min_activity = ip_total_activity.min()
            max_activity = ip_total_activity.max()
            if max_activity == min_activity:
                 df["NodeWeight_Src"] = 0.5
                 df["NodeWeight_Dst"] = 0.5
            else:
                df["NodeWeight_Src"] = df["Source"].map(ip_total_activity).apply(lambda x: (x - min_activity) / (max_activity - min_activity) if pd.notna(x) else 0.5)
                df["NodeWeight_Dst"] = df["Destination"].map(ip_total_activity).apply(lambda x: (x - min_activity) / (max_activity - min_activity) if pd.notna(x) else 0.5)
            df["NodeWeight"] = (df["NodeWeight_Src"] + df["NodeWeight_Dst"]) / 2
            if "NodeWeight_Src" in df.columns: df.drop(columns=["NodeWeight_Src"], inplace=True, errors='ignore')
            if "NodeWeight_Dst" in df.columns: df.drop(columns=["NodeWeight_Dst"], inplace=True, errors='ignore')
        else:
            df["NodeWeight"] = 0.5
    else:
        df["NodeWeight"] = 0.5
    logging.info(f"PROFILE: PayloadLength & NodeWeight took: {time.perf_counter() - current_time_section:.4f} seconds")
    current_time_section = time.perf_counter()

    if "InterArrivalTime" in df.columns and "ConnectionID" in df.columns:
        df["BurstID"] = df.groupby("ConnectionID", observed=True)["InterArrivalTime"].transform(lambda x: (x.fillna(0) >= 0.01).cumsum())
    else:
        df["BurstID"] = 0
    logging.info(f"PROFILE: BurstID took: {time.perf_counter() - current_time_section:.4f} seconds")
    current_time_section = time.perf_counter()

    logging.info("PROFILE: Starting ClusterID computation (Louvain)...")
    if not df.empty:
        try:
            cols_for_clustering = ['Source', 'Destination']
            if 'processCount' in df.columns:
                cols_for_clustering.append('processCount')
            df_for_clustering_view = df[cols_for_clustering].copy()
            node_cluster_map = compute_clusters(df_for_clustering_view, resolution=2.5)
            df["ClusterID"] = df["Source"].astype(str).map(node_cluster_map).fillna('N/A').astype('category')
        except Exception as e:
            logging.error(f"Error during initial clustering: {e}. Assigning 'N/A' to ClusterID.", exc_info=True)
            df["ClusterID"] = pd.Series(['N/A'] * len(df), dtype='category', index=df.index if not df.empty else None)
    else:
        df["ClusterID"] = pd.Series(dtype='category')
    logging.info(f"PROFILE: ClusterID (Louvain) computation took: {time.perf_counter() - current_time_section:.4f} seconds")
    current_time_section = time.perf_counter()

    cluster_entropy_map = {}
    if not df.empty and "ClusterID" in df.columns and df["ClusterID"].nunique(dropna=False) > 0:
        valid_clusters_df = df[df['ClusterID'] != 'N/A']
        if not valid_clusters_df.empty:
            for cluster_id_val, group in valid_clusters_df.groupby("ClusterID", observed=True):
                entropies = []
                if "Protocol" in group.columns and not group["Protocol"].dropna().empty:
                    entropies.append(compute_entropy(group["Protocol"].dropna()))
                if "SourcePort" in group.columns and not group["SourcePort"].dropna().empty:
                    entropies.append(compute_entropy(group["SourcePort"].astype(str).dropna()))
                if "DestinationPort" in group.columns and not group["DestinationPort"].dropna().empty:
                    entropies.append(compute_entropy(group["DestinationPort"].astype(str).dropna()))
                
                valid_entropies = [e for e in entropies if pd.notna(e) and np.isfinite(e) and e > 0]
                cluster_entropy_map[cluster_id_val] = np.mean(valid_entropies) if valid_entropies else 0.0
    df["ClusterEntropy"] = df["ClusterID"].map(cluster_entropy_map).fillna(0.0)
    logging.info(f"PROFILE: ClusterEntropy took: {time.perf_counter() - current_time_section:.4f} seconds")
    
    logging.info("PROFILE: Starting Sankey pre-computation...")
    sankey_precompute_start = time.perf_counter()
    for port_col_name in ["SourcePort", "DestinationPort"]:
        new_col_name = f"{port_col_name}_Group"
        df[new_col_name] = pd.cut(df[port_col_name],
                                  bins=[-1, 0, 1023, 49151, 65535],
                                  labels=['N/A', 'Well-Known', 'Registered (1024-49151)', 'Dyn/Priv (49152-65535)'],
                                  right=True).astype(str)
        well_known_mask = (df[port_col_name] >= 1) & (df[port_col_name] <= 1023)
        df.loc[well_known_mask, new_col_name] = df.loc[well_known_mask, port_col_name].astype(str)
        df[new_col_name] = df[new_col_name].fillna('N/A').astype('category')

    df['Len_Group'] = pd.cut(df['Length'],
                             bins=[-1, 59, 99, 199, 499, 999, 1499, float('inf')],
                             labels=["0-59 B", "60-99 B", "100-199 B", "200-499 B", "500-999 B", "1000-1499 B", "1500+ B"],
                             right=True).astype(str).fillna('N/A').astype('category')
    logging.info(f"PROFILE: Sankey pre-computation took: {time.perf_counter() - sankey_precompute_start:.4f} seconds")
    
    # --- PERFORMANCE OPTIMIZATION ---
    if 'Time' in df.columns and pd.api.types.is_datetime64_any_dtype(df["Time"]):
        # Important: Reset index before setting 'Time' to avoid MultiIndex errors
        if isinstance(df.index, pd.MultiIndex):
            df.reset_index(inplace=True)
        df.set_index('Time', inplace=True)
        df.sort_index(inplace=True)
        logging.info("Set and sorted 'Time' column as the DataFrame index for performance.")
    # --- END PERFORMANCE OPTIMIZATION ---

    logging.info(f"PROFILE: Total prepare_dataframe_from_upload took: {time.perf_counter() - overall_start_time:.4f} seconds")
    logging.info(f"DataFrame feature engineering complete. Shape after processing: {df.shape}")
    return df

# --- Flask App Setup ---
app = Flask(__name__)
CORS(app) # Enable CORS for all routes
logging.info("--- FLASK APP INITIALIZED (Parquet Version) ---")


@app.route('/process_uploaded_file', methods=['POST'])
def process_uploaded_file_endpoint():
    global global_df, global_start_time, global_end_time, global_duration_seconds
    global global_backend_csv_processing_time_seconds
    global attack_detail_map_cache, attack_timeframes_cache, attacking_sources_cache

    backend_processing_internal_start = time.perf_counter()

    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request."}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected for upload."}), 400

    if file and file.filename.endswith('.parquet'):
        try:
            logging.info(f"Received Parquet file: {file.filename}")
            parquet_data = BytesIO(file.read())
            raw_df = pd.read_parquet(parquet_data)
            logging.info(f"Successfully read Parquet file into DataFrame. Shape: {raw_df.shape}")

            # This function returns a DataFrame with 'Time' as the index
            df = prepare_dataframe_from_upload(raw_df)

            # --- CORRECTED TIME INFO LOGIC ---
            # Since 'Time' is now the index, get time info from it directly.
            if isinstance(df.index, pd.DatetimeIndex) and not df.index.empty:
                min_time = df.index.min()
                max_time = df.index.max()
                global_start_time = min_time.isoformat() if pd.notna(min_time) else None
                global_end_time = max_time.isoformat() if pd.notna(max_time) else None
                global_duration_seconds = (max_time - min_time).total_seconds() if pd.notna(min_time) and pd.notna(max_time) else 0
            # --- END CORRECTION ---
            
            # Load attack data, filtering by the capture's time window
            attack_detail_map_cache, attack_timeframes_cache, attacking_sources_cache = load_attack_data(
                start_time_filter_str=global_start_time,
                end_time_filter_str=global_end_time
            )

            # Create a temporary 'Time' column from the index for attack processing
            df.reset_index(inplace=True)

            # --- ANOMALY AND CLUSTER ANOMALY DETECTION (REVISED LOGIC) ---
            if not df.empty:
                # Assign AttackType based on (Source, Destination) pair
                attack_keys = list(zip(df["Source"].astype(str), df["Destination"].astype(str)))
                df["AttackType"] = pd.Series(attack_keys, index=df.index).map(attack_detail_map_cache).fillna("N/A").astype('category')
                
                # Default all rows to 'normal' first
                df['Anomaly'] = 'normal'
                
                # Iterate through each known attack timeframe and mark matching packets
                if attack_timeframes_cache:
                    for attack in attack_timeframes_cache:
                        if pd.notna(attack['start']) and pd.notna(attack['stop']):
                            mask = (
                                (df['Source'] == attack['source']) &
                                (df['Destination'] == attack['destination']) &
                                (df['Time'] >= attack['start']) &
                                (df['Time'] <= attack['stop'])
                            )
                            df.loc[mask, 'Anomaly'] = 'anomaly'
                
                df['Anomaly'] = df['Anomaly'].astype('category')

                # Determine ClusterAnomaly
                if "ClusterID" in df.columns and df["ClusterID"].nunique(dropna=False) > 0:
                    df["ClusterAnomaly"] = df.groupby("ClusterID", observed=True)["Anomaly"].transform(
                        lambda s: "anomaly" if (s == "anomaly").any() else "normal"
                    ).astype('category')
                else:
                    df["ClusterAnomaly"] = pd.Series(["normal"] * len(df), dtype='category', index=df.index if not df.empty else None)
            else:
                for col in ["AttackType", "Anomaly", "ClusterAnomaly"]:
                    df[col] = pd.Series(dtype='category')

            # Ensure all other expected columns are present
            for col in expected_cols:
                if col not in df.columns and col != 'Time':
                    if col in ["SourcePort", "DestinationPort"]: df[col] = pd.NA
                    elif pd.api.types.is_string_dtype(df.get(col, pd.Series(dtype=str))): df[col] = ""
                    else: df[col] = 0
                    logging.info(f"Added missing expected column '{col}' with default values.")
            
            # --- CORRECTED FINAL DATAFRAME CREATION ---
            # Re-order columns to the expected final order and re-establish the Time index
            final_cols = [col for col in expected_cols if col in df.columns]
            global_df = df[final_cols].copy()
            if 'Time' in global_df.columns:
                global_df.set_index('Time', inplace=True)
                if not global_df.index.is_monotonic_increasing:
                    global_df.sort_index(inplace=True)
            
            logging.info(f"Parquet file processed into global_df. Final shape: {global_df.shape}")

            backend_processing_internal_end = time.perf_counter()
            global_backend_csv_processing_time_seconds = backend_processing_internal_end - backend_processing_internal_start
            logging.info(f"Backend Parquet processing and setup took: {global_backend_csv_processing_time_seconds:.4f} seconds.")

            return jsonify({
                "message": f"Parquet file processed successfully. {len(global_df)} rows loaded.",
                "filename": file.filename,
                "rows_loaded": len(global_df)
            }), 200

        except Exception as e:
            logging.exception(f"Error processing uploaded Parquet file '{file.filename}'")
            global_df, global_start_time, global_end_time, global_duration_seconds, global_backend_csv_processing_time_seconds = None, None, None, None, None
            attack_detail_map_cache, attack_timeframes_cache, attacking_sources_cache = {}, [], set()
            return jsonify({"error": f"An unexpected server error occurred: {str(e)}"}), 500
    else:
        return jsonify({"error": "Invalid file type. Please upload a .parquet file."}), 400

def apply_time_filter(df, request_obj):
    """
    Applies a time filter to a DataFrame based on request arguments, using the DatetimeIndex.
    Returns the filtered DataFrame.
    """
    params = request_obj.args if request_obj.method == 'GET' else request_obj.get_json(silent=True) or {}
    
    start_time_str = params.get('start_time')
    end_time_str = params.get('end_time')

    # Check if the DataFrame's index is a DatetimeIndex
    if start_time_str and end_time_str and isinstance(df.index, pd.DatetimeIndex):
        try:
            start_dt = pd.to_datetime(start_time_str, errors='coerce', utc=True)
            end_dt = pd.to_datetime(end_time_str, errors='coerce', utc=True)
            
            if pd.notna(start_dt) and pd.notna(end_dt):
                original_rows = len(df)
                # Use .loc for fast slicing on the sorted DatetimeIndex
                df = df.loc[start_dt:end_dt].copy()
                # Reset index to make 'Time' a column again for other functions that need it
                df.reset_index(inplace=True)
                logging.info(f"Time filter applied via index: {start_dt} to {end_dt}. Rows changed from {original_rows} to {len(df)}.")
            else:
                logging.warning(f"Invalid start_time or end_time format. Not applying time filter.")
        except Exception as e:
            logging.error(f"Error applying time filter on index: {e}", exc_info=True)
    return df

def group_port(port):
    if pd.isna(port): return "N/A"
    try:
        p = int(port)
        if 1 <= p <= 1023: return str(p) # Well-known, show number
        elif 1024 <= p <= 49151: return "Registered (1024-49151)"
        elif 49152 <= p <= 65535: return "Dyn/Priv (49152-65535)"
        else: return "Other" 
    except (ValueError, TypeError): return "N/A"

def group_length(length):
    if pd.isna(length): return "N/A"
    try:
        l = int(length)
        if l < 0: return "N/A"
        elif l < 60: return "0-59 B"
        elif l < 100: return "60-99 B"
        elif l < 200: return "100-199 B"
        elif l < 500: return "200-499 B"
        elif l < 1000: return "500-999 B"
        elif l < 1500: return "1000-1499 B"
        else: return "1500+ B"
    except (ValueError, TypeError): return "N/A"

@app.route('/filter_and_aggregate', methods=['POST'])
def filter_and_aggregate():
    global global_df
    if global_df is None or global_df.empty: # Check for empty df too
        logging.warning("/filter_and_aggregate called but global_df is None or empty.")
        return jsonify([]) # Return empty list for D3/frontend to handle gracefully

    logging.info(f"Entering /filter_and_aggregate. global_df shape: {global_df.shape}")
    
    # Apply time filter first from the POST body
    df = apply_time_filter(global_df.copy(), request)

    # Anomaly and Attack Type maps for clusters
    anomaly_map = {}
    cluster_attack_types_map = {}
    if "ClusterID" in df.columns and not df.empty:
        anomaly_map = (
            df.groupby("ClusterID", observed=True)["Anomaly"] # observed=True for category performance
            .apply(lambda s: "anomaly" if (s == "anomaly").any() else "normal")
            .to_dict()
        )
        if "AttackType" in df.columns:
            for cluster_id_val, group in df.groupby("ClusterID", observed=True):
                if cluster_id_val == 'N/A': continue # Skip N/A clusters explicitly
                # Ensure AttackType is treated as string, filter out "N/A" before unique()
                unique_cluster_attacks = group["AttackType"].astype(str).str.upper()
                unique_cluster_attacks = unique_cluster_attacks[unique_cluster_attacks != "N/A"].unique()
                cluster_attack_types_map[str(cluster_id_val)] = list(unique_cluster_attacks) if len(unique_cluster_attacks) > 0 else []
    
    data = request.get_json()
    logging.info(f"Request data for /filter_and_aggregate: {data}")

    # --- Apply Filters ---
    # Ensure filters use .get() with defaults and handle types robustly
    payloadKeyword = data.get("payloadKeyword", "").strip().lower()
    sourceFilter = data.get("sourceFilter", "").strip().lower()
    destinationFilter = data.get("destinationFilter", "").strip().lower()
    protocolFilter = data.get("protocolFilter", "").strip().lower()

    try: entropyMin = float(data.get("entropyMin", float('-inf')))
    except (ValueError, TypeError): entropyMin = float('-inf')
    try: entropyMax = float(data.get("entropyMax", float('inf')))
    except (ValueError, TypeError): entropyMax = float('inf')
    
    metric = data.get("metric", "count") # Default to 'count'

    min_source_amt = int(data["minSourceAmt"]) if data.get("minSourceAmt","").strip() else 0
    max_source_amt = int(data["maxSourceAmt"]) if data.get("maxSourceAmt","").strip() else float('inf')
    min_dest_amt = int(data["minDestinationAmt"]) if data.get("minDestinationAmt","").strip() else 0
    max_dest_amt = int(data["maxDestinationAmt"]) if data.get("maxDestinationAmt","").strip() else float('inf')

    # Apply other general filters
    if payloadKeyword and "Payload" in df.columns and not df.empty:
        df = df[df["Payload"].str.lower().str.contains(payloadKeyword, na=False)]
    if sourceFilter and "Source" in df.columns and not df.empty:
        df = df[df["Source"].str.lower().str.contains(sourceFilter, na=False)]
    if destinationFilter and "Destination" in df.columns and not df.empty:
        df = df[df["Destination"].str.lower().str.contains(destinationFilter, na=False)]
    if protocolFilter and "Protocol" in df.columns and not df.empty:
        df = df[df["Protocol"].str.lower().str.contains(protocolFilter, na=False)]

    if "ClusterEntropy" in df.columns and not df.empty:
        df["ClusterEntropy"] = pd.to_numeric(df["ClusterEntropy"], errors='coerce')
        df = df[(df["ClusterEntropy"] >= entropyMin) & (df["ClusterEntropy"] <= entropyMax)]
    
    logging.info(f"df shape after all filtering: {df.shape}, for metric: {metric}")
    if df.empty:
        logging.warning(f"DataFrame is empty after filters for metric '{metric}'. Returning empty list.")
        return jsonify([])

    # --- Aggregation Logic ---
    agg = pd.Series(dtype=float)
    if not df.empty and "ClusterID" in df.columns: # Ensure ClusterID exists before grouping
        grouped_by_cluster = df.groupby("ClusterID", observed=True)

        if metric == "count":
            if 'processCount' in df.columns: # processCount comes from prepare_dataframe_from_upload
                agg = grouped_by_cluster['processCount'].sum()
            else: # Fallback
                agg = grouped_by_cluster.size()
        elif metric == "% SYN packets" and "IsSYN" in df.columns:
            agg = grouped_by_cluster["IsSYN"].sum() / grouped_by_cluster.size().replace(0, 1) * 100
        elif metric == "% RST packets" and "IsRST" in df.columns:
            agg = grouped_by_cluster["IsRST"].sum() / grouped_by_cluster.size().replace(0, 1) * 100
        elif metric == "% ACK packets" and "IsACK" in df.columns:
            agg = grouped_by_cluster["IsACK"].sum() / grouped_by_cluster.size().replace(0, 1) * 100
        elif metric == "% PSH packets" and "IsPSH" in df.columns:
            agg = grouped_by_cluster["IsPSH"].sum() / grouped_by_cluster.size().replace(0, 1) * 100
        elif metric == "Unique Destinations" and "Destination" in df.columns:
            agg = grouped_by_cluster["Destination"].nunique()
        elif metric == "Unique Sources" and "Source" in df.columns:
            agg = grouped_by_cluster["Source"].nunique()
        elif metric == "Unique IPs" and "Source" in df.columns and "Destination" in df.columns:
             agg = grouped_by_cluster.apply(lambda g: len(set(g["Source"]).union(set(g["Destination"]))))
        elif metric == "Payload Size Variance" and "PayloadLength" in df.columns:
             df["PayloadLength"] = pd.to_numeric(df["PayloadLength"], errors="coerce").fillna(0)
             agg = grouped_by_cluster["PayloadLength"].var(ddof=0) # Population variance
        elif metric == "Packets per Second" and "Time" in df.columns:
            df['Time'] = pd.to_datetime(df['Time'], errors='coerce') # Ensure datetime
            def packets_per_second(g):
                if g["Time"].count() < 2 or g["Time"].isnull().all(): return 0.0
                duration = (g["Time"].max() - g["Time"].min()).total_seconds()
                return len(g) / duration if duration > 0 else float(len(g)) # Avoid NaN if duration is 0 but packets exist
            agg = grouped_by_cluster.apply(packets_per_second)
        elif metric == "Total Data Sent" and "Length" in df.columns:
            df["Length"] = pd.to_numeric(df["Length"], errors='coerce').fillna(0)
            agg = grouped_by_cluster["Length"].sum()
        elif metric == "Start Time" and "Time" in df.columns:
            df['Time'] = pd.to_datetime(df['Time'], errors='coerce')
            overall_min_time = df['Time'].dropna().min()
            agg_time = grouped_by_cluster["Time"].min()
            if pd.notna(overall_min_time) and not agg_time.empty:
                 agg = (agg_time - overall_min_time).dt.total_seconds()
            else: agg = pd.Series(0, index=agg_time.index, dtype=float) if not agg_time.empty else pd.Series(dtype=float)
        elif metric == "Duration" and "Time" in df.columns:
            df['Time'] = pd.to_datetime(df['Time'], errors='coerce')
            agg = (grouped_by_cluster["Time"].max() - grouped_by_cluster["Time"].min()).dt.total_seconds()
        elif metric == "Average Inter-Arrival Time" and "InterArrivalTime" in df.columns:
            df["InterArrivalTime"] = pd.to_numeric(df["InterArrivalTime"], errors='coerce')
            agg = grouped_by_cluster["InterArrivalTime"].mean()
        elif metric in df.columns: # Generic sum for other numeric columns
            df[metric] = pd.to_numeric(df[metric], errors='coerce').fillna(0)
            agg = grouped_by_cluster[metric].sum()
        else: # Fallback if metric is unknown or column missing
            logging.warning(f"Metric '{metric}' not found or not supported in /filter_and_aggregate. Aggregating by size.")
            agg = grouped_by_cluster.size() # Default to count of rows in cluster

        agg = agg.fillna(0.0) # Ensure no NaNs in final aggregation
        agg = agg.replace([np.inf, -np.inf], 0) # Replace infinities
    else:
        if df.empty: logging.info("DataFrame empty before aggregation.")
        else: logging.warning("ClusterID column not found or no clusters to aggregate. Returning empty list.")
        return jsonify([])

    # Apply source/destination count filters
    unique_sources_per_cluster = df.groupby("ClusterID", observed=True)["Source"].nunique() if "ClusterID" in df.columns and "Source" in df.columns else pd.Series(dtype=int)
    unique_destinations_per_cluster = df.groupby("ClusterID", observed=True)["Destination"].nunique() if "ClusterID" in df.columns and "Destination" in df.columns else pd.Series(dtype=int)

    filtered_pivot = []
    for cluster_id_val, value in agg.items():
        str_cluster_id_val = str(cluster_id_val)
        
        src_count = unique_sources_per_cluster.get(cluster_id_val, 0)
        dst_count = unique_destinations_per_cluster.get(cluster_id_val, 0)
        
        if not (min_source_amt <= src_count <= max_source_amt): continue
        if not (min_dest_amt <= dst_count <= max_dest_amt): continue
        
        processed_value = 0.0
        if pd.notnull(value) and np.isfinite(value):
            processed_value = float(value)

        filtered_pivot.append({
            "cluster": str_cluster_id_val,
            "value": processed_value,
            "clusterAnomaly": anomaly_map.get(str_cluster_id_val, "normal"),
            "ClusterAttackTypes": cluster_attack_types_map.get(str_cluster_id_val, [])
        })
    
    logging.info(f"Number of items in filtered_pivot for metric '{metric}': {len(filtered_pivot)}")
    return jsonify(filtered_pivot)

@app.route('/get_sankey_matching_clusters', methods=['POST'])
def get_sankey_matching_clusters():
    global global_df
    if global_df is None or global_df.empty:
        logging.warning("/get_sankey_matching_clusters called but global_df is None or empty.")
        return jsonify({"error": "No data loaded"}), 400

    data = request.get_json()
    sankey_filter_data = data.get("sankeyFilter")
    main_filters = data.get("mainFilters")

    if not sankey_filter_data:
        logging.error("/get_sankey_matching_clusters: No Sankey filter provided in request.")
        return jsonify({"error": "No Sankey filter provided"}), 400

    df_filtered = global_df.copy()

    # Apply main filters first, if they exist
    if main_filters and not df_filtered.empty:
        logging.info(f"Applying main filters to /get_sankey_matching_clusters: {main_filters}")
        sourceFilter = main_filters.get("sourceFilter", "").strip().lower()
        destinationFilter = main_filters.get("destinationFilter", "").strip().lower()
        protocolFilter = main_filters.get("protocolFilter", "").strip().lower()

        if sourceFilter and "Source" in df_filtered.columns:
            df_filtered = df_filtered[df_filtered["Source"].str.lower().str.contains(sourceFilter, na=False)]
        if destinationFilter and "Destination" in df_filtered.columns:
            df_filtered = df_filtered[df_filtered["Destination"].str.lower().str.contains(destinationFilter, na=False)]
        if protocolFilter and "Protocol" in df_filtered.columns:
            df_filtered = df_filtered[df_filtered["Protocol"].str.lower().str.contains(protocolFilter, na=False)]
        logging.info(f"Shape after main filters in /get_sankey_matching_clusters: {df_filtered.shape}")

    # These are the PROGRAMMATIC keys from the frontend, e.g., "SourceClassification", "SourcePort_Group"
    sankey_dim_key = sankey_filter_data.get("dimensionKey") 
    sankey_val = str(sankey_filter_data.get("value"))
    
    logging.info(f"Filtering for Sankey node: Dimension='{sankey_dim_key}', Value to Match='{sankey_val}'")

    processed_sankey_filter = False
    
    # *** CORRECTED LOGIC: Use the pre-computed columns directly ***
    if sankey_dim_key in ["SourcePort_Group", "DestinationPort_Group", "Len_Group", "Protocol", "SourceClassification", "DestinationClassification", "Anomaly", "ClusterID"]:
        if sankey_dim_key in df_filtered.columns:
            df_filtered = df_filtered[df_filtered[sankey_dim_key].astype(str) == sankey_val]
            processed_sankey_filter = True
        else:
             logging.warning(f"Sankey filter dimension '{sankey_dim_key}' not found in DataFrame.")
    
    if not processed_sankey_filter:
        logging.warning(f"Sankey filter for dimension '{sankey_dim_key}' was not processed in /get_sankey_matching_clusters.")
        return jsonify({"matchingClusterIds": []})

    if "ClusterID" in df_filtered.columns and not df_filtered.empty:
        matching_cluster_ids = df_filtered["ClusterID"].astype(str).unique().tolist()
        if sankey_val != 'N/A':
            matching_cluster_ids = [cid for cid in matching_cluster_ids if cid != 'N/A']
        
        logging.info(f"Found {len(matching_cluster_ids)} cluster IDs matching Sankey filter.")
        return jsonify({"matchingClusterIds": matching_cluster_ids})
    else: 
        logging.info(f"No cluster IDs found matching Sankey filter for '{sankey_dim_key}'='{sankey_val}'.")
        return jsonify({"matchingClusterIds": []})

@app.route('/hierarchical_clusters', methods=['GET'])
def hierarchical_clusters():
    global global_df
    if global_df is None or global_df.empty:
        logging.warning("/hierarchical_clusters called but global_df is None or empty.")
        return jsonify({"id": "empty_root_no_data", "dist": 0, "no_tree": True, "error": "No data loaded"}), 200

    df_for_dendro = apply_time_filter(global_df.copy(), request)

    if df_for_dendro.empty:
        logging.warning("DataFrame is empty after time filter in /hierarchical_clusters.")
        return jsonify({"id": "empty_root_no_data_in_range", "dist": 0, "no_tree": True, "error": "No data in selected time range"}), 200

    resolution = 2.5
    try:
        resolution_param = request.args.get("resolution")
        if resolution_param is not None:
            resolution = float(resolution_param)
    except (TypeError, ValueError):
        pass # Use default

    tree_dict = generate_tree_from_df(df_for_dendro, resolution=resolution, is_subtree=False)
    
    # This logic remains here because it maps the newly generated DendroClusterID back to the original ClusterID
    # which is only necessary for the main tree view, not sub-trees.
    if 'DendroClusterID' in df_for_dendro.columns and 'ClusterID' in df_for_dendro.columns:
        dendro_to_global_map = df_for_dendro.groupby('DendroClusterID')['ClusterID'].unique().apply(list).to_dict()
        def embed_original_clusters(node):
            if 'cluster_id' in node: # Leaf node
                node['original_clusters'] = dendro_to_global_map.get(node['cluster_id'], [])
            if 'children' in node:
                aggregated_originals = []
                for child in node['children']:
                    embed_original_clusters(child)
                    if child.get('original_clusters'):
                        aggregated_originals.extend(child['original_clusters'])
                node['original_clusters'] = list(set(aggregated_originals))
        embed_original_clusters(tree_dict)

    return jsonify(tree_dict)

@app.route('/create_subtree', methods=['POST'])
def create_subtree():
    """
    Creates a new hierarchical tree and heatmap from a specific subset of original clusters.
    """
    global global_df
    if global_df is None or global_df.empty:
        return jsonify({"error": "No data loaded on the server."}), 400

    data = request.get_json()
    original_cluster_ids = data.get("original_cluster_ids")

    if not original_cluster_ids or not isinstance(original_cluster_ids, list):
        return jsonify({"error": "A list of 'original_cluster_ids' is required."}), 400

    logging.info(f"Received request to create subtree from {len(original_cluster_ids)} original clusters.")

    # Ensure IDs are strings for matching with DataFrame's string-based category
    str_ids = [str(cid) for cid in original_cluster_ids]
    
    # Filter the main DataFrame to get only the rows belonging to the selected original clusters
    # Use the original 'ClusterID' column for filtering.
    df_subset = global_df[global_df['ClusterID'].astype(str).isin(str_ids)].copy()

    if df_subset.empty:
        logging.warning("No data found for the provided original cluster IDs.")
        return jsonify({"id": "empty_root_no_data", "dist": 0, "no_tree": True, "error": "No data found for the provided cluster IDs."})

    # Generate a new tree from this subset. We pass `is_subtree=True` to signal
    # that we should use the existing 'ClusterID' column for leaf nodes.
    subtree_dict = generate_tree_from_df(df_subset, is_subtree=True)
    
    return jsonify(subtree_dict)

@app.route('/louvain_ip_graph_data', methods=['GET'])
def louvain_ip_graph_data():
    global global_df, attacking_sources_cache 
    if global_df is None or global_df.empty:
        logging.warning("/louvain_ip_graph_data called but global_df is None.")
        return jsonify({"nodes": [], "edges": [], "error": "No data loaded"}), 400

    df_for_graph = global_df.copy()
    # Ensure critical columns are strings and handle NaNs
    df_for_graph['Source'] = df_for_graph['Source'].astype(str).str.strip().replace(['nan', 'NaN', ''], 'Unknown_IP')
    df_for_graph['Destination'] = df_for_graph['Destination'].astype(str).str.strip().replace(['nan', 'NaN', ''], 'Unknown_IP')
    df_for_graph['Length'] = pd.to_numeric(df_for_graph['Length'], errors='coerce').fillna(0)
    
    if 'Time' not in df_for_graph.columns: df_for_graph['Time'] = 0 
    if 'Anomaly' not in df_for_graph.columns:
        logging.warning("'Anomaly' column missing in df_for_graph. Defaulting to 'normal'.")
        df_for_graph['Anomaly'] = 'normal'
    else: # Ensure Anomaly is string
        df_for_graph['Anomaly'] = df_for_graph['Anomaly'].astype(str)


    # --- Louvain Community Detection for IP Graph ---
    # We need Source, Destination, and optionally processCount for clustering
    cols_for_ip_louvain = ['Source', 'Destination']
    if 'processCount' in df_for_graph.columns:
        cols_for_ip_louvain.append('processCount')
    
    df_for_louvain_clustering_ip_graph = df_for_graph[cols_for_ip_louvain].copy()
    # compute_clusters expects 'Source' and 'Destination'
    ip_to_louvain_community_map = compute_clusters(df_for_louvain_clustering_ip_graph, resolution=2.5)


    all_ips_involved_series = pd.concat([df_for_graph['Source'], df_for_graph['Destination']]).unique()
    all_ips_involved = [ip for ip in all_ips_involved_series if ip and pd.notna(ip) and str(ip).strip() and str(ip).strip() != 'Unknown_IP']

    if not all_ips_involved:
        logging.warning("No valid IPs for IP graph.")
        return jsonify({"nodes": [], "edges": [], "error": "No IP data to process."}), 200

    # Map communities to their anomaly status
    louvain_community_to_ips = {}
    for ip_str, comm_id_str in ip_to_louvain_community_map.items():
        comm_id_str = str(comm_id_str) # Ensure string
        if comm_id_str not in louvain_community_to_ips:
            louvain_community_to_ips[comm_id_str] = set()
        louvain_community_to_ips[comm_id_str].add(str(ip_str))

    louvain_community_anomaly_status = {comm_id: False for comm_id in louvain_community_to_ips.keys()}
    # Anomalous sources are IPs directly marked as source of 'anomaly' rows in df_for_graph
    anomalous_source_ips_in_df = set(df_for_graph[df_for_graph['Anomaly'] == 'anomaly']['Source'].astype(str))
    
    for comm_id, ips_in_comm_set in louvain_community_to_ips.items():
        if not anomalous_source_ips_in_df.isdisjoint(ips_in_comm_set):
             louvain_community_anomaly_status[comm_id] = True

    # Color mapping for communities
    unique_community_ids = sorted([uid_str for uid_str in list(set(ip_to_louvain_community_map.values())) if uid_str != 'N/A' and not uid_str.startswith('N/A_')])
    color_palette = ["#e6194B", "#3cb44b", "#ffe119", "#4363d8", "#f58231", "#911eb4", "#46f0f0", "#f032e6", "#bcf60c", "#fabebe", "#008080", "#e6beff", "#9A6324", "#fffac8", "#800000", "#aaffc3", "#808000", "#ffd8b1", "#000075", "#808080"]
    community_id_to_color = {comm_id_str: color_palette[i % len(color_palette)] for i, comm_id_str in enumerate(unique_community_ids)}
    community_id_to_color['N/A'] = '#CCCCCC' # Default for N/A or unclassified communities


    # --- Feature Extraction for PCA/Layout ---
    ip_features_dict = {
        ip_val: {'outgoing_packet_count': 0, 'incoming_packet_count': 0, 
                 'outgoing_length': 0, 'incoming_length': 0, 
                 'distinct_dest_contacted': 0, 'distinct_sources_contacted_by': 0,
                 'is_source_sessions': 0, 'is_dest_sessions': 0} 
        for ip_val in all_ips_involved
    }
    
    # Aggregate packet counts and lengths for edges
    # Use processCount if available, else count rows
    agg_spec_ip_graph = {'aggregated_total_length': ('Length', 'sum')}
    if 'processCount' in df_for_graph.columns:
        agg_spec_ip_graph['aggregated_packet_count'] = ('processCount', 'sum')
    else:
        agg_spec_ip_graph['aggregated_packet_count'] = ('Time', 'count') # Fallback to row count
        
    edges_df_agg = df_for_graph.groupby(["Source", "Destination"], observed=True).agg(**agg_spec_ip_graph).reset_index()

    for _, row in edges_df_agg.iterrows():
        src, dst = str(row["Source"]), str(row["Destination"])
        pkt_count = int(row["aggregated_packet_count"])
        total_len = float(row["aggregated_total_length"])
        if src in ip_features_dict: 
            ip_features_dict[src]['outgoing_packet_count'] += pkt_count
            ip_features_dict[src]['outgoing_length'] += total_len
            ip_features_dict[src]['is_source_sessions'] += 1 # Count unique dests contacted
        if dst in ip_features_dict: 
            ip_features_dict[dst]['incoming_packet_count'] += pkt_count
            ip_features_dict[dst]['incoming_length'] += total_len
            ip_features_dict[dst]['is_dest_sessions'] += 1 # Count unique sources contacted by

    # Distinct destinations contacted by each source
    source_to_dest_counts = df_for_graph.groupby('Source', observed=True)['Destination'].nunique()
    # Distinct sources that contacted each destination
    dest_to_source_counts = df_for_graph.groupby('Destination', observed=True)['Source'].nunique()
    
    for ip_val_str in all_ips_involved:
        if ip_val_str in source_to_dest_counts: ip_features_dict[ip_val_str]['distinct_dest_contacted'] = source_to_dest_counts[ip_val_str]
        if ip_val_str in dest_to_source_counts: ip_features_dict[ip_val_str]['distinct_sources_contacted_by'] = dest_to_source_counts[ip_val_str]

    # --- PCA for Layout ---
    feature_matrix_list, ordered_ips_for_matrix = [], []
    # Filter out Unknown_IP before PCA if it was a placeholder
    valid_ips_for_pca = [ip for ip in all_ips_involved if ip in ip_features_dict and ip != 'Unknown_IP']

    if not valid_ips_for_pca: 
        logging.warning("No valid IPs with features for PCA in IP graph.")
        # Handle by creating random positions or returning empty graph
        nodes_list_pca_fallback = []
        for ip_str_val in all_ips_involved: # Still create nodes, just random pos
            louvain_id_str = str(ip_to_louvain_community_map.get(ip_str_val, 'N/A'))
            node_clr_pca = community_id_to_color.get(louvain_id_str, community_id_to_color.get('N/A_Isolated', '#CCCCCC')) # Fallback color
            is_comm_anom = louvain_community_anomaly_status.get(louvain_id_str, False)
            classification_pca = classify_ip_vector(ip_str_val)
            pos_x_pca = np.random.uniform(-200, 200)
            pos_y_pca = np.random.uniform(-200, 200)
            raw_features_pca = ip_features_dict.get(ip_str_val, {})
            total_pkt_count_pca = raw_features_pca.get('outgoing_packet_count',0) + raw_features_pca.get('incoming_packet_count',0)

            nodes_list_pca_fallback.append({
                "data": { "id": ip_str_val, "label": ip_str_val, "clusterId": louvain_id_str,
                          "classification": classification_pca, "packet_count": int(total_pkt_count_pca),
                          "node_color": node_clr_pca, "is_community_anomalous": is_comm_anom,
                          "is_attacker": ip_str_val in attacking_sources_cache,
                          "x_original": pos_x_pca, "y_original": pos_y_pca,
                          "features_for_pca": {k: int(v) for k,v in raw_features_pca.items()}
                        },
                "position": {"x": pos_x_pca, "y": pos_y_pca}
            })
        # Edges still need to be built even if PCA fails
        edges_list_pca_fallback = []
        valid_ips_for_edges = set(all_ips_involved) # Use all_ips_involved for edges
        for _, row_edge in edges_df_agg.iterrows():
            src_edge, dst_edge = str(row_edge["Source"]), str(row_edge["Destination"])
            if src_edge in valid_ips_for_edges and dst_edge in valid_ips_for_edges and src_edge != 'Unknown_IP' and dst_edge != 'Unknown_IP':
                edges_list_pca_fallback.append({
                    "data": { "id": f"edge_{src_edge}_{dst_edge}_{np.random.randint(100000)}", "source": src_edge, "target": dst_edge,
                              "packet_count": int(row_edge["aggregated_packet_count"]), "total_length": float(row_edge["aggregated_total_length"]) }})
        return jsonify({"nodes": nodes_list_pca_fallback, "edges": edges_list_pca_fallback})


    ordered_ips_for_matrix = valid_ips_for_pca # Use the filtered list
    for ip_val_str_pca in ordered_ips_for_matrix:
        f_pca = ip_features_dict[ip_val_str_pca]
        feature_matrix_list.append([
            f_pca['outgoing_packet_count'], f_pca['incoming_packet_count'], 
            f_pca['outgoing_length'], f_pca['incoming_length'],
            f_pca['distinct_dest_contacted'], f_pca['distinct_sources_contacted_by'],
            f_pca['is_source_sessions'], f_pca['is_dest_sessions']
        ])

    ip_to_coords = {}
    coords_2d = None
    scaling_factor = 150 # Adjust for spread
    random_fallback_scaling = 250

    if feature_matrix_list:
        feature_matrix = np.array(feature_matrix_list)
        if feature_matrix.shape[0] > 0: # At least one IP to process
            scaler = StandardScaler(); scaled_features = scaler.fit_transform(feature_matrix)
            if scaled_features.shape[0] >= 2 and scaled_features.shape[1] >= 2: # Need at least 2 samples, 2 features for PCA
                pca = PCA(n_components=2, random_state=42)
                coords_2d = pca.fit_transform(scaled_features)
            elif scaled_features.shape[0] >= 1 and scaled_features.shape[1] == 1: # Only 1 feature after scaling (or only 1 input feature)
                 coords_2d = np.hstack([scaled_features, np.zeros_like(scaled_features)]) # Use feature as X, Y=0
            else: # Not enough samples or features
                logging.warning(f"PCA: Not enough data for PCA (Samples: {scaled_features.shape[0]}, Features: {scaled_features.shape[1]}). Using random positions.")
                coords_2d = np.random.rand(scaled_features.shape[0] if scaled_features.shape[0] > 0 else len(ordered_ips_for_matrix), 2) * random_fallback_scaling
            
            if coords_2d is not None: 
                coords_2d = coords_2d * scaling_factor
                # Ensure coords are finite
                coords_2d = np.nan_to_num(coords_2d, nan=0.0, posinf=random_fallback_scaling, neginf=-random_fallback_scaling)
                ip_to_coords = {ip_str_val: coords_2d[i] for i, ip_str_val in enumerate(ordered_ips_for_matrix)}
    else: # Fallback if feature_matrix_list is empty (e.g. only 'Unknown_IP's)
        logging.warning("PCA: Empty feature matrix. Using random positions for all_ips_involved.");
        temp_coords_rand = np.random.rand(len(all_ips_involved), 2) * random_fallback_scaling
        ip_to_coords = {ip_str_val: temp_coords_rand[i] for i, ip_str_val in enumerate(all_ips_involved)}


    # --- Build Nodes and Edges for Cytoscape ---
    nodes_list = []
    for ip_str_node in all_ips_involved: # Iterate through ALL ips that should be nodes
        louvain_id_for_node = str(ip_to_louvain_community_map.get(ip_str_node, 'N/A_Unmapped'))
        node_color_for_node = community_id_to_color.get(louvain_id_for_node, community_id_to_color.get('N/A', '#CCCCCC'))
        is_community_anomalous_node = louvain_community_anomaly_status.get(louvain_id_for_node, False)
        classification_node = classify_ip_vector(ip_str_node)
        
        # Get coordinates, default to random if IP wasn't in PCA (e.g. Unknown_IP or only one)
        raw_coords_node = ip_to_coords.get(ip_str_node, np.array([np.random.uniform(-random_fallback_scaling, random_fallback_scaling), 
                                                                 np.random.uniform(-random_fallback_scaling, random_fallback_scaling)]))
        
        pos_x_node = float(raw_coords_node[0]) if pd.notna(raw_coords_node[0]) and np.isfinite(raw_coords_node[0]) else 0.0
        pos_y_node = float(raw_coords_node[1]) if pd.notna(raw_coords_node[1]) and np.isfinite(raw_coords_node[1]) else 0.0

        raw_features_node = ip_features_dict.get(ip_str_node, {}) # Get features for this IP
        total_packet_count_node = raw_features_node.get('outgoing_packet_count', 0) + raw_features_node.get('incoming_packet_count', 0)

        nodes_list.append({
            "data": { "id": ip_str_node, "label": ip_str_node, "clusterId": louvain_id_for_node,
                      "classification": classification_node, "packet_count": int(total_packet_count_node),
                      "node_color": node_color_for_node, "is_community_anomalous": is_community_anomalous_node,
                      "is_attacker": ip_str_node in attacking_sources_cache,
                      "x_original": pos_x_node, "y_original": pos_y_node, # Store original PCA/random coords
                      "features_for_pca": {k_feat: int(v_feat) for k_feat,v_feat in raw_features_node.items()} # All features
                    },
            "position": {"x": pos_x_node, "y": pos_y_node} # For preset layout
        })

    edges_list = []
    # Use all_ips_involved for edges to ensure Unknown_IPs can connect if they are in data
    valid_ips_for_edges_set = set(all_ips_involved) 
    for _, row_edge_final in edges_df_agg.iterrows():
        src_final, dst_final = str(row_edge_final["Source"]), str(row_edge_final["Destination"])
        # Only add edges if both source and target are in our node list (all_ips_involved)
        if src_final in valid_ips_for_edges_set and dst_final in valid_ips_for_edges_set:
            edges_list.append({
                "data": { "id": f"edge_{src_final}_{dst_final}_{np.random.randint(1000000)}", # Ensure highly unique edge ID
                          "source": src_final, "target": dst_final,
                          "packet_count": int(row_edge_final["aggregated_packet_count"]), 
                          "total_length": float(row_edge_final["aggregated_total_length"]) }})

    logging.info(f"/louvain_ip_graph_data: Returning Nodes: {len(nodes_list)}, Edges: {len(edges_list)}")
    return jsonify({"nodes": nodes_list, "edges": edges_list})


@app.route('/cluster_network', methods=['GET'])
def cluster_network():
    global global_df, attacking_sources_cache
    if global_df is None or global_df.empty:
        logging.error("/cluster_network called but global_df is None or empty.")
        return jsonify({"nodes": [], "edges": [], "error": "No data loaded"}), 500

    cluster_id_param = request.args.get("cluster_id")
    logging.info(f"Processing /cluster_network for cluster_id: {cluster_id_param}")

    if not cluster_id_param:
        logging.error("/cluster_network called without cluster_id.")
        return jsonify({"nodes": [], "edges": [], "error": "cluster_id parameter is missing"}), 400
    
    # Convert param to string to match DataFrame's ClusterID type (category of strings)
    str_cluster_id_param = str(cluster_id_param)

    try:
        # Ensure required columns exist in global_df
        required_cols_for_cluster_net = ["Source", "Destination", "Protocol", "ClusterID", 
                                         "NodeWeight", "SourceClassification", "DestinationClassification", 
                                         "AttackType", "Length", "processCount"]
        for col_check in required_cols_for_cluster_net:
            if col_check not in global_df.columns:
                logging.warning(f"Column '{col_check}' missing in global_df for /cluster_network. Results may be incomplete.")
                # Optionally, add missing columns with default values to prevent crashes
                if col_check == "NodeWeight": global_df[col_check] = 0.5
                elif col_check == "AttackType": global_df[col_check] = "N/A"
                # Add others as needed

        # Filter for the specific cluster. Ensure ClusterID in global_df is also string for comparison.
        df_cluster = global_df[global_df["ClusterID"].astype(str) == str_cluster_id_param].copy()
        logging.info(f"df_cluster for {str_cluster_id_param} shape: {df_cluster.shape}")
        
        if df_cluster.empty:
            logging.warning(f"df_cluster is empty for cluster_id: {str_cluster_id_param}. Returning empty network.")
            return jsonify({"nodes": [], "edges": []})

        # --- Prepare Node and Edge Data for Cytoscape ---
        # Clean and type-cast columns for the cluster subset
        df_cluster["Source"] = df_cluster["Source"].astype(str).str.strip()
        df_cluster["Destination"] = df_cluster["Destination"].astype(str).str.strip()
        df_cluster["Protocol"] = df_cluster["Protocol"].astype(str).str.strip()
        if 'NodeWeight' in df_cluster.columns:
            df_cluster["NodeWeight"] = pd.to_numeric(df_cluster['NodeWeight'], errors='coerce').fillna(0.5)
        else: df_cluster["NodeWeight"] = 0.5
        if 'processCount' not in df_cluster.columns: df_cluster['processCount'] = 1
        else: df_cluster['processCount'] = pd.to_numeric(df_cluster['processCount'], errors='coerce').fillna(1).astype(int)


        # Unique IPs in this specific cluster
        all_ips_in_cluster_series = pd.concat([df_cluster["Source"], df_cluster["Destination"]]).unique()
        # Filter out "nan" strings or truly empty strings that might have come fromastype(str)
        all_ips_in_cluster = [str(ip).strip() for ip in all_ips_in_cluster_series 
                              if pd.notna(ip) and str(ip).strip() and str(ip).strip().lower() != 'nan']


        # Aggregate features for nodes within this cluster
        node_data_agg = {}
        for ip_node_str in all_ips_in_cluster:
            is_source_df = df_cluster[df_cluster["Source"] == ip_node_str]
            is_dest_df = df_cluster[df_cluster["Destination"] == ip_node_str]
            
            # Combine weights if IP appears as both source and dest
            weights_series = pd.concat([
                is_source_df.get("NodeWeight", pd.Series(dtype=float)), 
                is_dest_df.get("NodeWeight", pd.Series(dtype=float))
            ]).dropna()
            avg_weight = weights_series.mean() if not weights_series.empty else 0.5

            # Combine packet counts
            packet_count_val = is_source_df.get('processCount', pd.Series(dtype=int)).sum() + \
                   is_dest_df.get('processCount', pd.Series(dtype=int)).sum()
            
            # Determine classification (take first non-"External" or default to External)
            classifications = pd.concat([
                is_source_df.get("SourceClassification", pd.Series(dtype=str)),
                is_dest_df.get("DestinationClassification", pd.Series(dtype=str)) # Use DestClass if IP is a destination
            ]).unique()
            node_classification = "External" # Default
            for cls in classifications:
                if pd.notna(cls) and str(cls) != "External":
                    node_classification = str(cls)
                    break
            
            # Involved Attack Types
            involved_attack_types = set()
            if "AttackType" in df_cluster.columns:
                src_attacks = is_source_df["AttackType"].astype(str)
                dst_attacks = is_dest_df["AttackType"].astype(str)
                all_row_attacks = pd.concat([src_attacks, dst_attacks])
                unique_node_attacks = all_row_attacks[all_row_attacks.str.upper() != "N/A"].unique()
                involved_attack_types.update(unique_node_attacks)

            node_data_agg[ip_node_str] = {
                "id": ip_node_str, "label": ip_node_str,
                "Classification": node_classification,
                "NodeWeight": avg_weight,
                "packetCount": int(packet_count_val),
                "InvolvedAttackTypes": list(involved_attack_types),
                "is_attacker": ip_node_str in attacking_sources_cache
            }

        # Aggregate Edge Data
        # Group by Source, Destination, Protocol for distinct edges
        edge_agg_cols = {'EdgeWeight': ('Length', 'sum')}
        if 'processCount' in df_cluster.columns: # Use processCount for edge packet count
            edge_agg_cols['processCount'] = ('processCount', 'sum')
        else: # Fallback if processCount isn't there
            edge_agg_cols['processCount'] = ('Time', 'count') # Using 'Time' as a dummy col to count rows


        edges_grouped = df_cluster.groupby(["Source", "Destination", "Protocol"], observed=True).agg(**edge_agg_cols).reset_index()

        # Add AttackType to edges
        edge_attack_map = {}
        if "AttackType" in df_cluster.columns:
            for _, row in df_cluster.iterrows():
                edge_key = (row["Source"], row["Destination"], row["Protocol"])
                attack = str(row["AttackType"])
                if attack.upper() != "N/A":
                    if edge_key not in edge_attack_map: edge_attack_map[edge_key] = set()
                    edge_attack_map[edge_key].add(attack)
        
        edges_cytoscape_list = []
        for _, edge_row in edges_grouped.iterrows():
            edge_key_tuple = (edge_row["Source"], edge_row["Destination"], edge_row["Protocol"])
            edge_attacks = list(edge_attack_map.get(edge_key_tuple, {"N/A"})) # Default to N/A if no specific attacks

            edges_cytoscape_list.append({
                "data": {
                    "id": f"edge-{edge_row['Source']}-{edge_row['Destination']}-{edge_row['Protocol']}-{np.random.randint(100000)}",
                    "source": edge_row["Source"], "target": edge_row["Destination"], 
                    "Protocol": edge_row["Protocol"],
                    "EdgeWeight": float(edge_row["EdgeWeight"]), 
                    "processCount": int(edge_row["processCount"]),
                    "AttackType": edge_attacks[0] if edge_attacks else "N/A" # Show first attack type for simplicity
                }
            })
        
        final_nodes_list_cluster = [{"data": node_info} for node_info in node_data_agg.values()]
        network_data = {"nodes": final_nodes_list_cluster, "edges": edges_cytoscape_list}

        logging.info(f"Prepared network data for cluster {str_cluster_id_param}. Nodes: {len(final_nodes_list_cluster)}, Edges: {len(edges_cytoscape_list)}")
        # convert_nan_to_none is essential for JSON serialization if NaNs are present
        return jsonify(convert_nan_to_none(network_data)) 

    except Exception as e:
        logging.exception(f"Critical error in /cluster_network for cluster_id {str_cluster_id_param}:")
        return jsonify({"nodes": [], "edges": [], "error": f"Server error processing cluster {str_cluster_id_param}: {str(e)}"}), 500

@app.route('/timeline_data', methods=['GET'])
def timeline_data():
    """
    Provides data aggregated over time for the timeline brush visualization.
    """
    global global_df
    if global_df is None or global_df.empty:
        logging.warning("/timeline_data called but global_df is None or empty.")
        return jsonify([])

    df_time = global_df.copy()

    # The global_df has 'Time' as its index. We must work with the index directly.
    if not isinstance(df_time.index, pd.DatetimeIndex) or df_time.index.empty:
        logging.warning("Timeline data requested, but DataFrame index is not a DatetimeIndex or is empty.")
        return jsonify([])
        
    df_time.index.name = 'Time' # Ensure the index has a name
    
    # Use processCount for value if it exists, otherwise count rows
    value_col = 'processCount' if 'processCount' in df_time.columns else None

    # Determine a suitable resampling frequency based on total duration
    duration_seconds = (df_time.index.max() - df_time.index.min()).total_seconds()
    if duration_seconds <= 120:      # up to 2 minutes
        freq = '1S'          # 1 Second bins
    elif duration_seconds <= 7200:   # up to 2 hours
        freq = '15S'         # 15 Second bins
    elif duration_seconds <= 172800: # up to 2 days
        freq = '1Min'        # 1 Minute bins
    else:                    # more than 2 days
        freq = '5Min'        # 5 Minute bins

    # Resample directly on the DatetimeIndex.
    if value_col:
        time_series = df_time.resample(freq)[value_col].sum()
    else:
        time_series = df_time.resample(freq).size()
    
    # Convert to JSON format expected by D3
    timeline_json = [
        {"time": ts.isoformat(), "value": int(val)}
        for ts, val in time_series.items()
    ]
    return jsonify(timeline_json)

@app.route('/get_cluster_rows', methods=['GET'])
def get_cluster_rows():
    global global_df
    if global_df is None or global_df.empty:
        return jsonify({"rows": [], "total": 0, "error": "No data loaded."}) # Added error message
    
    cluster_id_param = request.args.get("cluster_id")
    if not cluster_id_param:
        return jsonify({"rows": [], "total": 0, "error": "cluster_id parameter is missing."})

    try:
        page = int(request.args.get("page", 1))
        page_size = int(request.args.get("page_size", 50)) # Consistent with HTML
        if page < 1: page = 1
        if page_size < 1: page_size = 50
    except ValueError:
        return jsonify({"rows": [], "total": 0, "error": "Invalid page or page_size parameter."})

    # Filter for the specific cluster
    df_cluster = global_df[global_df["ClusterID"].astype(str) == str(cluster_id_param)]
    total_rows_in_cluster = len(df_cluster)
    
    start_index = (page - 1) * page_size
    end_index = start_index + page_size
    
    # Select rows for the current page
    # Use .iloc for positional indexing after filtering
    paginated_rows_df = df_cluster.iloc[start_index:end_index]
    
    # Convert to dictionary records, replacing NaT/NaN with None for JSON
    # Also handle Pandas NA (for Int64 nullable types)
    rows_for_json = []
    for _, row_series in paginated_rows_df.iterrows():
        record = {}
        for col_name, val in row_series.items():
            if pd.isna(val): # Catches pd.NaT, np.nan, pd.NA
                record[col_name] = None
            elif isinstance(val, pd.Timestamp): # Ensure timestamps are ISO format strings
                 record[col_name] = val.isoformat()
            else:
                record[col_name] = val
        rows_for_json.append(record)
        
    return jsonify({"rows": rows_for_json, "total": total_rows_in_cluster})


@app.route('/get_cluster_table', methods=['GET'])
def get_cluster_table():
    global global_df
    if global_df is None or global_df.empty:
        return jsonify({"rows": [], "total": 0, "error": "No data available."}), 404

    cluster_id_param = request.args.get("cluster_id")
    if not cluster_id_param:
        return jsonify({"rows": [], "total": 0, "error": "cluster_id parameter is missing."}), 400

    try:
        page = int(request.args.get("page", 1))
        page_size = int(request.args.get("page_size", 30))
        search_query = request.args.get("search", "").strip().lower()
    except (ValueError, TypeError):
        return jsonify({"rows": [], "total": 0, "error": "Invalid parameters."}), 400

    df_cluster = global_df[global_df["ClusterID"].astype(str) == str(cluster_id_param)].copy()

    # --- UPDATED: Expanded column list for display ---
    display_cols = ['No.', 'Time', 'Source', 'SourcePort', 'Destination', 'DestinationPort', 'Protocol', 'Length', 'Flags', 'processCount', 'InterArrivalTime', 'BytesPerSecond', 'AttackType']
    cols_to_search = display_cols  # Search the columns that are being displayed

    if search_query and not df_cluster.empty:
        search_series = pd.Series([''] * len(df_cluster), index=df_cluster.index, dtype=str)
        for col in cols_to_search:
            if col in df_cluster.columns:
                search_series += df_cluster[col].astype(str).str.lower() + ' '
        
        df_cluster = df_cluster[search_series.str.contains(search_query, na=False)]

    total = len(df_cluster)
    start = (page - 1) * page_size
    end = start + page_size

    final_cols = [col for col in display_cols if col in df_cluster.columns]
    paginated_df = df_cluster[final_cols].iloc[start:end]

    rows_for_json = []
    for _, row_series in paginated_df.iterrows():
        record = {}
        for col_name, val in row_series.items():
            if pd.isna(val):
                record[col_name] = ""
            elif isinstance(val, pd.Timestamp):
                record[col_name] = val.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            else:
                record[col_name] = val
        rows_for_json.append(record)

    return jsonify({"rows": rows_for_json, "total": total})

@app.route('/sankey_data', methods=['GET'])
def sankey_data():
    global global_df
    if global_df is None or global_df.empty:
        return jsonify({"nodes": [], "links": [], "error": "No data loaded"}), 400

    # Apply time filter from GET request args
    df_sankey = apply_time_filter(global_df.copy(), request)

    if df_sankey.empty:
        logging.warning("DataFrame is empty after time filter in /sankey_data.")
        return jsonify({"nodes": [], "links": []})

    dimensions_str = request.args.get('dimensions', 'Protocol,SourceClassification')
    dimensions_keys = [d.strip() for d in dimensions_str.split(',') if d.strip()]

    if not dimensions_keys or len(dimensions_keys) < 2:
        return jsonify({"nodes": [], "links": [], "error": "At least two dimensions are required"}), 400

    for k_dim_check in range(len(dimensions_keys) - 1):
        if dimensions_keys[k_dim_check] == dimensions_keys[k_dim_check + 1]:
            return jsonify({"nodes": [], "links": [], "error": f"Consecutive Sankey dimensions cannot be the same: {dimensions_keys[k_dim_check]}"}), 400

    for key in dimensions_keys:
        if key not in df_sankey.columns:
            logging.error(f"Sankey dimension key '{key}' not found in DataFrame columns.")
            return jsonify({"nodes": [], "links": [], "error": f"Dimension '{key}' not found"}), 400

    value_col = 'processCount' if 'processCount' in df_sankey.columns else None

    if value_col:
        grouped_df = df_sankey.groupby(dimensions_keys, observed=True)[value_col].sum().reset_index(name='value')
    else:
        grouped_df = df_sankey.groupby(dimensions_keys, observed=True).size().reset_index(name='value')

    if grouped_df.empty:
        return jsonify({"nodes": [], "links": []})

    key_to_label_map = {
        "Protocol": "Protocol", "SourceClassification": "Source Type", "DestinationClassification": "Dest. Type",
        "SourcePort_Group": "Src Port Grp", "DestinationPort_Group": "Dst Port Grp", "Len_Group": "Pkt Len Grp",
        "Anomaly": "Anomaly", "ClusterID": "Cluster ID"
    }
    
    links_agg = {}
    
    for _, row in grouped_df.iterrows():
        path_value = row['value']
        for i in range(len(dimensions_keys) - 1):
            source_key = dimensions_keys[i]
            target_key = dimensions_keys[i+1]
            
            source_val = row[source_key]
            target_val = row[target_key]

            source_label = key_to_label_map.get(source_key, source_key)
            target_label = key_to_label_map.get(target_key, target_key)

            source_name = f"{source_label}: {source_val}"
            target_name = f"{target_label}: {target_val}"
            
            link_tuple = (source_name, target_name)
            links_agg[link_tuple] = links_agg.get(link_tuple, 0) + path_value

    nodes_map = {}
    nodes_list = []
    links_list = []

    for (source_name, target_name), value in links_agg.items():
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

@app.route('/protocol_percentages', methods=['GET'])
def protocol_percentages():
    global global_df
    if global_df is None or global_df.empty:
        logging.warning("/protocol_percentages: global_df is None or empty")
        return jsonify({})

    df_proto = global_df.copy() # Work on a copy

    if 'Protocol' not in df_proto.columns:
        logging.warning("/protocol_percentages: 'Protocol' column not found.")
        return jsonify({})

    df_proto['Protocol'] = df_proto['Protocol'].astype(str).fillna('').str.strip()
    
    # Use processCount for weighting if available, otherwise count rows
    if 'processCount' in df_proto.columns:
        df_proto['processCount'] = pd.to_numeric(df_proto['processCount'], errors='coerce').fillna(1)
        protocol_counts = df_proto.groupby('Protocol', observed=True)['processCount'].sum()
    else:
        protocol_counts = df_proto.groupby('Protocol', observed=True).size()
        
    total_proto_sum = protocol_counts.sum()
    
    if total_proto_sum == 0:
        logging.warning("/protocol_percentages: total protocol sum is 0.")
        return jsonify({})
        
    percentages = {
        proto_name: round((count_val / total_proto_sum) * 100, 5)
        for proto_name, count_val in protocol_counts.items() 
        if proto_name # Ensure protocol name is not empty string
    }
    
    logging.info(f"/protocol_percentages: returning percentages: {percentages}")
    return jsonify(percentages)


@app.route('/time_info', methods=['GET'])
def get_time_info():
    global global_start_time, global_end_time, global_duration_seconds, global_backend_csv_processing_time_seconds
    if global_df is None: # Check if data has been processed
         return jsonify({"error": "No data has been processed yet."}), 404
    
    return jsonify({
        "start_time": global_start_time, # Should be ISO string
        "end_time": global_end_time,     # Should be ISO string
        "duration_seconds": global_duration_seconds,
        "backend_processing_time_seconds": global_backend_csv_processing_time_seconds # Renamed key for clarity
    })


@app.route('/download_processed_data', methods=['GET']) # Renamed endpoint
def download_processed_data():
    global global_df
    if global_df is None or global_df.empty:
        return jsonify({"error": "No processed data available to download."}), 400
    
    # Output as CSV for user convenience
    csv_io = StringIO()
    try:
        # Handle potential NaT in Time column for CSV conversion
        df_to_download = global_df.copy()
        if 'Time' in df_to_download.columns and pd.api.types.is_datetime64_any_dtype(df_to_download['Time']):
             # Format datetime to string, handling NaT gracefully
            df_to_download['Time'] = df_to_download['Time'].apply(lambda x: x.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] if pd.notna(x) else '')
        
        df_to_download.to_csv(csv_io, index=False, quoting=csv.QUOTE_MINIMAL)
        csv_io.seek(0)
        return Response(
            csv_io.getvalue(), 
            mimetype='text/csv', 
            headers={'Content-Disposition': 'attachment;filename=processed_data.csv'}
        )
    except Exception as e:
        logging.error(f"Error generating CSV for download: {e}", exc_info=True)
        return jsonify({"error": "Failed to generate CSV data for download."}), 500

@app.route('/')
def serve_index():
    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))
    return send_from_directory(frontend_dir, 'MalscapeDev.html')


@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), path)


# --- Helper for JSONifying DataFrames with NaNs ---
def convert_nan_to_none(obj):
    """Recursively converts np.nan, pd.NaT, pd.NA in dicts/lists to None for JSON."""
    if isinstance(obj, dict):
        return {k: convert_nan_to_none(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_nan_to_none(item) for item in obj]
    elif pd.isna(obj): # Handles np.nan, pd.NaT, pd.NA
        return None
    elif isinstance(obj, pd.Timestamp): # Convert timestamps to ISO strings
        return obj.isoformat()
    # Handle specific numpy types that might not be directly JSON serializable
    elif isinstance(obj, (np.integer, np.int_)): return int(obj)
    elif isinstance(obj, np.floating): return float(obj)
    elif isinstance(obj, np.bool_): return bool(obj)
    return obj

# --- Get Edge Table (for sidebar, if needed) ---
# This endpoint might need review if its usage changes significantly
@app.route('/get_edge_table', methods=['GET'])
def get_edge_table():
    global global_df
    if global_df is None or global_df.empty: return "<p>No data available.</p>"

    source = request.args.get("source")
    destination = request.args.get("destination")
    protocol = request.args.get("protocol")
    if not source or not destination or not protocol: return "<p>Missing source, destination, or protocol.</p>"

    try: page = int(request.args.get("page", 1))
    except: page = 1
    try: page_size = int(request.args.get("page_size", 50))
    except: page_size = 50

    df_filtered = global_df[
        (global_df["Source"].astype(str) == str(source)) & 
        (global_df["Destination"].astype(str) == str(destination)) & 
        (global_df["Protocol"].astype(str) == str(protocol))
    ]
    total = len(df_filtered)
    start = (page - 1) * page_size
    end = start + page_size
    
    rows_for_html_edge = []
    for _, row_series in df_filtered.iloc[start:end].iterrows():
        record = {}
        for col_name, val in row_series.items():
            if pd.isna(val): record[col_name] = ""
            elif isinstance(val, pd.Timestamp): record[col_name] = val.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            else: record[col_name] = str(val)
        rows_for_html_edge.append(record)

    if not rows_for_html_edge: return "<p>No rows found for this edge.</p>"
    columns = list(rows_for_html_edge[0].keys())
    # (HTML generation logic as before)
    html = "<table style='width:100%; border-collapse: collapse; border:1px solid #ddd;'>"
    html += "<thead><tr>" + "".join(f"<th style='padding:8px; border:1px solid #ddd; text-align:left;'>{col}</th>" for col in columns) + "</tr></thead><tbody>"
    for row_item_edge in rows_for_html_edge:
        html += "<tr>" + "".join(f"<td style='padding:8px; border:1px solid #ddd;'>{row_item_edge.get(col, '')}</td>" for col in columns) + "</tr>"
    html += "</tbody></table>"
    html += f"<p id='table-summary' data-total='{total}'>Showing rows {start + 1} to {min(end, total)} of {total}.</p>"
    return html

@app.route('/get_multi_edge_table', methods=['POST'])
def get_multi_edge_table():
    global global_df
    if global_df is None or global_df.empty:
        return jsonify({"rows": [], "total": 0, "error": "No data available."}), 404

    try:
        data = request.get_json()
        edges_to_filter = data.get("edges", [])
        page = int(data.get("page", 1))
        page_size = int(data.get("page_size", 30))
        search_query = data.get("search", "").strip().lower()
    except Exception as e_req:
        return jsonify({"rows": [], "total": 0, "error": f"Error parsing request: {str(e_req)}"}), 400

    if not edges_to_filter:
        return jsonify({"rows": [], "total": 0})

    combined_mask = pd.Series([False] * len(global_df), index=global_df.index)
    for edge_filter_item in edges_to_filter:
        try:
            condition = (
                (global_df["Source"].astype(str) == str(edge_filter_item["source"])) &
                (global_df["Destination"].astype(str) == str(edge_filter_item["destination"])) &
                (global_df["Protocol"].astype(str) == str(edge_filter_item["protocol"]))
            )
            combined_mask |= condition
        except KeyError:
            continue

    filtered_df = global_df[combined_mask].copy()
    
    # --- UPDATED: Expanded column list for display ---
    display_cols = ['No.', 'Time', 'Source', 'SourcePort', 'Destination', 'DestinationPort', 'Protocol', 'Length', 'Flags', 'processCount', 'InterArrivalTime', 'BytesPerSecond', 'AttackType']
    cols_to_search = display_cols # Search the columns that are being displayed

    if search_query and not filtered_df.empty:
        search_series = pd.Series([''] * len(filtered_df), index=filtered_df.index, dtype=str)
        for col in cols_to_search:
            if col in filtered_df.columns:
                 search_series += filtered_df[col].astype(str).str.lower() + ' '
        
        filtered_df = filtered_df[search_series.str.contains(search_query, na=False)]

    total = len(filtered_df)
    start = (page - 1) * page_size
    end = start + page_size

    final_cols = [col for col in display_cols if col in filtered_df.columns]
    paginated_df = filtered_df[final_cols].iloc[start:end]

    rows_for_json = []
    for _, row_series in paginated_df.iterrows():
        record = {}
        for col_name, val in row_series.items():
            if pd.isna(val):
                record[col_name] = ""
            elif isinstance(val, pd.Timestamp):
                record[col_name] = val.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            else:
                record[col_name] = val
        rows_for_json.append(record)

    return jsonify({"rows": rows_for_json, "total": total})


# --- Main Execution ---
if __name__ == '__main__':
    # Simplified: Always run as Flask server for this context
    # The CLI mode for app.py might be less relevant if converter.py handles file processing.
    port = int(os.environ.get("PORT", 5000))
    logging.info(f"Starting Flask server (Parquet version) on host 0.0.0.0 port {port}")
    # Consider debug=False for production-like testing
    app.run(debug=True, host='0.0.0.0', port=port)