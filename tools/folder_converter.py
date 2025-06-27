#!/usr/bin/env python3
import os
import re
import lzma
import argparse
import subprocess
import pandas as pd
from datetime import datetime, timedelta
from io import StringIO

# --- Core Helper Functions ---

def aggregate_packets_optimized(df):
    """
    Aggregates identical and consecutive packets that occur within a 1-second window
    using a vectorized pandas approach. This function is identical to the one in pconverter.py.

    Args:
        df (pd.DataFrame): The input DataFrame of packets, expected to be sorted by time.

    Returns:
        pd.DataFrame: A new DataFrame with aggregated packets and a 'processCount' column.
    """
    if df.empty:
        print("Input DataFrame to aggregate_packets is empty.")
        return df.assign(processCount=pd.Series(dtype='int'))

    # The aggregation logic assumes data is sorted by time.
    df = df.sort_values('Time', ignore_index=True)

    # Columns defining a unique packet for aggregation purposes.
    group_cols = ['Source', 'Destination', 'Protocol', 'SourcePort', 'DestinationPort']

    # 1. Identify break points for groups. A new group starts if:
    #    a) The packet's key features are different from the previous one.
    is_different_packet = (df[group_cols].ne(df[group_cols].shift())).any(axis=1)
    
    #    b) The time gap since the previous packet is larger than 1 second.
    is_time_gap = df['Time'].diff() > timedelta(seconds=1)

    # Use cumsum() on the boolean 'break points' to create a unique ID for each consecutive group.
    group_ids = (is_different_packet | is_time_gap).cumsum()

    # 2. Define the aggregation rules for each column.
    agg_rules = {
        'Length': 'sum',
        'Time': 'first',
        'No.': 'first',
        'Source': 'first',
        'Destination': 'first',
        'Protocol': 'first',
        'SourcePort': 'first',
        'DestinationPort': 'first',
        'Flags_temp': 'first',
        'Payload': 'first'
    }

    # 3. Group by the generated IDs and apply the aggregation rules.
    aggregated_df = df.groupby(group_ids).agg(agg_rules)

    # Calculate the count for each group and add it as the 'processCount' column.
    aggregated_df['processCount'] = df.groupby(group_ids).size()
    
    # Reorder columns to match pconverter.py's output.
    cols = df.columns.tolist() + ['processCount']
    if 'Payload' in cols:
        cols.remove('processCount')
        payload_index = cols.index('Payload')
        cols.insert(payload_index, 'processCount')

    print("Packet aggregation successful.")
    return aggregated_df[cols].reset_index(drop=True)


def extract_timestamp_from_filename(filename):
    """
    Extract a timestamp string from the filename.
    The expected format is YYYYMMDDHHMMSS.
    For example: mypcap_20091103082335.pcap.xz
    """
    pattern = r'(\d{14})' # Looks for 14 digits
    match = re.search(pattern, filename)
    if not match:
        print(f"Warning: No YYYYMMDDHHMMSS timestamp in '{filename}'. Will attempt fallback for base_time.")
        return None 
    timestamp_str = match.group(1)
    try:
        base_time = datetime.strptime(timestamp_str, "%Y%m%d%H%M%S")
    except ValueError as e:
        print(f"Warning: Error parsing timestamp '{timestamp_str}' from filename (pattern matched but strptime failed): {e}. Will attempt fallback for base_time.")
        return None
    return base_time

def decompress_file(compressed_file):
    """Decompress a .xz file and write the uncompressed content to a new file."""
    if not compressed_file.endswith('.xz'):
        raise ValueError("The file does not have a .xz extension.")
    
    uncompressed_file = compressed_file[:-3] # Strips '.xz'
    
    if os.path.exists(uncompressed_file) and os.path.getmtime(uncompressed_file) >= os.path.getmtime(compressed_file):
        print(f"Using existing and up-to-date uncompressed file: {uncompressed_file}")
        return uncompressed_file
        
    print(f"Decompressing {compressed_file} to {uncompressed_file} ...")
    
    try:
        with lzma.open(compressed_file, 'rb') as fin, open(uncompressed_file, 'wb') as fout:
            chunk_size = 1024 * 1024  # 1 MB
            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                fout.write(chunk)
    except Exception as e:
        raise RuntimeError(f"Error decompressing file {compressed_file}: {e}")
    
    print("Decompression complete.")
    return uncompressed_file

def pcap_to_dataframe(pcap_file, base_time_from_filename):
    """
    Uses tshark to convert pcap data to a Pandas DataFrame.
    This function is now aligned with pconverter.py for identical output.
    """
    print(f"Converting {pcap_file} to DataFrame using tshark...")
    
    tshark_fields = [
        "-e", "frame.number", "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "udp.srcport", "-e", "tcp.dstport", "-e", "udp.dstport",
        "-e", "_ws.col.protocol", "-e", "frame.len", "-e", "tcp.flags", "-e", "_ws.col.Info"      
    ]
    
    tshark_cmd = [
        "tshark", "-r", pcap_file, "-T", "fields",
        "-E", "header=y", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f",
        *tshark_fields
    ]

    try:
        process = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
        stdout, stderr = process.communicate(timeout=360) 

        if process.returncode != 0:
            raise RuntimeError(f"tshark command failed. Return code: {process.returncode}\nError: {stderr}")
        if not stdout.strip():
            check_pkt_count_cmd = ["capinfos", "-c", pcap_file]
            pkt_count_proc = subprocess.run(check_pkt_count_cmd, capture_output=True, text=True)
            if pkt_count_proc.returncode == 0 and "Number of packets:       0" in pkt_count_proc.stdout:
                 print(f"Warning: The pcap file '{pcap_file}' contains 0 packets. Resulting DataFrame will be empty.")
                 empty_df_cols = ["Time", "No.", "Source", "Destination", "Protocol", "Length", 
                                  "SourcePort", "DestinationPort", "Flags_temp", "Payload"]
                 return pd.DataFrame(columns=empty_df_cols)
            else:
                raise ValueError(f"tshark output is empty for {pcap_file}. It might be corrupted or have no processable packets. stderr: {stderr}")

    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        raise RuntimeError(f"tshark command timed out for {pcap_file}. Stderr: {stderr}")
    except FileNotFoundError:
        raise RuntimeError("tshark (or capinfos) command not found. Please ensure Wireshark/tshark is installed and in your PATH.")
    except Exception as e:
        raise RuntimeError(f"An unexpected error occurred during tshark execution for {pcap_file}: {e}\nStdout: {stdout}\nStderr: {stderr}")

    df = pd.read_csv(StringIO(stdout))

    column_map = {
        "frame.number": "No.", "frame.time_epoch": "TimeEpoch", "ip.src": "Source",
        "ip.dst": "Destination", "_ws.col.protocol": "Protocol", "frame.len": "Length",
        "tcp.flags": "Flags_temp", "_ws.col.Info": "Payload"
    }
    df.rename(columns=column_map, inplace=True)

    df["No."] = pd.to_numeric(df.get("No.", pd.Series(dtype='float')), errors='coerce').fillna(0).astype(int)
    df["TimeEpoch"] = pd.to_numeric(df.get("TimeEpoch", pd.Series(dtype='float')), errors='coerce')
    
    df["Source"] = df.get("Source", pd.Series(dtype='object')).astype(str).fillna("0.0.0.0") 
    df["Destination"] = df.get("Destination", pd.Series(dtype='object')).astype(str).fillna("0.0.0.0")
    df["Protocol"] = df.get("Protocol", pd.Series(dtype='object')).astype(str).fillna("Unknown")
    df["Length"] = pd.to_numeric(df.get("Length", pd.Series(dtype='float')), errors='coerce').fillna(0).astype(int)
    
    # --- CORRECTED PORT HANDLING (from pconverter.py) ---
    tcp_srcport_series = df.get("tcp.srcport")
    udp_srcport_series = df.get("udp.srcport")
    if tcp_srcport_series is not None and udp_srcport_series is not None:
        df["SourcePort"] = tcp_srcport_series.fillna(udp_srcport_series)
    elif tcp_srcport_series is not None:
        df["SourcePort"] = tcp_srcport_series
    elif udp_srcport_series is not None:
        df["SourcePort"] = udp_srcport_series
    else:
        df["SourcePort"] = pd.NA

    tcp_dstport_series = df.get("tcp.dstport")
    udp_dstport_series = df.get("udp.dstport")
    if tcp_dstport_series is not None and udp_dstport_series is not None:
        df["DestinationPort"] = tcp_dstport_series.fillna(udp_dstport_series)
    elif tcp_dstport_series is not None:
        df["DestinationPort"] = tcp_dstport_series
    elif udp_dstport_series is not None:
        df["DestinationPort"] = udp_dstport_series
    else:
        df["DestinationPort"] = pd.NA

    df.drop(columns=[c for c in ["tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport"] if c in df.columns], inplace=True)
    
    df["SourcePort"] = pd.to_numeric(df.get("SourcePort"), errors='coerce').astype('Int64') 
    df["DestinationPort"] = pd.to_numeric(df.get("DestinationPort"), errors='coerce').astype('Int64')

    if "Flags_temp" not in df.columns: df["Flags_temp"] = 0 
    df["Flags_temp"] = df["Flags_temp"].fillna(0)
    df["Flags_temp"] = df["Flags_temp"].apply(lambda x: int(str(x), 16) if isinstance(x, str) and 'x' in str(x).lower() else x)
    df["Flags_temp"] = pd.to_numeric(df["Flags_temp"], errors='coerce').fillna(0).astype(int)

    df["Payload"] = df.get("Payload", pd.Series(dtype='object')).astype(str).fillna("")

    if df.empty or df["TimeEpoch"].isnull().all():
        df["Time"] = pd.NaT
    else:
        if not isinstance(base_time_from_filename, datetime):
            first_valid_epoch = df["TimeEpoch"].dropna().min()
            base_time_from_filename = datetime.fromtimestamp(first_valid_epoch) if pd.notna(first_valid_epoch) else datetime.now()
        capture_start_epoch = df["TimeEpoch"].dropna().min()
        if pd.notna(capture_start_epoch):
            df["Time"] = df["TimeEpoch"].apply(lambda x: base_time_from_filename + timedelta(seconds=(float(x) - float(capture_start_epoch))) if pd.notna(x) else pd.NaT)
        else:
            df["Time"] = pd.NaT
            
    df.drop(columns=["TimeEpoch"], inplace=True, errors='ignore')
    
    if "Time" in df.columns:
        df.insert(0, "Time", df.pop("Time"))

    # --- CORRECTED FINAL COLUMN SETUP (from pconverter.py) ---
    final_ordered_cols = ["Time", "No.", "Source", "Destination", "Protocol", "Length", "SourcePort", "DestinationPort", "Flags_temp", "Payload"]
    for col in final_ordered_cols:
        if col not in df.columns:
            if col == "Time": df[col] = pd.NaT
            elif col in ["No.", "Length", "Flags_temp"]: df[col] = 0
            elif col in ["SourcePort", "DestinationPort"]: df[col] = pd.NA 
            else: df[col] = "" 
            
    return df[final_ordered_cols]

# --- Main Execution Logic ---

def main():
    parser = argparse.ArgumentParser(
        description="Finds all .pcap.xz files in a target directory, converts them, combines them, "
                    "aggregates the packets, and saves the result as a single Parquet file. "
                    "By default, it targets the 'MalScape-1/parquet/Combine/' directory relative to its own location."
    )
    parser.add_argument(
        "input_folder", 
        nargs='?', 
        default=None,
        help="Path to the folder containing .pcap.xz files. (Optional: Defaults to ../parquet/Combine/)"
    )
    parser.add_argument(
        "-o", "--output_file", 
        help="Path for the final combined Parquet file. (Optional: Defaults to 'combined_aggregated_output.parquet' in the target folder)."
    )
    args = parser.parse_args()

    # --- 1. Determine target directory ---
    if args.input_folder:
        target_folder = args.input_folder
    else:
        script_path = os.path.abspath(__file__)
        tools_dir = os.path.dirname(script_path)
        project_root_dir = os.path.dirname(tools_dir)
        target_folder = os.path.join(project_root_dir, 'parquet', 'Combine')

    print(f"Targeting directory: {target_folder}")
    os.makedirs(target_folder, exist_ok=True)

    # --- 2. Validate input folder and determine output path ---
    if not os.path.isdir(target_folder):
        print(f"Error: Target path '{target_folder}' is not a valid directory.")
        return

    output_file = args.output_file if args.output_file else os.path.join(target_folder, "combined_aggregated_output.parquet")
    print(f"Final output file will be: {output_file}")

    # --- 3. Find all .pcap.xz files ---
    try:
        files_to_process = [f for f in os.listdir(target_folder) if f.endswith(".pcap.xz")]
        files_to_process.sort()
    except FileNotFoundError:
        print(f"Error: The directory '{target_folder}' does not exist.")
        return
        
    if not files_to_process:
        print("No .pcap.xz files found in the target folder.")
        return

    print(f"Found {len(files_to_process)} files to process.")

    # --- 4. Loop through files and process them ---
    all_dataframes = []
    for filename in files_to_process:
        full_filepath = os.path.join(target_folder, filename)
        print(f"\n--- Processing: {filename} ---")
        
        decompressed_temp_file = None
        try:
            base_time = extract_timestamp_from_filename(filename)
            if not base_time:
                 try:
                     base_time = datetime.fromtimestamp(os.path.getmtime(full_filepath))
                     print(f"Using file modification time as base_time: {base_time}")
                 except Exception as e_stat:
                    base_time = datetime.now()
                    print(f"Warning: Could not get file modification time ({e_stat}). Using current time as base_time.")

            decompressed_temp_file = decompress_file(full_filepath)
            df = pcap_to_dataframe(decompressed_temp_file, base_time)
            
            if not df.empty:
                all_dataframes.append(df)
            else:
                print(f"Skipping empty DataFrame from {filename}.")

        except Exception as e:
            print(f"!!! FAILED to process {filename}: {e} !!!")
        finally:
            if decompressed_temp_file and os.path.exists(decompressed_temp_file):
                try:
                    os.remove(decompressed_temp_file)
                    print(f"Removed temporary file: {decompressed_temp_file}")
                except OSError as e_remove:
                    print(f"Warning: Could not remove temporary file {decompressed_temp_file}: {e_remove}")

    # --- 5. Combine, sort, aggregate, and save the final DataFrame ---
    if not all_dataframes:
        print("\nNo data was successfully processed. Combined Parquet file will not be created.")
        return

    print(f"\nCombining {len(all_dataframes)} DataFrames into a single file...")
    combined_df = pd.concat(all_dataframes, ignore_index=True)

    print("Sorting combined data by timestamp...")
    combined_df.sort_values(by='Time', inplace=True, ignore_index=True)
    
    # --- AGGREGATION STEP ---
    print("\nAggregating consecutive packets in the combined data...")
    aggregated_df = aggregate_packets_optimized(combined_df)
    print(f"Aggregation complete. Rows changed from {len(combined_df)} to {len(aggregated_df)}.")
    
    # --- FINAL SAVE ---
    if 'Time' in aggregated_df.columns and pd.api.types.is_datetime64_any_dtype(aggregated_df['Time']):
        if aggregated_df['Time'].dt.tz is not None:
             print("Converting timezone-aware Time column to UTC for standardized Parquet storage.")
             aggregated_df['Time'] = aggregated_df['Time'].dt.tz_convert('UTC')

    print(f"\nSaving aggregated DataFrame with {len(aggregated_df)} rows to '{output_file}'...")
    # Using the exact saving parameters from pconverter.py
    aggregated_df.to_parquet(
        output_file, 
        index=False, 
        engine='pyarrow', 
        allow_truncated_timestamps=False, 
        coerce_timestamps='us'
    )

    print("\n--- Conversion Complete! ---")
    print(f"Successfully processed {len(all_dataframes)} files, aggregated the data, and created '{output_file}'.")


if __name__ == "__main__":
    main()