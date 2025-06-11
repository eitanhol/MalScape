#!/usr/bin/env python3
import os
import re
import lzma
import argparse
import subprocess
import pandas as pd
from datetime import datetime, timedelta
from io import StringIO

def aggregate_packets_optimized(df):
    """
    Aggregates identical and consecutive packets that occur within a 1-second window
    using a vectorized pandas approach.

    Args:
        df (pd.DataFrame): The input DataFrame of packets, expected to be sorted by time.

    Returns:
        pd.DataFrame: A new DataFrame with aggregated packets.
    """
    if df.empty:
        print("Input DataFrame to aggregate_packets is empty.")
        # Return a DataFrame with the expected 'processCount' column
        return df.assign(processCount=pd.Series(dtype='int'))

    # Ensure data is sorted by time for consecutive logic
    df = df.sort_values('Time', ignore_index=True)

    group_cols = ['Source', 'Destination', 'Protocol', 'SourcePort', 'DestinationPort']

    # 1. Identify break points for groups. A new group starts if:
    #    a) The packet is different from the previous one.
    is_different_packet = (df[group_cols].ne(df[group_cols].shift())).any(axis=1)
    
    #    b) The time gap since the previous packet is larger than 1 second.
    #    This is a highly efficient proxy for the original's 'time since group start' logic.
    is_time_gap = df['Time'].diff() > timedelta(seconds=1)

    # Use cumsum() on the boolean 'break points' to create a unique ID for each consecutive group
    group_ids = (is_different_packet | is_time_gap).cumsum()

    # 2. Define the aggregation rules for each column
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

    # 3. Group by the IDs and apply the aggregation rules
    aggregated_df = df.groupby(group_ids).agg(agg_rules)

    # Calculate the count for each group and add it as 'processCount'
    aggregated_df['processCount'] = df.groupby(group_ids).size()
    
    # Reorder columns to match original output, if desired
    cols = df.columns.tolist() + ['processCount']
    # A small reordering to place processCount before the last columns
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
        # Fallback if specific timestamp is not in filename
        print(f"Warning: No YYYYMMDDHHMMSS timestamp in '{filename}'. Will attempt fallback for base_time.")
        return None 
    timestamp_str = match.group(1)
    try:
        base_time = datetime.strptime(timestamp_str, "%Y%m%d%H%M%S")
    except ValueError as e:
        # This case should be less common if the pattern matches, but good to have
        print(f"Warning: Error parsing timestamp '{timestamp_str}' from filename (pattern matched but strptime failed): {e}. Will attempt fallback for base_time.")
        return None
    return base_time

def decompress_file(compressed_file):
    """Decompress a .xz file and write the uncompressed content to a new file."""
    if not compressed_file.endswith('.xz'):
        # This function should only be called for .xz files
        raise ValueError("The file does not have a .xz extension.")
    
    uncompressed_file = compressed_file[:-3] # Strips '.xz'
    
    # Check if uncompressed file already exists and is newer or same age
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
    Uses tshark to convert pcap data to a Pandas DataFrame, processing timestamps
    and other fields into a structure suitable for app.py.
    """
    print(f"Converting {pcap_file} to DataFrame using tshark...")
    
    tshark_fields = [
        "-e", "frame.number",
        "-e", "frame.time_epoch", 
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "udp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "_ws.col.protocol", 
        "-e", "frame.len",        
        "-e", "tcp.flags",        
        "-e", "_ws.col.Info"      
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
        "frame.number": "No.",
        "frame.time_epoch": "TimeEpoch",
        "ip.src": "Source",
        "ip.dst": "Destination",
        "_ws.col.protocol": "Protocol",
        "frame.len": "Length",
        "tcp.flags": "Flags_temp",
        "_ws.col.Info": "Payload"
    }
    df.rename(columns=column_map, inplace=True)

    df["No."] = pd.to_numeric(df.get("No.", pd.Series(dtype='float')), errors='coerce').fillna(0).astype(int)
    df["TimeEpoch"] = pd.to_numeric(df.get("TimeEpoch", pd.Series(dtype='float')), errors='coerce')
    
    df["Source"] = df.get("Source", pd.Series(dtype='object')).astype(str).fillna("0.0.0.0") 
    df["Destination"] = df.get("Destination", pd.Series(dtype='object')).astype(str).fillna("0.0.0.0")
    df["Protocol"] = df.get("Protocol", pd.Series(dtype='object')).astype(str).fillna("Unknown")
    df["Length"] = pd.to_numeric(df.get("Length", pd.Series(dtype='float')), errors='coerce').fillna(0).astype(int)
    
    # --- CORRECTED PORT HANDLING ---
    # Use .get(col_name) which returns None if col_name is not present.
    # Then fillna with the other port column.
    tcp_srcport_series = df.get("tcp.srcport")
    udp_srcport_series = df.get("udp.srcport")

    if tcp_srcport_series is not None and udp_srcport_series is not None:
        df["SourcePort"] = tcp_srcport_series.fillna(udp_srcport_series)
    elif tcp_srcport_series is not None:
        df["SourcePort"] = tcp_srcport_series
    elif udp_srcport_series is not None:
        df["SourcePort"] = udp_srcport_series
    else:
        df["SourcePort"] = pd.NA # Or pd.Series(dtype='float', index=df.index) if old pandas

    tcp_dstport_series = df.get("tcp.dstport")
    udp_dstport_series = df.get("udp.dstport")

    if tcp_dstport_series is not None and udp_dstport_series is not None:
        df["DestinationPort"] = tcp_dstport_series.fillna(udp_dstport_series)
    elif tcp_dstport_series is not None:
        df["DestinationPort"] = tcp_dstport_series
    elif udp_dstport_series is not None:
        df["DestinationPort"] = udp_dstport_series
    else:
        df["DestinationPort"] = pd.NA # Or pd.Series(dtype='float', index=df.index)

    # Drop original port columns if they existed and were processed
    cols_to_drop_after_processing = []
    if "tcp.srcport" in df.columns: cols_to_drop_after_processing.append("tcp.srcport")
    if "udp.srcport" in df.columns: cols_to_drop_after_processing.append("udp.srcport")
    if "tcp.dstport" in df.columns: cols_to_drop_after_processing.append("tcp.dstport")
    if "udp.dstport" in df.columns: cols_to_drop_after_processing.append("udp.dstport")
    if cols_to_drop_after_processing:
        df.drop(columns=cols_to_drop_after_processing, inplace=True)
    # --- END CORRECTED PORT HANDLING ---
    
    df["SourcePort"] = pd.to_numeric(df["SourcePort"], errors='coerce').astype('Int64') 
    df["DestinationPort"] = pd.to_numeric(df["DestinationPort"], errors='coerce').astype('Int64')

    if "Flags_temp" not in df.columns: 
        df["Flags_temp"] = 0 
    df["Flags_temp"] = df["Flags_temp"].fillna(0)
    df["Flags_temp"] = df["Flags_temp"].apply(lambda x: int(str(x), 16) if isinstance(x, str) and 'x' in str(x).lower() else x)
    df["Flags_temp"] = pd.to_numeric(df["Flags_temp"], errors='coerce').fillna(0).astype(int)

    df["Payload"] = df.get("Payload", pd.Series(dtype='object')).astype(str).fillna("")

    if df.empty or df["TimeEpoch"].isnull().all():
        print("Warning: No valid TimeEpoch data found after tshark processing. Timestamps will be NaT.")
        df["Time"] = pd.NaT
    else:
        if not isinstance(base_time_from_filename, datetime):
            print("Warning: Invalid base_time_from_filename passed to pcap_to_dataframe. Using first packet time as base.")
            first_valid_epoch = df["TimeEpoch"].dropna().min()
            if pd.isna(first_valid_epoch):
                 base_time_from_filename = datetime.now() 
                 print("Critical Warning: Could not determine a valid base time. Using current time.")
            else:
                base_time_from_filename = datetime.fromtimestamp(first_valid_epoch)

        capture_start_epoch = df["TimeEpoch"].dropna().min()
        if pd.isna(capture_start_epoch): 
            df["Time"] = pd.NaT
            print("Warning: capture_start_epoch is NA, setting Time to NaT.")
        else:
            df["Time"] = df["TimeEpoch"].apply(
                lambda x: base_time_from_filename + timedelta(seconds=(float(x) - float(capture_start_epoch))) if pd.notna(x) else pd.NaT
            )
            
    if "TimeEpoch" in df.columns:
      df.drop(columns=["TimeEpoch"], inplace=True)
    
    if "Time" in df.columns:
        time_col = df.pop("Time")
        df.insert(0, "Time", time_col)
    else: 
        df.insert(0, "Time", pd.NaT)

    final_ordered_cols = [
        "Time", "No.", "Source", "Destination", "Protocol", "Length", 
        "SourcePort", "DestinationPort", "Flags_temp", "Payload"
    ]
    
    for col in final_ordered_cols:
        if col not in df.columns:
            if col == "Time": df[col] = pd.NaT
            elif col in ["No.", "Length", "Flags_temp"]: df[col] = 0
            elif col in ["SourcePort", "DestinationPort"]: df[col] = pd.NA 
            else: df[col] = "" 

    df = df[final_ordered_cols]

    print(f"DataFrame processed. Rows: {len(df)}. Columns: {df.columns.tolist()}")
    if not df.empty:
        print("Sample of DataFrame (first 3 rows):")
        print(df.head(3))
        print("\nData types:")
        print(df.dtypes)
    return df

def main():
    parser = argparse.ArgumentParser(
        description="Uncompress a .pcap.xz file (if needed), convert it to a Pandas DataFrame via tshark, "
                    "aggregate identical consecutive packets within a 1-second window, and save as a Parquet file. "
                    "Output filename is derived from input filename (e.g., input.pcap.xz -> input.parquet)."
    )
    parser.add_argument("input_file", help="Path to the .pcap or .pcap.xz file")
    args = parser.parse_args()

    input_basename = os.path.basename(args.input_file)
    if input_basename.endswith(".pcap.xz"):
        output_basename = input_basename[:-len(".pcap.xz")] + ".parquet"
    elif input_basename.endswith(".pcap"):
        output_basename = input_basename[:-len(".pcap")] + ".parquet"
    else:
        print("Error: Input file must be a .pcap or .pcap.xz file.")
        return
    
    output_file = os.path.join(os.path.dirname(os.path.abspath(args.input_file)), output_basename)

    pcap_file_to_process = args.input_file
    decompressed_temp_file = None
    base_time = None

    try:
        if args.input_file.endswith('.pcap.xz'):
            print(f"Input is a compressed pcap: {args.input_file}")
            base_time = extract_timestamp_from_filename(input_basename)
            decompressed_temp_file = decompress_file(args.input_file)
            pcap_file_to_process = decompressed_temp_file
        elif args.input_file.endswith('.pcap'):
            print(f"Input is a pcap: {args.input_file}")
            pcap_file_to_process = args.input_file
            base_time = extract_timestamp_from_filename(input_basename)

        if base_time is None: 
            print(f"Could not extract yyyyMMDDHHMMSS timestamp from filename '{input_basename}'.")
            try:
                stat_result = os.stat(args.input_file) 
                base_time = datetime.fromtimestamp(stat_result.st_mtime)
                print(f"Using original input file's modification time as base_time: {base_time.strftime('%Y-%m-%d %H:%M:%S.%f')}")
            except Exception as e_stat:
                base_time = datetime.now()
                print(f"Warning: Could not get file modification time ({e_stat}). Using current time as base_time: {base_time.strftime('%Y-%m-%d %H:%M:%S.%f')}")
        
        print(f"Using base time for conversion: {base_time.strftime('%Y-%m-%d %H:%M:%S.%f')}")

        df = pcap_to_dataframe(pcap_file_to_process, base_time)
        
        if df.empty:
            print(f"Resulting DataFrame is empty. Not creating Parquet file '{output_file}' for '{args.input_file}'.")
        else:
            # *** NEW STEP: Aggregate packets before saving ***
            print("Aggregating consecutive packets...")
            aggregated_df = aggregate_packets_optimized(df)
            print(f"Aggregation complete. Rows changed from {len(df)} to {len(aggregated_df)}.")

            if 'Time' in aggregated_df.columns and aggregated_df['Time'].dtype == 'object':
                aggregated_df['Time'] = pd.to_datetime(aggregated_df['Time'], errors='coerce')
            
            if 'Time' in aggregated_df.columns and pd.api.types.is_datetime64_any_dtype(aggregated_df['Time']):
                try:
                    if aggregated_df['Time'].dt.tz is not None:
                         print(f"Time column is timezone-aware ({aggregated_df['Time'].dt.tz}). Converting to UTC for Parquet storage.")
                         aggregated_df['Time'] = aggregated_df['Time'].dt.tz_convert('UTC')
                except AttributeError as e:
                    if aggregated_df['Time'].isnull().all():
                        print("Time column contains all NaT values.")
                    else:
                        print(f"Could not process Time column timezone: {e}")

            # Save the aggregated DataFrame to Parquet
            aggregated_df.to_parquet(output_file, index=False, engine='pyarrow', allow_truncated_timestamps=False, coerce_timestamps='us')
            print(f"Successfully converted and aggregated '{args.input_file}' to '{output_file}'")

    except ValueError as ve: 
        print(f"Processing Error: {ve}")
    except RuntimeError as re_err: 
        print(f"Runtime Error: {re_err}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if decompressed_temp_file and os.path.exists(decompressed_temp_file):
            try:
                os.remove(decompressed_temp_file)
                print(f"Removed temporary decompressed file: {decompressed_temp_file}")
            except OSError as e:
                print(f"Warning: Could not remove temporary file {decompressed_temp_file}: {e}")


if __name__ == "__main__":
    # For the script to run, you'll need pandas and pyarrow (or fastparquet)
    # pip install pandas pyarrow
    main()