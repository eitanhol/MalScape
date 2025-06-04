#!/usr/bin/env python3
import os
import re
import lzma
import argparse
import subprocess
import pandas as pd
from datetime import datetime, timedelta

def extract_timestamp_from_filename(filename):
    """
    Extract a timestamp string from the filename.
    The expected format is ПроMMDDHHMMSS.
    For example: mypcap_20091103082335.pcap.xz
    """
    pattern = r'(\d{14})' # YYYYMMDDHHMMSS
    match = re.search(pattern, os.path.basename(filename)) # Search in basename only
    if not match:
        try:
            stat_result = os.stat(filename)
            base_time = datetime.fromtimestamp(stat_result.st_mtime)
            print(f"Warning: No timestamp in filename '{os.path.basename(filename)}', using file modification time: {base_time.strftime('%Y%m%d%H%M%S')}")
            return base_time
        except Exception as e:
            print(f"Error getting file modification time for '{filename}': {e}")
            raise ValueError(f"No valid timestamp in 'YYYYMMDDHHMMSS' format found in filename '{os.path.basename(filename)}', and could not use file modification time.")
    timestamp_str = match.group(1)
    try:
        base_time = datetime.strptime(timestamp_str, "%Y%m%d%H%M%S")
    except ValueError as e:
        raise ValueError(f"Error parsing timestamp '{timestamp_str}' from filename '{os.path.basename(filename)}': {e}")
    return base_time

def decompress_file(compressed_file):
    """Decompress a .xz file. If not .xz, assumes it's already pcap."""
    if not compressed_file.endswith('.xz'):
        if not os.path.exists(compressed_file):
            raise FileNotFoundError(f"Input file {compressed_file} not found.")
        print(f"File {compressed_file} does not have a .xz extension. Processing as is.")
        return compressed_file

    uncompressed_file = compressed_file[:-3]
    if os.path.exists(uncompressed_file) and os.path.getmtime(uncompressed_file) >= os.path.getmtime(compressed_file):
        print(f"Uncompressed file {uncompressed_file} already exists and is up-to-date. Skipping decompression.")
        return uncompressed_file

    print(f"Decompressing {compressed_file} to {uncompressed_file} ...")
    try:
        with lzma.open(compressed_file, 'rb') as fin, open(uncompressed_file, 'wb') as fout:
            chunk_size = 1024 * 1024
            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                fout.write(chunk)
    except Exception as e:
        raise RuntimeError(f"Error decompressing file: {e}")
    print("Decompression complete.")
    return uncompressed_file

def convert_pcap_to_csv(pcap_file, csv_file):
    """
    Use tshark to convert the pcap file to CSV with extended fields.
    """
    print(f"Converting {pcap_file} to CSV {csv_file} using tshark ...")
    
    tshark_fields = [
        "frame.number", "frame.time_epoch", "ip.src", "ip.dst",
        "_ws.col.protocol", "frame.len", "_ws.col.Info", 
        "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport", 
        "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.push", "tcp.flags.reset", 
        "tcp.seq", "tcp.ack", "tcp.window_size_value", 
        "tcp.len", "udp.length", 
        "tcp.options.timestamp.tsval", "tcp.options.timestamp.tsecr"
    ]
    tshark_cmd_parts = ["tshark", "-r", pcap_file, "-T", "fields", "-E", "header=y", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"]
    for field in tshark_fields:
        tshark_cmd_parts.extend(["-e", field])
    
    try:
        with open(csv_file, "w") as fout:
            process = subprocess.Popen(tshark_cmd_parts, stdout=fout, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
            _, stderr_output = process.communicate() 
            if process.returncode != 0:
                try:
                    with open(pcap_file, 'rb') as pf:
                        header = pf.read(24) 
                        if not header:
                             raise RuntimeError(f"tshark command failed. PCAP file '{pcap_file}' might be empty. Stderr: {stderr_output}")
                        if header[:4] not in [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a']: 
                             print(f"Warning: PCAP file '{pcap_file}' might not be a standard pcap or pcapng file or is corrupted. Header: {header[:16]}")
                except Exception as pcap_read_err:
                    print(f"Could not perform basic read check on pcap file '{pcap_file}': {pcap_read_err}")
                raise RuntimeError(f"tshark command failed with exit code {process.returncode}. Stderr: {stderr_output}")
            if stderr_output:
                print(f"tshark stderr (may include warnings):\n{stderr_output}")
    except FileNotFoundError:
        raise RuntimeError(f"tshark command not found. Please ensure tshark is installed and in your system's PATH.")
    except Exception as e:
        raise RuntimeError(f"Error during tshark execution: {e}")
    print("Conversion to CSV with tshark complete.")


def process_tshark_csv(input_csv_path, output_csv_path, base_time):
    """
    Reads tshark CSV, processes fields, and aggregates *consecutive* packets
    that are identical based on a refined set of less volatile fields,
    keeping the timestamp and other details of the first packet in each sequence.
    """
    print(f"Processing tshark CSV {input_csv_path}...")
    try:
        df = pd.read_csv(input_csv_path, low_memory=False, dtype={'frame.number': str})
    except pd.errors.EmptyDataError:
        print(f"Warning: tshark output CSV '{input_csv_path}' is empty. Writing an empty CSV to '{output_csv_path}'.")
        final_header_for_empty = [
            "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info_Orig", "Occurrences",
            "Direct_SourcePort", "Direct_DestinationPort",
            "Direct_IsSYN", "Direct_IsACK", "Direct_IsPSH", "Direct_IsRST",
            "Direct_Seq", "Direct_Ack", "Direct_Win",
            "Direct_PayloadLength", "Direct_TSval", "Direct_TSecr"
        ]
        with open(output_csv_path, 'w') as f:
            f.write(",".join(final_header_for_empty) + "\n")
        return
    except Exception as e:
        raise RuntimeError(f"Error reading tshark CSV file '{input_csv_path}': {e}")

    df.rename(columns={
        "frame.number": "No.",
        "frame.time_epoch": "Time_Epoch_Raw",
        "ip.src": "Source",
        "ip.dst": "Destination",
        "_ws.col.protocol": "Protocol",
        "frame.len": "Length",
        "_ws.col.Info": "Info_Orig",
    }, inplace=True)

    # --- Time Processing ---
    df["Time_Epoch_Raw"] = pd.to_numeric(df.get("Time_Epoch_Raw"), errors='coerce')
    capture_start_epoch_in_pcap = df["Time_Epoch_Raw"].min()
    if pd.isna(capture_start_epoch_in_pcap) and not df["Time_Epoch_Raw"].dropna().empty:
        capture_start_epoch_in_pcap = df["Time_Epoch_Raw"].dropna().min()

    if pd.isna(capture_start_epoch_in_pcap):
        df["Time"] = base_time.timestamp() if not df.empty else pd.NA
    else:
        def calculate_absolute_epoch(relative_epoch_in_pcap_series_val):
            if pd.notna(relative_epoch_in_pcap_series_val):
                offset_seconds = relative_epoch_in_pcap_series_val - capture_start_epoch_in_pcap
                absolute_dt = base_time + timedelta(seconds=offset_seconds)
                return absolute_dt.timestamp()
            return pd.NA
        df["Time"] = df["Time_Epoch_Raw"].apply(calculate_absolute_epoch)
    df.drop(columns=["Time_Epoch_Raw"], inplace=True, errors='ignore')
    # --- End Time Processing ---

    # --- Create Direct_* fields ---
    df['Direct_SourcePort'] = pd.to_numeric(df.get('tcp.srcport'), errors='coerce').fillna(pd.to_numeric(df.get('udp.srcport'), errors='coerce'))
    df['Direct_DestinationPort'] = pd.to_numeric(df.get('tcp.dstport'), errors='coerce').fillna(pd.to_numeric(df.get('udp.dstport'), errors='coerce'))
    df['Direct_IsSYN'] = pd.to_numeric(df.get('tcp.flags.syn'), errors='coerce').fillna(0).astype(int)
    df['Direct_IsACK'] = pd.to_numeric(df.get('tcp.flags.ack'), errors='coerce').fillna(0).astype(int)
    df['Direct_IsPSH'] = pd.to_numeric(df.get('tcp.flags.push'), errors='coerce').fillna(0).astype(int)
    df['Direct_IsRST'] = pd.to_numeric(df.get('tcp.flags.reset'), errors='coerce').fillna(0).astype(int)
    df['Direct_Seq'] = pd.to_numeric(df.get('tcp.seq'), errors='coerce')
    df['Direct_Ack'] = pd.to_numeric(df.get('tcp.ack'), errors='coerce')
    df['Direct_Win'] = pd.to_numeric(df.get('tcp.window_size_value'), errors='coerce')
    df['Direct_TSval'] = pd.to_numeric(df.get('tcp.options.timestamp.tsval'), errors='coerce')
    df['Direct_TSecr'] = pd.to_numeric(df.get('tcp.options.timestamp.tsecr'), errors='coerce')
    direct_payload_tcp = pd.to_numeric(df.get('tcp.len'), errors='coerce')
    direct_payload_udp = pd.to_numeric(df.get('udp.length'), errors='coerce')
    direct_payload_udp = direct_payload_udp.apply(lambda x: x - 8 if pd.notna(x) and x >= 8 else pd.NA)
    df['Direct_PayloadLength'] = direct_payload_tcp.fillna(direct_payload_udp)
    df["Length"] = pd.to_numeric(df.get("Length"), errors='coerce')
    # --- End Create Direct_* fields ---

    if 'Info_Orig' not in df.columns: df['Info_Orig'] = ""
    df["Info_Orig"] = df["Info_Orig"].fillna("").astype(str).str.replace(',', '/', regex=False)
    
    # --- Aggregation of Consecutive Identical Packets ---
    if not df.empty:
        identity_defining_columns = [
            "Source", "Destination", "Protocol", "Length",
            "Direct_SourcePort", "Direct_DestinationPort",
            "Direct_IsSYN", "Direct_IsACK", "Direct_IsPSH", "Direct_IsRST",
            "Direct_Win", "Direct_PayloadLength"
        ]
        
        placeholder_numeric = -999999 
        placeholder_string = "__FIELD_WAS_NAN__"

        df_identity_check = pd.DataFrame(index=df.index)
        for col in identity_defining_columns:
            if col not in df.columns: 
                if "Direct_Is" in col: current_col_data = pd.Series(0, index=df.index)
                elif any(k_word in col for k_word in ["Port", "Win", "Length"]): current_col_data = pd.Series(placeholder_numeric, index=df.index)
                else: current_col_data = pd.Series(placeholder_string, index=df.index)
            else: 
                current_col_data = df[col].copy() 
                if current_col_data.dtype == 'object' or isinstance(current_col_data.dtype, pd.StringDtype):
                    current_col_data.fillna(placeholder_string, inplace=True)
                else: 
                    if "Direct_Is" not in col:
                        current_col_data.fillna(placeholder_numeric, inplace=True)
            df_identity_check[col] = current_col_data
        
        print("Identifying consecutive identical packet sequences (with revised identity criteria)...")
        is_different_from_previous = df_identity_check.ne(df_identity_check.shift()).any(axis=1)
        df['block_id'] = is_different_from_previous.cumsum()

        print(f"Aggregating {len(df)} rows into consecutive identical blocks...")
        
        # Step 1: Aggregate all columns (except 'block_id') by taking the 'first' value from each block.
        # This ensures we have one representative row for each block.
        df_firsts = df.groupby('block_id', as_index=False).first()

        # Step 2: Calculate the size of each block to get the 'Occurrences'.
        # The result is a Series with 'block_id' as the index and counts as values.
        occurrences_counts = df.groupby('block_id').size().rename('Occurrences')

        # Step 3: Merge the 'Occurrences' back into the DataFrame of first values.
        # Since df_firsts has 'block_id' as a column (due to as_index=False),
        # and occurrences_counts has 'block_id' as its index, we merge on 'block_id'.
        df_aggregated = pd.merge(df_firsts, occurrences_counts, on='block_id', how='left')
        
        # Now, df_aggregated contains one row per block, with all original columns (values from the first packet)
        # AND an 'Occurrences' column.
        
        # Drop the temporary 'block_id' column if it's still there (it should be after merge)
        if 'block_id' in df_aggregated.columns:
            df_aggregated.drop(columns=['block_id'], inplace=True)
        
        print(f"Reduced rows from {len(df)} to {len(df_aggregated)} after aggregating.")
    else:
        cols_for_empty_agg = [
            "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info_Orig", "Occurrences",
            "Direct_SourcePort", "Direct_DestinationPort",
            "Direct_IsSYN", "Direct_IsACK", "Direct_IsPSH", "Direct_IsRST",
            "Direct_Seq", "Direct_Ack", "Direct_Win",
            "Direct_PayloadLength", "Direct_TSval", "Direct_TSecr"
        ]
        df_aggregated = pd.DataFrame(columns=cols_for_empty_agg)

    final_csv_columns = [ 
        "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info_Orig", "Occurrences",
        "Direct_SourcePort", "Direct_DestinationPort",
        "Direct_IsSYN", "Direct_IsACK", "Direct_IsPSH", "Direct_IsRST",
        "Direct_Seq", "Direct_Ack", "Direct_Win", 
        "Direct_PayloadLength", "Direct_TSval", "Direct_TSecr"
    ]
    
    for col in final_csv_columns:
        if col not in df_aggregated.columns:
            if col == 'Occurrences' and not df_aggregated.empty: df_aggregated[col] = 1 
            elif col == 'Occurrences' and df_aggregated.empty: df_aggregated[col] = 0
            else: df_aggregated[col] = pd.NA

    df_output = df_aggregated.reindex(columns=final_csv_columns).copy()

    for col in identity_defining_columns: 
        if col in df_output.columns:
            current_col_series = df_output[col]
            if pd.api.types.is_object_dtype(current_col_series) or pd.api.types.is_string_dtype(current_col_series):
                df_output[col] = current_col_series.replace(placeholder_string, pd.NA)
            elif pd.api.types.is_numeric_dtype(current_col_series): 
                df_output[col] = current_col_series.replace(placeholder_numeric, pd.NA)
    
    numeric_output_cols = [ 
        "Time", "Length", "Occurrences",
        "Direct_SourcePort", "Direct_DestinationPort", "Direct_Seq", "Direct_Ack",
        "Direct_Win", "Direct_PayloadLength", "Direct_TSval", "Direct_TSecr"
    ]
    for col in numeric_output_cols:
        if col in df_output.columns:
            df_output[col] = pd.to_numeric(df_output[col], errors='coerce')
            if col in ["Direct_PayloadLength", "Length", "Occurrences"]:
                 df_output[col] = df_output[col].fillna(0).astype(int) 
            elif col == "Time": 
                 pass 
            else: 
                 if df_output[col].isnull().any():
                     df_output[col] = df_output[col].astype(float) 
                 else:
                     try:
                        if df_output[col].dropna().apply(lambda x: float(x).is_integer()).all():
                            df_output[col] = df_output[col].astype(float).astype(pd.Int64Dtype()) 
                        else:
                            df_output[col] = df_output[col].astype(float)
                     except (AttributeError, ValueError, TypeError) : 
                        df_output[col] = df_output[col].astype(float)

    print(f"Writing aggregated CSV to {output_csv_path}...")
    df_output.to_csv(output_csv_path, index=False, na_rep='')

# main() function remains the same as your provided version.
def main():
    parser = argparse.ArgumentParser(
        description="Uncompress a .pcap.xz (or process .pcap) file, convert it to CSV via tshark, "
                    "and minimally process for faster ingestion by MalScape's app.py."
    )
    parser.add_argument("input_file", help="Path to the .pcap.xz or .pcap file")
    args = parser.parse_args()

    pcap_file_to_process = None
    intermediate_csv_path = None
    decompressed_pcap_path = None


    try:
        base_time = extract_timestamp_from_filename(args.input_file)
        
        if args.input_file.endswith(".pcap.xz"):
            decompressed_pcap_path = decompress_file(args.input_file)
            pcap_file_to_process = decompressed_pcap_path
        elif args.input_file.endswith(".pcap"):
            if not os.path.exists(args.input_file):
                raise FileNotFoundError(f"Input .pcap file {args.input_file} not found.")
            pcap_file_to_process = args.input_file
        else:
            raise ValueError("Input file must be a .pcap or .pcap.xz file.")

        # Determine output CSV filename
        base_name_os = os.path.basename(args.input_file)
        if base_name_os.endswith(".pcap.xz"):
            final_csv_name = base_name_os[:-len(".pcap.xz")] + ".csv"
        elif base_name_os.endswith(".pcap"):
            final_csv_name = base_name_os[:-len(".pcap")] + ".csv"
        else: # Should not happen due to check above
            final_csv_name = base_name_os + ".processed.csv"
        
        # Use a temporary CSV file for tshark's output
        output_dir = os.path.dirname(os.path.abspath(final_csv_name))
        os.makedirs(output_dir, exist_ok=True) 
        intermediate_csv_path = os.path.join(output_dir, os.path.basename(pcap_file_to_process) + "_tshark_temp.csv")

        convert_pcap_to_csv(pcap_file_to_process, intermediate_csv_path)
        process_tshark_csv(intermediate_csv_path, final_csv_name, base_time)

        print(f"Final CSV saved as {final_csv_name}")
        print("All operations completed successfully.")

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if intermediate_csv_path and os.path.exists(intermediate_csv_path):
            os.remove(intermediate_csv_path)
        if decompressed_pcap_path and decompressed_pcap_path != args.input_file and os.path.exists(decompressed_pcap_path):
            os.remove(decompressed_pcap_path)

if __name__ == "__main__":
    main()