import argparse
import json
import re
import os
import csv
import utils
import pandas as pd
from scipy import stats

TARGETS = ["abac_type_directed", "eval_type_directed",
           "validation_drt_type_directed", "convert_policy_est_to_cedar_type_directed"]
GENERATORS = ["derived", "fail_fast", "fail_fix"]
FUZZERS = ["random", "libfuzzer", "afl"]

def get_exec_and_valid_from_valid_log(valid_log, time=3600):
    with open(valid_log) as f:
        lines = f.readlines()
    if not lines:
        return 0, 0
    line = lines[-1]
    first_number = re.search(r'#(\d+)', line)
    assert first_number

    # Parse the number after 'valid:'
    valid_number = re.search(r'valid:\s*(\d+)', line)
    return int(first_number.group(1)) / time, int(valid_number.group(1)) / time

def read_random_exec_data(data_dir, reps=1, output_file=None):
    rows = [["target", "generator", "fuzzer", "rep", "total execs/s", "valid execs/s", "valid_percent"]]
    for target in TARGETS:
        for generator in GENERATORS:
            for r in range(1, reps + 1):
                log_path = os.path.join(data_dir, target, "random", generator, f"rep_{r}", "valid.log")
                total, valid = get_exec_and_valid_from_valid_log(log_path, 3600)
                if total and valid:
                    valid_percent = valid * 1.0 / total
                    rows.append([target, generator, "random", r, total, valid, valid_percent])
    if output_file:
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerows(rows)

def read_random_obs_data(data_dir, reps=1, output_file=None):
    rows = [["target", "generator", "fuzzer", "rep", "unique_pct", "mean_est_size", "entropy", "mean_kpaths"]]
    for target in TARGETS:
        for generator in GENERATORS:
            for r in range(1, reps + 1):
                log_path = os.path.join(data_dir, target, "random", generator, f"rep_{r}", "obs.jsonl")
                if not os.path.exists(log_path):
                    continue
                df = utils.load_json_df(log_path)
                valid_df = df[df["status"] == "passed"]
                total_count = len(valid_df)
                unique_pct = valid_df["representation"].nunique() / total_count * 100
                if "eval" in target:
                    exprs = valid_df["representation"].apply(lambda x: json.loads(x)["expression"])
                else:
                    exprs = []
                    # Loop through all values of valid_df["representation"]
                    for v in valid_df["representation"]:
                        # Parse the JSON string into a dictionary
                        d = json.loads(v)["policy"]
                        # Get the value of the key "expression" in the dictionary
                        exprs += [e['body'] for e in d['conditions']]
                try:
                    expr_est_sizes = [utils.count_size(e) for e in exprs]
                    category_maps = [utils.get_category_map(e) for e in exprs]
                except:
                    continue
                # Step 2: Create a new DataFrame from the Series
                category_freqs_df = pd.DataFrame(category_maps)
                category_freqs_df = category_freqs_df.fillna(0)

                # Step 3: Calculate the mean of each column (category) across all rows
                category_mean_freqs = category_freqs_df.mean(axis=0)

                # Step 4: Normalize frequencies
                category_mean_freqs = category_mean_freqs / category_mean_freqs.sum()
                mean_est_size = sum(expr_est_sizes) / len(expr_est_sizes)
                entropy = stats.entropy(category_mean_freqs.values)
                k_paths = [utils.num_kpaths(e) for e in exprs]
                mean_kpaths = sum(k_paths) / len(k_paths)
                rows.append([target, generator, "random", r, unique_pct, mean_est_size, entropy, mean_kpaths])
    if output_file:
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerows(rows)

def read_coverage_exec_data(data_dir, reps=5, output_file=None):
    rows = [["target", "generator", "fuzzer", "rep", "checkpoint", "total execs/s", "valid execs/s", "valid_percent"]]
    for target in TARGETS:
        for generator in GENERATORS:
            for r in range(1, reps + 1):
                for checkpoint in range(0, 13):
                    log_path = os.path.join(data_dir, target, "libfuzzer",
                                            generator, f"rep_{r}", "checkpoint_results",
                                            f"hour_{checkpoint}", "valid.log")
                    print(log_path)
                    if not os.path.exists(log_path):
                        print("MISSING!!")
                        continue
                    total, valid = get_exec_and_valid_from_valid_log(log_path, 300)
                    if total and valid:
                        valid_percent = valid * 1.0 / total
                        rows.append([target, generator, "coverage", r, checkpoint, total, valid, valid_percent])
    if output_file:
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerows(rows)

def read_coverage_obs_data(data_dir, reps=1, output_file=None):
    rows = [["target", "generator", "fuzzer", "rep", "checkpoint", "unique_pct", "mean_est_size", "entropy", "mean_kpaths"]]
    for target in TARGETS:
        for generator in GENERATORS:
            for r in range(1, reps + 1):
                for checkpoint in range(0, 13):
                    log_path = os.path.join(data_dir, target, "libfuzzer", generator, f"rep_{r}",
                                            "checkpoint_results", f"hour_{checkpoint}", "obs.jsonl")
                    print(log_path)
                    if not os.path.exists(log_path):
                        print("MISSING!!")
                        continue
                    df = utils.load_json_df(log_path)
                    valid_df = df[df["status"] == "passed"]
                    total_count = len(valid_df)
                    unique_pct = valid_df["representation"].nunique() / total_count * 100
                    if "eval" in target:
                        exprs = valid_df["representation"].apply(lambda x: json.loads(x)["expression"])
                    else:
                        exprs = []
                        # Loop through all values of valid_df["representation"]
                        for v in valid_df["representation"]:
                            # Parse the JSON string into a dictionary
                            d = json.loads(v)["policy"]
                            # Get the value of the key "expression" in the dictionary
                            exprs += [e['body'] for e in d['conditions']]
                    try:
                        expr_est_sizes = [utils.count_size(e) for e in exprs]
                        category_maps = [utils.get_category_map(e) for e in exprs]
                    except:
                        continue
                    # Step 2: Create a new DataFrame from the Series
                    category_freqs_df = pd.DataFrame(category_maps)
                    category_freqs_df = category_freqs_df.fillna(0)

                    # Step 3: Calculate the mean of each column (category) across all rows
                    category_mean_freqs = category_freqs_df.mean(axis=0)

                    # Step 4: Normalize frequencies
                    category_mean_freqs = category_mean_freqs / category_mean_freqs.sum()
                    mean_est_size = sum(expr_est_sizes) / len(expr_est_sizes)
                    entropy = stats.entropy(category_mean_freqs.values)
                    k_paths = [utils.num_kpaths(e) for e in exprs]
                    mean_kpaths = sum(k_paths) / len(k_paths)
                    rows.append([target, generator, "random", r, checkpoint, unique_pct, mean_est_size, entropy, mean_kpaths])
        if output_file:
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerows(rows)

    def read_coverage_exec_data(data_dir, reps=5, output_file=None):
        rows = [["target", "generator", "fuzzer", "rep", "checkpoint", "total execs/s", "valid execs/s", "valid_percent"]]
        for target in TARGETS:
            for generator in GENERATORS:
                for r in range(1, reps + 1):
                    for checkpoint in range(0, 13):
                        log_path = os.path.join(data_dir, target, "libfuzzer",
                                                generator, f"rep_{r}", "checkpoint_results",
                                                f"hour_{checkpoint}", "valid.log")
                        print(log_path)
                        if not os.path.exists(log_path):
                            print("MISSING!!")
                            continue
                        total, valid = get_exec_and_valid_from_valid_log(log_path, 300)
                        if total and valid:
                            valid_percent = valid * 1.0 / total
                            rows.append([target, generator, "coverage", r, checkpoint, total, valid, valid_percent])
    if output_file:
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerows(rows)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate CSV stats for data')
    parser.add_argument('data_dir', type=str, help='Path to the raw data')
    parser.add_argument('output_dir', type=str, help='Path to the raw data')
    args = parser.parse_args()
    print("Reading execution and validity data for random generators...")
    output_file = os.path.join(args.output_dir, "random_gen_exec_stats.csv")
    read_random_exec_data(args.data_dir, output_file=os.path.join(output_file))
    # print("Wrote random generator execution stats to", output_file)
    # print("Reading input data for random generators...")
    # read_random_obs_data(args.data_dir, output_file=os.path.join(args.output_dir, "random_gen_input_stats.csv"))
    # print("Wrote random generator input stats to", output_file)
    # print("Reading execution and validity data for coverage generators...")
    # read_coverage_exec_data(args.data_dir, output_file=os.path.join(args.output_dir, "coverage_gen_exec_stats.csv"))
    # print("Reading input data for coverage generators...")
    # read_coverage_obs_data(args.data_dir, output_file=os.path.join(args.output_dir, "coverage_gen_input_stats.csv"))
