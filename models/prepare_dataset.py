import os
from pathlib import Path
import pandas as pd
from datasets import load_dataset


# Dataset 1: rogue-security/prompt-injections-benchmark
def load_rogue():

    token = os.getenv("HF_TOKEN")

    dataset = load_dataset(
        "rogue-security/prompt-injections-benchmark",
        split="test",
        token=token
    )

    df = dataset.to_pandas()

    df["label"] = df["label"].apply(
        lambda x: 0 if x == "benign" else 1
    )

    df = df[["text", "label"]]

    print("Rogue rows:", len(df))

    return df


# Dataset 2: deepset/prompt-injections
def load_deepset():

    dataset = load_dataset("deepset/prompt-injections")

    dfs = []

    for split in dataset.keys():
        print("Loading deepset split:", split)
        dfs.append(dataset[split].to_pandas())

    df = pd.concat(dfs, ignore_index=True)

    df = df[["text", "label"]]

    print("Deepset rows:", len(df))

    return df

# Dataset 3: JailbreakBench
def load_jailbreakbench():

    dataset = load_dataset(
        "JailbreakBench/JBB-Behaviors",
        "behaviors"
    )

    harmful = dataset["harmful"].to_pandas()
    benign = dataset["benign"].to_pandas()

    harmful["label"] = 1
    benign["label"] = 0

    df = pd.concat([harmful, benign], ignore_index=True)

    df = df[["Goal", "label"]].rename(
        columns={"Goal": "text"}
    )

    print("JailbreakBench rows:", len(df))

    return df


# Merge datasets
def merge_datasets():

    loaders = [
        ("rogue-security/prompt-injections-benchmark", load_rogue),
        ("deepset/prompt-injections", load_deepset),
        ("JailbreakBench/JBB-Behaviors", load_jailbreakbench),
    ]

    dataframes = []

    for name, loader in loaders:
        try:
            df = loader()
            print(f"Loaded {name}: {len(df)} rows\n")
            dataframes.append(df)

        except Exception as e:
            print(f"Skipping {name}: {e}")

    if not dataframes:
        raise RuntimeError("No datasets loaded.")

    combined = pd.concat(dataframes, ignore_index=True)

    print("Total rows before shuffle:", len(combined))

    combined = combined.sample(frac=1).reset_index(drop=True)

    print("\nLabel distribution:")
    print(combined["label"].value_counts())

    return combined


# Main
if __name__ == "__main__":

    final_df = merge_datasets()

    output_dir = Path("models/data")
    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = output_dir / "combined_dataset.csv"

    final_df.to_csv(output_path, index=False)

    print("\nDataset saved successfully!")
    print("Saved to:", output_path)

    print("\nPreview:")
    print(final_df.head())
