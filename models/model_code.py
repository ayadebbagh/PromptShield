# train_model.py
# Prompt Injection / PII Classifier Training
# trained on google colab

import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split

from transformers import (
    DistilBertTokenizerFast,
    DistilBertForSequenceClassification,
    Trainer,
    TrainingArguments
)
import torch

# ------------------------------
# 1. Load merged dataset
# ------------------------------
data_path = Path("combined_dataset.csv")
df = pd.read_csv(data_path)

print("Total rows:", len(df))
print("Label distribution:\n", df["label"].value_counts())

# ------------------------------
# 2. Train / Validation Split
# ------------------------------
train_texts, val_texts, train_labels, val_labels = train_test_split(
    df["text"].tolist(),
    df["label"].tolist(),
    test_size=0.1,
    random_state=42,
    stratify=df["label"]
)

# ------------------------------
# 3. Tokenization
# ------------------------------
tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")

train_encodings = tokenizer(
    train_texts,
    truncation=True,
    padding=True,
    max_length=256
)

val_encodings = tokenizer(
    val_texts,
    truncation=True,
    padding=True,
    max_length=256
)

# ------------------------------
# 4. Create Torch Dataset
# ------------------------------
class PromptDataset(torch.utils.data.Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item["labels"] = torch.tensor(self.labels[idx])
        return item

train_dataset = PromptDataset(train_encodings, train_labels)
val_dataset = PromptDataset(val_encodings, val_labels)

# ------------------------------
# 5. Load Model
# ------------------------------
model = DistilBertForSequenceClassification.from_pretrained(
    "distilbert-base-uncased",
    num_labels=2
)

# ------------------------------
# 6. Training Arguments (v5 compatible)
# ------------------------------
training_args = TrainingArguments(
    output_dir="./results",
    num_train_epochs=3,
    per_device_train_batch_size=16,
    per_device_eval_batch_size=16,
    eval_strategy="epoch",        # ← add this (matches save_strategy)
    logging_steps=100,
    save_strategy="epoch",
    learning_rate=5e-5,
    weight_decay=0.01,
    load_best_model_at_end=True,
    metric_for_best_model="accuracy",
    push_to_hub=False
)


# ------------------------------
# 7. Metric Function
# ------------------------------
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

def compute_metrics(pred):
    labels = pred.label_ids
    preds = pred.predictions.argmax(-1)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average="binary")
    acc = accuracy_score(labels, preds)
    return {
        "accuracy": acc,
        "f1": f1,
        "precision": precision,
        "recall": recall
    }

# ------------------------------
# 8. Trainer
# ------------------------------
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=val_dataset,
    processing_class=tokenizer,   # ← replaces 'tokenizer'
    compute_metrics=compute_metrics
)

# ------------------------------
# 9. Train!
# ------------------------------
trainer.train()

# ------------------------------
# 10. Save Model
# ------------------------------
model_save_path = Path("models/saved_model/prompt_firewall_model")
model_save_path.mkdir(parents=True, exist_ok=True)

trainer.save_model(model_save_path)
tokenizer.save_pretrained(model_save_path)

print("Model and tokenizer saved to:", model_save_path)
