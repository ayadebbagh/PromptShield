from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

# Path to your saved model
MODEL_PATH = "models/prompt_firewall_model"

# Load tokenizer & model at import time
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)

# Move to GPU if available
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)
model.eval()

def predict_prompt(prompt: str) -> tuple[int, float]:
    """
    Returns:
        label      : int   — 0 = benign, 1 = malicious
        confidence : float — probability of the predicted class (0–1)
    """
    inputs = tokenizer(
        prompt,
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=256
    ).to(device)

    with torch.no_grad():
        logits = model(**inputs).logits

    probs = torch.softmax(logits, dim=-1)
    label = torch.argmax(probs, dim=-1).item()
    confidence = probs[0, label].item()

    return label, confidence