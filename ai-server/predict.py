import torch
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification

_LABEL_MAP = {
    "LABEL_0": "NORMAL",
    "LABEL_1": "CWE-89",
    "LABEL_2": "CWE-79",
    "LABEL_3": "CWE-78",
    "LABEL_4": "CWE-22",
}


class WAFPredictor:
    def __init__(self, model_path: str) -> None:
        self.tokenizer = DistilBertTokenizerFast.from_pretrained(model_path)
        self.model = DistilBertForSequenceClassification.from_pretrained(model_path)
        self.model.eval()
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)

    def predict(self, raw_input: str) -> dict:
        inputs = self.tokenizer(
            raw_input,
            return_tensors="pt",
            truncation=True,
            max_length=256,
            padding=True,
        )
        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        with torch.no_grad():
            logits = self.model(**inputs).logits
            probs = torch.softmax(logits, dim=-1)[0]

        idx = int(probs.argmax())
        label_key = f"LABEL_{idx}"
        cwe_label = _LABEL_MAP.get(label_key, "NORMAL")
        return {
            "classificationScore": float(probs[idx]),
            "cweLabel": cwe_label,
        }
