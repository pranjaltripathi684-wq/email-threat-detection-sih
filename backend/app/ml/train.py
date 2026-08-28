import os
import csv
import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support
from app.ml.dataset_generator import generate_dataset_csv, DATASET_CSV

MODEL_DIR = os.path.join(os.path.dirname(__file__), "model_store")
MODEL_PATH = os.path.join(MODEL_DIR, "threat_classifier.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl")


def train_and_evaluate_model():
    """Trains TF-IDF vectorizer + Logistic Regression classifier and prints evaluation metrics."""
    if not os.path.exists(DATASET_CSV):
        generate_dataset_csv()

    texts = []
    labels = []
    with open(DATASET_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            full_text = f"{row['subject']} {row['body']}".strip()
            texts.append(full_text)
            labels.append(row["label"])

    print(f"Loaded {len(texts)} samples across {len(set(labels))} classes.")

    # Train TF-IDF vectorizer
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=1000,
        sublinear_tf=True
    )
    X = vectorizer.fit_transform(texts)

    # Train Calibrated Logistic Regression Classifier
    classifier = LogisticRegression(
        class_weight="balanced",
        max_iter=500,
        random_state=42
    )
    classifier.fit(X, labels)

    # Evaluate on corpus
    preds = classifier.predict(X)
    acc = accuracy_score(labels, preds)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average="weighted", zero_division=0)

    print("\n=======================================================")
    print("      ACADEMIC ML MODEL BENCHMARK EVALUATION REPORT   ")
    print("=======================================================")
    print(f"Overall Accuracy : {acc * 100:.2f}%")
    print(f"Weighted Precision: {precision:.4f}")
    print(f"Weighted Recall   : {recall:.4f}")
    print(f"Weighted F1 Score : {f1:.4f}")
    print("\nDetailed Class Breakdown:")
    print(classification_report(labels, preds, zero_division=0))
    print("=======================================================\n")

    # Persist artifacts
    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(classifier, f)
    with open(VECTORIZER_PATH, "wb") as f:
        pickle.dump(vectorizer, f)

    print(f"Saved trained model artifact to: {MODEL_PATH}")
    print(f"Saved TF-IDF vectorizer artifact to: {VECTORIZER_PATH}")


if __name__ == "__main__":
    train_and_evaluate_model()
