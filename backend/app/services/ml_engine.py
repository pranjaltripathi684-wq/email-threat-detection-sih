import os
import time
import pickle
import numpy as np
from typing import Dict, Any, List, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ml", "model_store")
MODEL_PATH = os.path.join(MODEL_DIR, "threat_classifier.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl")


class ThreatMLPipeline:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.classes = [
            "Legitimate",
            "Phishing",
            "Executive Impersonation",
            "Business Email Compromise (BEC)",
            "Financial Fraud",
            "Malware Delivery",
            "Spam"
        ]
        self._load_or_initialize()

    def _load_or_initialize(self):
        """Loads trained model or initializes a high-quality baseline."""
        if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
            try:
                with open(MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
                with open(VECTORIZER_PATH, "rb") as f:
                    self.vectorizer = pickle.load(f)
                return
            except Exception:
                pass

        # Build baseline synthetic training set and train instantly
        self._train_baseline_model()

    def _train_baseline_model(self):
        """Initializes and trains an academic baseline TF-IDF + Logistic Regression model."""
        os.makedirs(MODEL_DIR, exist_ok=True)
        
        # Synthetic academic baseline samples
        corpus = [
            # Legitimate
            ("Team, here is the weekly project status report and sprint review agenda.", "Legitimate"),
            ("Please find the minutes of our quarterly budget planning meeting attached.", "Legitimate"),
            ("Thanks for attending the webinar yesterday. The slide deck is accessible here.", "Legitimate"),
            ("Hi John, could you review the latest pull request when you get a chance?", "Legitimate"),
            ("Your order has shipped and will arrive on Friday. Track package at UPS.", "Legitimate"),
            ("University announcement: Campus library holiday hours and study room bookings.", "Legitimate"),
            
            # Phishing
            ("URGENT: Your PayPal account has been suspended! Verify your password immediately at secure-login.", "Phishing"),
            ("Action Required: Unauthorized sign-in attempt detected on your Microsoft Office 365 account.", "Phishing"),
            ("Your mailbox storage limit is full. Click here to confirm credentials and avoid account deletion.", "Phishing"),
            ("Security Notice: Re-authenticate your banking session within 24 hours to prevent account closure.", "Phishing"),
            ("DocuSign: You have received a document for signature. Click to verify your identity and view.", "Phishing"),
            
            # Executive Impersonation
            ("From CEO: I am currently in a conference meeting and need you to urgently purchase Apple gift cards for a client.", "Executive Impersonation"),
            ("Are you at your desk? I need an urgent wire transfer done right away. Keep this private.", "Executive Impersonation"),
            ("From President: Please process this confidential executive request before end of business today.", "Executive Impersonation"),
            ("Need immediate assistance with a discrete transaction for executive board members. Do not call my phone.", "Executive Impersonation"),

            # BEC
            ("Attention Accounting: Our supplier bank account details have changed. Remit payment to the updated routing number.", "Business Email Compromise (BEC)"),
            ("Please find revised invoice #8841 attached with our new bank wire instructions. Update payroll records.", "Business Email Compromise (BEC)"),
            ("Vendor remittance notification: kindly redirect pending invoice disbursements to our new escrow account.", "Business Email Compromise (BEC)"),

            # Financial Fraud
            ("You have inherited $5.5 million USD from a deceased estate. Send your bank details for wire transfer.", "Financial Fraud"),
            ("Investment opportunity with guaranteed 300% return in Bitcoin crypto trading. Deposit funds now.", "Financial Fraud"),
            ("IRS Tax Refund Department: Claim your uncollected tax credit of $2,450 by providing banking details.", "Financial Fraud"),

            # Malware Delivery
            ("Please review the attached invoice_Q3.pdf.exe and enable macros to decrypt content.", "Malware Delivery"),
            ("Scanned document from Xerox printer attached in zip archive. Run setup.vbs to view.", "Malware Delivery"),
            ("Attached is the subpoena document from district court. Open docm file to view legal charges.", "Malware Delivery"),

            # Spam
            ("Huge discount on luxury watches and designer sunglasses! Order today for 80% off.", "Spam"),
            ("Increase your website SEO ranking and domain traffic within 48 hours guaranteed.", "Spam")
        ]

        texts = [item[0] for item in corpus]
        labels = [item[1] for item in corpus]

        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=1000,
            sublinear_tf=True
        )
        X = self.vectorizer.fit_transform(texts)

        self.model = LogisticRegression(
            class_weight="balanced",
            max_iter=500,
            random_state=42
        )
        self.model.fit(X, labels)

        # Save model
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(self.model, f)
        with open(VECTORIZER_PATH, "wb") as f:
            pickle.dump(self.vectorizer, f)

    def predict(self, subject: str, body_text: str) -> Dict[str, Any]:
        """
        Runs inference on email subject and body text, returning calibrated class probabilities
        and top contributing TF-IDF n-gram feature tokens.
        """
        start_time = time.perf_counter()
        full_text = f"{subject} {body_text}".strip()
        
        if not full_text:
            return {
                "predicted_class": "Unknown / Insufficient Text",
                "probability_score": 0.5,
                "top_features": [],
                "inference_time_ms": 0.0
            }

        X = self.vectorizer.transform([full_text])
        probabilities = self.model.predict_proba(X)[0]
        classes = self.model.classes_

        best_idx = np.argmax(probabilities)
        predicted_class = classes[best_idx]
        best_prob = float(probabilities[best_idx])

        # Extract top feature words contributing to this decision
        feature_names = np.array(self.vectorizer.get_feature_names_out())
        row_vector = X.toarray()[0]
        nonzero_indices = np.where(row_vector > 0)[0]
        
        # Calculate feature contribution = tfidf_weight * class_coefficient
        class_coefs = self.model.coef_[best_idx]
        contributions = []
        for idx in nonzero_indices:
            token = feature_names[idx]
            weight = float(row_vector[idx] * class_coefs[idx])
            contributions.append({"token": token, "weight": round(weight, 4)})

        contributions.sort(key=lambda x: x["weight"], reverse=True)
        top_features = contributions[:8]

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return {
            "predicted_class": predicted_class,
            "probability_score": round(best_prob, 3),
            "all_class_probabilities": {cls: round(float(prob), 3) for cls, prob in zip(classes, probabilities)},
            "top_features": top_features,
            "inference_time_ms": elapsed_ms
        }


ml_pipeline = ThreatMLPipeline()
