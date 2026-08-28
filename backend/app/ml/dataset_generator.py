import os
import csv
from typing import List, Tuple

DATASET_CSV = os.path.join(os.path.dirname(__file__), "academic_threat_corpus.csv")

SAMPLE_DATA: List[Tuple[str, str, str]] = [
    # Legitimate
    ("Team Sprint Review & Architecture Planning", "Please review the attached project sprint review notes for the upcoming milestone release.", "Legitimate"),
    ("Q3 Department Budget Presentation", "The finance committee has published the quarterly budget allocations on the intranet portal.", "Legitimate"),
    ("Library Resource Guide & Extended Hours", "The university library will remain open 24 hours during final examination week.", "Legitimate"),
    ("Shipping Confirmation: Package Dispatched", "Your package with tracking number 1Z99999999 has been dispatched via UPS ground.", "Legitimate"),
    ("Monthly Security Awareness Training", "Please complete your assigned 15-minute cybersecurity refresher module on the learning LMS.", "Legitimate"),
    ("Invitation: Department Research Seminar", "You are cordially invited to attend the guest lecture on distributed ledger technologies on Friday.", "Legitimate"),
    ("System Maintenance Notification", "Scheduled database backup and routine operating system patching will occur this Saturday at 02:00 UTC.", "Legitimate"),
    ("Meeting Summary and Action Items", "Attached are the summarized meeting notes and action item assignments from our client discussion.", "Legitimate"),

    # Phishing
    ("URGENT: Your PayPal Account Has Been Suspended", "We detected unauthorized login attempts from an unknown device. Verify your credentials immediately at secure-login-portal.", "Phishing"),
    ("Action Required: Microsoft Office 365 Password Expiration", "Your corporate domain password expires in 2 hours. Click here to keep your current password and re-authenticate.", "Phishing"),
    ("Security Alert: Suspicious Activity Detected on Your Bank Account", "A direct debit of $1,420.00 was authorized from your account. If this was not you, cancel the transaction immediately by verifying identity.", "Phishing"),
    ("IT Helpdesk: Mailbox Storage Quota Exceeded", "Your enterprise mailbox has exceeded 99% capacity. Click below to upgrade storage quota or messages will be permanently rejected.", "Phishing"),
    ("DocuSign: Electronic Document Pending Signature", "You have received an urgent contract document for electronic signature. Please click to verify identity and review terms.", "Phishing"),
    ("Google Workspace: Critical Security Notice", "An unrecognized Linux browser in Russia accessed your Gmail account. Re-verify your master password now to protect account.", "Phishing"),

    # Executive Impersonation
    ("From CEO: Immediate Task Needed", "Are you at your desk right now? I am in an executive board meeting and need you to urgently buy Apple gift cards for a VIP customer.", "Executive Impersonation"),
    ("Confidential Request from Office of the President", "Please assist me with a private wire transfer for an overseas acquisition. Do not discuss this with colleagues until announced.", "Executive Impersonation"),
    ("URGENT - Direct Instruction from Chief Executive", "I need you to process an emergency payroll adjustment today. Reply with your mobile number so I can text you payment coordinates.", "Executive Impersonation"),
    ("Executive Request: Purchase Corporate Vouchers", "Kindly procure 5x $500 Steam gift cards for our client appreciation event today and email the back scratch codes.", "Executive Impersonation"),

    # BEC (Business Email Compromise)
    ("Updated Bank Account Details for Pending Invoice", "Please note that our company has transitioned banking partners. Update our vendor remittance profile with the new IBAN/routing number.", "Business Email Compromise (BEC)"),
    ("Revised Payment Instructions for Invoice #8841", "Kindly re-route the scheduled wire transfer for invoice #8841 to our subsidiary escrow account listed below.", "Business Email Compromise (BEC)"),
    ("Supplier Remittance Advice & Account Modification", "Due to an internal banking audit, our primary receiving account is temporarily unavailable. Please direct all pending disbursements to our new account.", "Business Email Compromise (BEC)"),

    # Financial Fraud
    ("Notification of Unclaimed Inheritance Funds", "You are the designated beneficiary of a $7.2M USD estate left by a foreign national. Send your bank account and passport to claim.", "Financial Fraud"),
    ("Guaranteed Cryptocurrency Investment Opportunity", "Earn 250% weekly return on automated Bitcoin trading algorithm. Deposit a minimum of 0.1 BTC to commence automated trading.", "Financial Fraud"),
    ("Official IRS Tax Rebate Notice", "You have an uncollected federal tax refund of $3,150.00. Submit your direct deposit banking routing number to receive disbursement.", "Financial Fraud"),

    # Malware Delivery
    ("Legal Subpoena Notice & Document Production Mandate", "You are commanded to appear before the court. Please open the attached Subpoena_Notice_Q3.pdf.exe and enable macros to review charges.", "Malware Delivery"),
    ("Scanned Invoice Document from Office Copier", "Attached is the electronic scan of your purchase order receipt in zip archive. Run setup.vbs to inspect invoice.", "Malware Delivery"),
    ("Shipping Manifest & Customs Clearance Document", "Your package delivery failed due to unpaid customs duties. Open the attached shipment_manifest.docm to pay import tax.", "Malware Delivery"),

    # Spam
    ("Exclusive Discount on Luxury Designer Timepieces", "Save up to 85% on Swiss watches and luxury handbags. Limited quantities available, shop now!", "Spam"),
    ("Boost Your Website Google Search Ranking", "Increase your domain traffic and search engine authority ranking within 48 hours guaranteed with our backlink package.", "Spam")
]


def generate_dataset_csv():
    """Generates synthetic dataset CSV for academic benchmarking and evaluation."""
    os.makedirs(os.path.dirname(DATASET_CSV), exist_ok=True)
    with open(DATASET_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["subject", "body", "label"])
        for subj, body, lbl in SAMPLE_DATA:
            writer.writerow([subj, body, lbl])
    print(f"Generated dataset CSV with {len(SAMPLE_DATA)} synthetic academic samples at: {DATASET_CSV}")


if __name__ == "__main__":
    generate_dataset_csv()
