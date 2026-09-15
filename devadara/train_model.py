"""
train_model.py

This script trains DEVADARA's machine-learning "instinct" layer, similar to
how the immune system can react to threats it has never exactly seen before,
just because they look suspicious in structure.

We use a Random Forest classifier from scikit-learn. It's a great beginner
choice because:
  - It doesn't need feature scaling/normalization (unlike e.g. SVM or
    logistic regression), so preprocessing stays simple.
  - It handles many numeric features well without much tuning.
  - It gives us "feature importances" afterwards, so we can see *which*
    file characteristics it actually relies on - useful for understanding
    (and trusting) what the model is doing.

IMPORTANT: This script is run manually, ONCE, during development. The app
itself never calls this file - it only loads the already-trained model that
this script produces. That matches the project rule: "train once, bundle,
never retrain automatically."

Run it with:
    python -m devadara.train_model
"""

import json
import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

# --- Paths -------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(PROJECT_ROOT, "data", "raw", "pe_malware_dataset.csv")
MODEL_OUTPUT_PATH = os.path.join(PROJECT_ROOT, "models", "malware_model.joblib")
FEATURE_LIST_OUTPUT_PATH = os.path.join(PROJECT_ROOT, "models", "feature_columns.json")

# --- Which columns are our features? ------------------------------------
# These are the 52 "raw" PE header fields that Python's `pefile` library can
# read directly and exactly from any real .exe/.dll file. We deliberately
# exclude "Name" (just an identifier, not a real feature), "Malware" (the
# answer we're trying to predict), and the dataset's other derived columns
# (their exact calculation isn't documented, so we can't reproduce them
# reliably from a live file - see the explanation in the chat).
FEATURE_COLUMNS = [
    "e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc",
    "e_maxalloc", "e_ss", "e_sp", "e_csum", "e_ip", "e_cs", "e_lfarlc",
    "e_ovno", "e_oemid", "e_oeminfo", "e_lfanew",
    "Machine", "NumberOfSections", "TimeDateStamp", "PointerToSymbolTable",
    "NumberOfSymbols", "SizeOfOptionalHeader", "Characteristics",
    "Magic", "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode",
    "SizeOfInitializedData", "SizeOfUninitializedData", "AddressOfEntryPoint",
    "BaseOfCode", "ImageBase", "SectionAlignment", "FileAlignment",
    "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
    "MajorImageVersion", "MinorImageVersion", "MajorSubsystemVersion",
    "MinorSubsystemVersion", "SizeOfHeaders", "CheckSum", "SizeOfImage",
    "Subsystem", "DllCharacteristics", "SizeOfStackReserve",
    "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit",
    "LoaderFlags", "NumberOfRvaAndSizes",
]

LABEL_COLUMN = "Malware"  # 1 = malware, 0 = legitimate, as confirmed in the CSV


def main():
    print("=== DEVADARA - ML Model Training (Step 2) ===")

    # 1. Load the dataset --------------------------------------------------
    print(f"[INFO] Loading dataset from {DATASET_PATH} ...")
    df = pd.read_csv(DATASET_PATH)
    print(f"[INFO] Loaded {len(df)} rows.")

    x = df[FEATURE_COLUMNS]
    y = df[LABEL_COLUMN]

    # 2. Split into training data and testing data --------------------------
    # We hold back 20% of the data as a "test set" the model never trains on,
    # so we can honestly check how well it does on files it hasn't memorized.
    # stratify=y keeps the malware/legitimate ratio the same in both splits.
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[INFO] Training on {len(x_train)} files, testing on {len(x_test)} files.")

    # 3. Train the model ----------------------------------------------------
    # class_weight="balanced" tells the model to pay extra attention to the
    # smaller class (legitimate files are ~26% of this dataset), so it
    # doesn't just learn to guess "malware" all the time.
    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,  # use all CPU cores to train faster
    )
    print("[INFO] Training Random Forest model...")
    model.fit(x_train, y_train)

    # 4. Evaluate it honestly -------------------------------------------------
    predictions = model.predict(x_test)
    accuracy = accuracy_score(y_test, predictions)

    print()
    print(f"[RESULT] Accuracy on unseen test data: {accuracy:.4f}")
    print()
    print("[RESULT] Detailed report (per class):")
    print(classification_report(y_test, predictions, target_names=["Legitimate (0)", "Malware (1)"]))
    print("[RESULT] Confusion matrix:")
    print("            Predicted Legit   Predicted Malware")
    cm = confusion_matrix(y_test, predictions)
    print(f"Actual Legit     {cm[0][0]:>6}            {cm[0][1]:>6}")
    print(f"Actual Malware   {cm[1][0]:>6}            {cm[1][1]:>6}")

    # 5. Show which features mattered most -----------------------------------
    # This helps us "trust but verify" the model - e.g. if it turned out to
    # rely entirely on one weird column, that would be worth investigating.
    importances = pd.Series(model.feature_importances_, index=FEATURE_COLUMNS)
    print()
    print("[INFO] Top 10 most important features:")
    print(importances.sort_values(ascending=False).head(10))

    # 6. Save the trained model to disk --------------------------------------
    # joblib is the standard way to save scikit-learn models. We also save
    # the exact list + order of feature columns, so ml_scanner.py can build
    # a matching row of numbers for any new file it scans.
    os.makedirs(os.path.dirname(MODEL_OUTPUT_PATH), exist_ok=True)
    joblib.dump(model, MODEL_OUTPUT_PATH)
    with open(FEATURE_LIST_OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(FEATURE_COLUMNS, f, indent=2)

    print()
    print(f"[INFO] Model saved to: {MODEL_OUTPUT_PATH}")
    print(f"[INFO] Feature list saved to: {FEATURE_LIST_OUTPUT_PATH}")
    print("[INFO] Done. This model will now be loaded (not retrained) by the app.")


if __name__ == "__main__":
    main()
