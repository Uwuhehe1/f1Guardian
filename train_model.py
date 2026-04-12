# train.py
import os
from app import train_and_save, MODEL_PATH, TRAIN_CSV, ML_THRESHOLD

if __name__ == "__main__":
    csv_path = os.getenv("TRAIN_CSV", TRAIN_CSV)
    out_path = os.getenv("MODEL_PATH", MODEL_PATH)
    print(f"📂 Training from: {csv_path}")
    print(f"💾 Saving model to: {out_path}")
    train_and_save(csv_path, out_path, threshold=ML_THRESHOLD)
    print("✅ Training complete.")
