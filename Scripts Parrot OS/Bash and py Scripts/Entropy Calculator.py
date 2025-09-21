import os
import hashlib
import math
from collections import Counter

def sha384_hash(file_path):
    with open(file_path, "rb") as f:
        return hashlib.sha384(f.read()).hexdigest()

def calculate_entropy(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    counter = Counter(data)
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
    return entropy

def main(scan_folder):
    files = [os.path.join(scan_folder, f) for f in os.listdir(scan_folder) if os.path.isfile(os.path.join(scan_folder, f))]
    highest_entropy = 0
    target_file = None
    target_hash = None

    for file in files:
        entropy = calculate_entropy(file)
        file_hash = sha384_hash(file)
        if entropy > highest_entropy:
            highest_entropy = entropy
            target_file = file
            target_hash = file_hash

    print(f"File with highest entropy: {target_file}")
    print(f"SHA-384 Hash: {target_hash}")
    print(f"Entropy: {highest_entropy}")

if __name__ == "__main__":
    scan_folder = "c:\\Users\\anton\\Desktop\\scan"
    main(scan_folder)
