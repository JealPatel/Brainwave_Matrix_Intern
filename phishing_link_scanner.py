import re
import tldextract

def extract_features(url):
    """
    Extracts features from a given URL for phishing detection.
    Returns a dictionary of feature flags.
    """
    features = {}

    # Feature 1: Does the URL use an IP address?
    features['has_ip'] = bool(re.match(r"http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url))

    # Feature 2: Does it contain an "@" symbol?
    features['has_at'] = '@' in url

    # Feature 3: Is the URL long?
    features['length'] = len(url)

    # Feature 4: Does it contain hyphens?
    features['has_hyphen'] = '-' in url

    # Feature 5: Is the TLD suspicious?
    suspicious_tlds = ['xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq']
    tld = tldextract.extract(url).suffix
    features['suspicious_tld'] = tld in suspicious_tlds

    return features


def is_phishing(url):
    """
    Uses extracted features to determine if a URL is likely phishing.
    Returns True if suspicious, False otherwise.
    """
    features = extract_features(url)
    score = 0

    if features['has_ip']:
        score += 1
    if features['has_at']:
        score += 1
    if features['length'] > 75:
        score += 1
    if features['has_hyphen']:
        score += 1
    if features['suspicious_tld']:
        score += 1

    # If 3 or more red flags, mark as phishing
    return score >= 3


def main():
    print("🔍 Phishing Link Scanner 🔍")
    print("----------------------------")

    while True:
        url = input("\nEnter a URL to scan (or type 'exit' to quit): ").strip()

        if url.lower() == 'exit':
            print("Goodbye!")
            break

        try:
            result = is_phishing(url)

            if result:
                print("⚠️ Warning: This might be a phishing URL!")
            else:
                print("✅ This URL looks safe.")
        except Exception as e:
            print(f"Error processing the URL: {e}")


if __name__ == "__main__":
    main()
