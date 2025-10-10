import hashlib
import json
from datetime import datetime
import time
from transformers import pipeline
from blockchain import ThreatBlockchain


# Load model
def load_model():
    return pipeline("text-classification", model="unitary/toxic-bert")

try:
    classifier = load_model()
    model_loaded = True
except Exception as e:
    model_loaded = False


# Detect threat
def detect_threat(text, response_times=None):
    start_time = time.time()
    result = classifier(text)[0]
    end_time = time.time()

    resp_time = (end_time - start_time) * 1000  # ms
    if response_times is not None:
        response_times.append(resp_time)

    score = result['score']
    if score > 0.5:
        text_lower = text.lower()
        if any(word in text_lower for word in ['rape', 'r***', 'molest', 'sexual', 'fuck']):
            threat_type = 'SEXUAL_HARASSMENT'
        elif any(word in text_lower for word in ['kill', 'hurt', 'murder', 'beat', 'die', 'dead']):
            threat_type = 'Violent Threat'
        elif any(word in text_lower for word in ['hate', 'religion', 'muslim', 'hindu', 'christian']):
            threat_type = 'Hate Speech'
        else:
            threat_type = 'Abusive Language'

        if score > 0.9:
            severity = 'HIGH'
        elif score > 0.7:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'

        return {
            'is_threat': True,
            'threat_type': threat_type,
            'severity': severity,
            'confidence': score,
            'response_time': resp_time
        }
    else:
        return {
            'is_threat': False,
            'confidence': 1 - score,
            'response_time': resp_time
        }


# This will be used for pattern-attack detection
def get_watch_group():
    return ["alice", "bob", "John"]

def check_pattern_attack(threat_history, watched_users=None, lookback=5, window_minutes=5):

    if len(threat_history) < 2:
        return None

    recent = threat_history[-lookback:]

    if watched_users:
        recent = [t for t in recent if t.get("username") in watched_users]

    if len(recent) <= 2:
        return None

    time_diffs = []
    parsed_times = []
    for t in recent:
        try:
            parsed_times.append(datetime.strptime(t['timestamp'], "%Y-%m-%d %H:%M:%S"))
        except Exception as e:
            continue

    if len(parsed_times) < 2:
        return None

    for i in range(1, len(parsed_times)):
        diff_min = (parsed_times[i] - parsed_times[i-1]).total_seconds() / 60.0
        time_diffs.append(diff_min)


    if any(d < window_minutes for d in time_diffs):
        return {
            "attack_detected": True,
            "threat_count": len(recent),
            "accounts": list(set([t.get("username", "Unknown") for t in recent])),
            "time_span": f"{max(time_diffs):.1f} minutes"
        }

    return None


chain = ThreatBlockchain()
threat_history = []
response_times = []


while True:
    mode = input("Choose mode (1 = Normal Check, 2 = Pattern Attack (single comment only), 'exit' to quit): ").strip()
    if mode.lower() == "exit":
        break

    if mode == "1":
        text = input("Enter a comment: ").strip()
        username = input("Enter username: ").strip()

        result = detect_threat(text, response_times)

        if result['is_threat']:
            threat_data = {
                'incident_id': f"INC_{len(chain.chain)}",
                'text_hash': hashlib.sha256(text.encode()).hexdigest()[:16],
                'threat_type': result['threat_type'],
                'severity': result['severity'],
                'confidence': f"{result['confidence']:.2%}",
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'username': username
            }
            chain.add_threat_block(threat_data)
            threat_history.append(threat_data)
            print(f"Threat detected and logged for {username}: {result['threat_type']} ({result['severity']})")
        else:
            print("Safe comment")

    elif mode == "2":
        text = input("Enter a single comment to simulate across the watched group: ").strip()
        watched = get_watch_group()

        for w in watched:
            result = detect_threat(text, response_times)
            if result['is_threat']:
                threat_data = {
                    'incident_id': f"INC_{len(chain.chain)}",
                    'text_hash': hashlib.sha256(text.encode()).hexdigest()[:16],
                    'threat_type': result['threat_type'],
                    'severity': result['severity'],
                    'confidence': f"{result['confidence']:.2%}",
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'username': w
                }
                chain.add_threat_block(threat_data)
                threat_history.append(threat_data)
                print(f"Logged threat for {w}: {result['threat_type']} ({result['severity']})")
            else:
                print(f"{w}: Safe (not logged)")

       
        pattern = check_pattern_attack(threat_history, watched_users=watched, lookback=5, window_minutes=5)
        if pattern:
            print("\nPATTERN ATTACK DETECTED!")
            print(f"Threat count: {pattern['threat_count']}")
            print(f"Accounts: {pattern['accounts']}")
            print(f"Time span: {pattern['time_span']}")
        else:
            print("No pattern attack detected (not enough threat events in the window).")

    else:
        print("Invalid mode. Choose 1, 2 or 'exit'.")


    
    for block in chain.get_threat_blocks():
        print(json.dumps(block, indent=4))
