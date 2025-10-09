import hashlib
import json
from datetime import datetime

class ThreatBlockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()
    
    def create_genesis_block(self):
        genesis_block = {
            'index': 0,
            'timestamp': str(datetime.now()),
            'data': 'Genesis Block - SafeSpot AI Initialized',
            'previous_hash': '0',
            'hash': self.calculate_hash(0, str(datetime.now()), 'Genesis Block', '0')
        }
        self.chain.append(genesis_block)
    
    def calculate_hash(self, index, timestamp, data, previous_hash):
        value = str(index) + str(timestamp) + str(data) + str(previous_hash)
        return hashlib.sha256(value.encode()).hexdigest()
    
    def add_threat_block(self, threat_data):
        previous_block = self.chain[-1]
        index = len(self.chain)
        timestamp = str(datetime.now())
        previous_hash = previous_block['hash']
        
        block = {
            'index': index,
            'timestamp': timestamp,
            'data': threat_data,
            'previous_hash': previous_hash,
            'hash': self.calculate_hash(index, timestamp, json.dumps(threat_data), previous_hash)
        }
        
        self.chain.append(block)
        return block
    
    def verify_chain(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            
            if current['previous_hash'] != previous['hash']:
                return False
            
            calculated_hash = self.calculate_hash(
                current['index'],
                current['timestamp'],
                json.dumps(current['data']),
                current['previous_hash']
            )
            
            if current['hash'] != calculated_hash:
                return False
        
        return True
    
    def get_threat_blocks(self):
        return [block for block in self.chain if block['index'] > 0]