# SafeGuard AI  

## Intelligent Real-Time Harassment Detection System  
**Built for:** Thales GenTech India Hackathon 2025  
**Theme:** Cybersecurity  

---

## Overview  

SafeGuard AI is an intelligent harassment detection system that protects users from online threats in real-time by combining **Artificial Intelligence** and **Blockchain technology**.  

It is designed to detect, record, and prevent online harassment, providing victims with **tamper-proof evidence** and **instant protection**.

---

![Image](https://github.com/user-attachments/assets/721df96f-6e36-4d29-9f75-26912974e348)




## Quick Stats  

| Metric             | Value                      |
|-------------------|----------------------------|
| Detection Speed    | < 500ms per message        |
| Accuracy           | 93%+ on threat detection   |
| Blockchain         | 100% tamper-proof evidence |
| Languages          | English        |

---

## Problem Statement  

### The Crisis  

Online harassment and cyberbullying are serious concerns in India, especially for women.  

- Reports show a steady rise in harassment across social media and digital platforms.  
- Cyberbullying cases have increased significantly since the pandemic, with many incidents going unreported.  
- Victims often struggle to collect digital evidence to support their cases.  
- Major platforms face challenges in real-time detection and moderation.  
- Psychological impacts such as stress, anxiety, and fear of online spaces remain widespread.  

### The Challenge  

Current solutions often lack:  
- Real-time detection  
- Immutable evidence for legal cases  
- Pattern recognition for coordinated attacks   
- Victim-centric design  

---

## Solution  

SafeGuard AI addresses these challenges through a **three-layer protection system**:

### 1. AI Detection Layer  
- Uses pre-trained **Toxic-BERT** model  
- Real-time analysis (< 500ms)  
- Detects: sexual harassment, violent threats, hate speech, abusive language  
- Categorizes severity: HIGH, MEDIUM, LOW  

### 2. Blockchain Evidence Layer  
- Logs every threat to an immutable blockchain  
- Generates tamper-proof evidence for court use  
- Stores: timestamp, threat type, severity, content hash  
- Victims can download evidence reports anytime  

### 3. Pattern Detection Layer  
- Identifies coordinated harassment campaigns  
- Links multiple accounts targeting the same user  
- Detects escalation patterns  
- Alerts users about organized attacks  

**Why Blockchain?**  
- Stores instances securely  
- Tamper-proof: even if the original content is deleted, evidence remains  
- Includes timestamp and threat type for each user  

---

## Pattern Recognition for Coordinated Attacks  

Detects when a user receives multiple threatening or toxic comments from different accounts in a short period.

Flags possible coordinated harassment campaigns instead of treating each comment individually.

Summarizes the attack:

- Number of threats  
- Accounts involved  
- Time span of the attack  

Helps protect users by providing early warnings and allowing for escalation or reporting of organized attacks.

---

## Key Features  

### Beautiful UI/UX  
- Modern gradient design (UX/UI designed with assistance from **Claude AI**)  
- Responsive layout  
- Intuitive navigation  
- Dual views: Post Owner & Commenter  

### AI-Powered Detection  
- Real-time threat analysis  
- Confidence scoring  
- Multi-category detection  

### Blockchain Security  
- Immutable evidence logging  
- SHA-256 hashing  
- Chain verification  
- Built-in Blockchain Explorer  

### Smart Alerts  
- Pattern attack detection  
- Severity gauges  
- Real-time notifications  
- Coordinated attack warnings  

### Analytics Dashboard  
- Live threat statistics  
- Severity and type distribution  
- Timeline visualizations  
- Graphs created using **Plotly** for better insights  
- System performance metrics  

### Evidence Export  
- Download threat reports (CSV)  
- Court-ready documentation  
- Complete incident history  
- Blockchain proof included  

---

## Tech Stack  

| Layer       | Technologies & Notes |
|------------|--------------------|
| **Backend** | Python, Pandas, Hashlib, Transformers (Hugging Face), PyTorch |
| **Frontend** | Streamlit, Plotly, Custom CSS |
| **AI/ML** | Pre-trained Toxic-BERT (used for real-time threat detection), NLP techniques, BERT architecture understanding and implementation |
| **Blockchain** | Custom Python implementation, SHA-256 cryptographic hashing, Chain integrity verification |

---

 

## Personal Contributions and Learning  

- Learned about **BERT** and how it is used for real-time harassment detection.  
- Studied **coordinated attack detection** techniques linking multiple accounts.  
- Learned to create interactive **graphs using Plotly** to visualize attack patterns and threat statistics.  
- Assisted with UX/UI design using **Claude AI**.

---

## Future Scope  

- Language Expansion: Add support for Indian regional languages (Tamil, Bengali, Marathi, Telugu, etc.)  
- Victim Support Network: Integration with helplines, NGOs, and law enforcement for direct reporting  
- Custom Dataset Training: Train on custom dataset to improve accuracy and correct labels (Normal, Neutral, Hate, Sexual harassment, etc.)  
 

---

**SafeGuard AI** — Empowering safer digital spaces with trust, technology, and truth.
