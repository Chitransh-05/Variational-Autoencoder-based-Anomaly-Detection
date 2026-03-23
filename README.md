# 🔐 Network Intrusion Detection System (NIDS)

![Python](https://img.shields.io/badge/Python-3.13-blue?logo=python)
![TensorFlow](https://img.shields.io/badge/TensorFlow-Deep%20Learning-orange?logo=tensorflow)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-ML-yellow?logo=scikitlearn)
![Status](https://img.shields.io/badge/Status-Production%20Ready-success)
![License](https://img.shields.io/badge/License-MIT-green)

🚀 A real-time anomaly-based Network Intrusion Detection System using Isolation Forest, Variational Autoencoder (VAE), and Random Forest on the CICIDS2017-18 dataset.

---

## 📌 Why This Project Matters

Traditional IDS systems rely on signatures, making them ineffective against:
- Zero-day attacks  
- Unknown attack patterns  

This project uses behavior-based anomaly detection to overcome these limitations.

---

## 🎯 Key Achievements

- Reduced False Alarm Rate from 10.54% → 1.77%
- Improved Precision from 48.6% → 85.29%
- Real-time packet processing (~90 packets/sec)
- Deep learning-based anomaly detection (VAE)
- Production-ready pipeline

---

## 🧠 Dataset

- CICIDS2017-18
- ~2.5M flows
- 52 features
- 80/20 split

---

## 🏗️ Architecture

Raw Packets → Flow Aggregation → Feature Extraction → Normalization → Model Inference → Alerts

---

## 🤖 Models

### Isolation Forest
- Accuracy: ~82.64%
- Precision: ~48.6%
- Recall: ~49%
- FAR: ~10.54%

### Variational Autoencoder
- Accuracy: 90.17%
- Precision: 85.29%
- Recall: 50.51%
- FAR: 1.77%

### Random Forest
- Multi-class attack classification

---

## 🚀 How to Run

### 1. Clone
```
git clone https://github.com/your-username/NIDS-Project.git
cd NIDS-Project
```

### 2. Install Dependencies
```
pip install -r requirements.txt
```

### 3. Prepare Dataset
Place dataset files in:
```
data/processed/
```

Required files:
- X_train.csv  
- y_train.csv  
- X_test.csv  
- y_test.csv  

---

### 4. Run Training Pipeline

Execute notebooks in order:

1. 01_data_exploration.ipynb  
2. 02_data_preprocessing.ipynb  
3. 03_baseline_isolation_forest.ipynb  
4. 05_advanced_VAE.ipynb  
5. 04_Random_Forest_multiclass.ipynb  

---

### 5. Run Real-Time Detection

Start packet capture engine:
```
07_packet_capture_engine.ipynb
```

---

### 6. Launch Web Dashboard

After running the detection system, start the dashboard:

```
python app.py
```

Then open your browser and go to:
```
http://localhost:5000
```

---

## 📊 Results & Outputs

All model outputs are stored in the **results/** folder, including:

- Confusion matrices  
- Performance metrics  
- Graphs and visualizations  
- Model evaluation reports  

---

## 📊 Insights

- VAE drastically reduces false positives
- Better precision, similar recall
- Suitable for real-world deployment

---

## ⚠️ Limitations

- Recall ~50%
- Static threshold
- Dataset dependency

---

## 🔮 Future Work

- Adaptive thresholding  
- LSTM/Transformer models  
- SIEM integration  
- Performance optimization  

---

## 👨‍💻 Author

**Chitransh Mathur**  
Cybersecurity Enthusiast | Network Security | Anomaly Detection | ML-based IDS  

I am a Computer Science Engineering student with a strong focus on Cybersecurity, particularly in:

- Network Intrusion Detection Systems (NIDS)  
- Anomaly Detection using Machine Learning & Deep Learning  
- Malware Analysis and Threat Intelligence  
- Real-time security system design  

This project demonstrates building production-oriented security solutions combining ML, DL, and network analysis.

📄 A research paper based on this project is currently in progress.

🚀 Aspiring Red Team / Security Engineer.
