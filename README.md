# ENHANCED-INTRUSION-DETECTION-SYSTEM-USING-DL-WITH-XAI-AND-GEN-AI-
This repository has the project file of intrusion detection which aim to detect threats in network logs
This project implements an advanced network intrusion detection system using deep learning techniques with GAN enhancement. The application provides both manual and automatic detection modes with explainable AI features.

## System Requirements

- **Python Version**: 3.10.0 (Strict requirement)
- **IDE**: Visual Studio Code (recommended)
- **Operating System**: Windows/Linux/MacOS
- **streamlit**
- **numpy==1.26.4**
- **pandas==2.2.2**
- **tensorflow==2.17.1**
- **lime==0.2.0.1**
- **scikit-learn==1.5.2****

## Using the Application

1. **Login/Register**: Use the default admin account (username: admin, password: password) or register a new account
2. **Dashboard**: View system status and recent activity
3. **Manual Detection**: Input network traffic parameters manually
4. **Automatic Detection**: Upload a CSV file or use the included sample dataset
5. **Model Performance**: Compare different approaches and see the impact of GAN enhancement

## Project Structure

- `app1.py`: Main application file
- `requirements.txt`: Required Python packages
- `cnn_model.keras`: Trained CNN model
- `lstm_model.keras`: Trained LSTM model
- `scaler.pkl`: Feature scaler for input normalization
- `balanced_sample_100_row_per_attack_cat.csv`: Sample dataset for testing
