# 🔐 Phishing URL Detection using Machine Learning with CI/CD Automation

A DevOps-oriented Machine Learning project that detects phishing URLs using only URL-based features, integrated with Git version control and CI/CD automation using GitHub Actions.

---

## 📌 Overview

Phishing attacks are one of the most common cybersecurity threats, where attackers create malicious websites that closely resemble legitimate ones to steal sensitive information such as login credentials and financial details.

This project presents an **end-to-end phishing URL detection system** using **Machine Learning**, combined with **DevOps best practices** such as Git-based version control and **CI/CD automation** using GitHub Actions.

The system classifies URLs as **legitimate or phishing** using only **URL-based features**, making it lightweight, fast, and suitable for real-time usage without relying on webpage content, HTML, JavaScript, or external services.

---

## 🎯 Key Highlights

- ✅ URL-based phishing detection (no HTML / JS / WHOIS dependency)
- ✅ Robust feature engineering on URL structure and lexical patterns
- ✅ XGBoost classifier for high accuracy and strong ROC-AUC
- ✅ Interactive Streamlit web application for real-time prediction
- ✅ CI/CD pipeline using GitHub Actions for automated validation
- ✅ Clean, reproducible, and resume-ready project structure
- ✅ DevOps-centric workflow with version control and automation

---

## 🧠 Machine Learning Approach

- **Problem Type:** Binary Classification (Phishing vs Legitimate)
- **Model Used:** XGBoost Classifier
- **Why XGBoost?**
  - Handles non-linear patterns
  - Robust to outliers
  - High performance on tabular data
  - Suitable for real-world ML systems

### Feature Engineering (URL-Based)
Examples of features used:
- URL length
- Number of dots
- Number of subdomains
- Digit ratio in URL
- Suspicious keywords
- Prefix–suffix patterns
- Random domain detection

> ⚠️ HTML-based and external features were intentionally removed to ensure real-time usability and DevOps compatibility.

---

## 🖥️ Web Application (Streamlit)

A Streamlit web interface allows users to:
- Enter a URL
- View classification result (Legitimate / Phishing)
- See confidence score
- Visualize extracted features

---

## ⚙️ DevOps & CI/CD Integration

This project follows a **Git-centric DevOps workflow**:

- Git for local version control
- GitHub as remote repository (single source of truth)
- GitHub Actions for Continuous Integration (CI)
- Automated dependency installation
- Automated validation on every push

### CI Pipeline Tasks
- Checkout repository
- Set up Python environment
- Install dependencies from `requirements.txt`
- Run CI sanity checks

---

## 📂 Project Structure

<img width="818" height="640" alt="image" src="https://github.com/user-attachments/assets/a98c702a-6e6f-4624-a2b5-8a315aa92791" />



---

## 🛠️ Tools & Technologies

- **Programming Language:** Python
- **Machine Learning:** Scikit-learn, XGBoost
- **Data Processing:** Pandas, NumPy
- **Visualization:** Matplotlib, Seaborn
- **Web Interface:** Streamlit
- **DevOps Tools:** Git, GitHub
- **CI/CD Automation:** GitHub Actions
- **IDE:** Visual Studio Code

---

## 🚀 Git & DevOps Workflow (Commands Used)

 📊 Outcome of the Project

✔️ Successfully implemented phishing URL detection system

✔️ Achieved high accuracy and strong ROC-AUC

✔️ Built real-time prediction web application

✔️ Implemented Git-based version control

✔️ Automated validation using CI/CD pipeline

✔️ Gained hands-on DevOps + ML integration experience

✔️ Created a resume-worthy, industry-aligned project

-----------------

🧾 Conclusion

This project demonstrates how Machine Learning systems can be effectively managed using DevOps principles. By integrating Git version control and CI/CD automation with a phishing detection application, the project ensures reliability, traceability, and automation in modern software development workflows.

It strongly aligns with DevOps fundamentals, academic evaluation standards, and industry practices.

🔗 Repository Link

👉 GitHub: https://github.com/Mahajan-Sachin/Phishing

👤 Author

Sachin Mahajan
B.Tech CSE (AI/ML)
Lovely Professional University
