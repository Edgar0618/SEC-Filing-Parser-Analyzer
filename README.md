# 📊 SEC Filing Parser & Analyzer

A powerful financial document analysis tool that extracts and visualizes insights from SEC filings and earnings reports. Built with Flask, MongoDB, and real-time stock data integration.

## 🚀 Features

- **PDF Document Scanning**: Parse and extract key financial metrics from 10-Q filings
- **Earnings Analysis**: Real-time stock data visualization with yFinance integration
- **Company Comparison**: Compare financial metrics across different companies and industries
- **User Authentication**: Secure user management with encrypted password storage
- **Interactive Charts**: Beautiful visualizations of financial data and trends

## 📋 Prerequisites

- Python 3.8+
- MongoDB
- pip (Python package manager)

## ⚙️ Installation

### 1. Install MongoDB

On macOS:
```bash
brew tap mongodb/brew
brew install mongodb-community
brew services start mongodb/brew/mongodb-community
```

For other operating systems, visit [MongoDB Installation Guide](https://docs.mongodb.com/manual/installation/)

### 2. Clone the Repository

```bash
git clone https://github.com/Edgar0618/SEC-Filing-Parser-Analyzer.git
cd "SEC Filing Parser & Analyzer"
```

### 3. Set Up Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 4. Install Dependencies

```bash
pip install flask pymongo yfinance matplotlib pymupdf
```

Or use the requirements file (if available):
```bash
pip install -r requirements.txt
```

## 🏃 Running the Application

1. Make sure MongoDB is running:
   ```bash
   brew services start mongodb/brew/mongodb-community
   ```

2. Start the Flask application:
   ```bash
   python app.py
   ```

3. Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

## 🗄️ Database Management (Optional)

### Using MongoDB Shell

Install mongosh:
```bash
brew install mongosh
```

Connect to the database:
```bash
mongosh
use userDatabase
```

View registered users:
```bash
db.users.find({}, { password: 0, _id: 0 })
```

## 📁 Project Structure

```
SEC-Filing-Parser-Analyzer/
├── app.py                  # Main Flask application
├── Database.py             # MongoDB connection and queries
├── PasswordHashing.py      # Password encryption utilities
├── templates/              # HTML templates
│   ├── index.html
│   ├── login.html
│   ├── earnings_report.html
│   └── ...
└── forTesting/            # Testing files and examples
```

## 🛠️ Tech Stack

- **Backend**: Flask (Python)
- **Database**: MongoDB
- **Financial Data**: yFinance API
- **Data Visualization**: Matplotlib
- **PDF Processing**: PyMuPDF
- **Authentication**: Custom password hashing

## 📝 Notes

- The `.gitignore` file ensures virtual environments and sensitive files are not tracked
- Make sure MongoDB is running before starting the application
- Default Flask port is 5000 (can be changed in app.py)

## 🤝 Contributing

Feel free to fork this repository and submit pull requests for any improvements!

## 📄 License

This project is open source and available under the MIT License.

---

Built with ❤️ for financial analysis enthusiasts
