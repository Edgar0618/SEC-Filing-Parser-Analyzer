from flask import Flask, render_template, request, redirect, url_for, session, render_template_string, jsonify
from Database import createConnection, createCollection, registerUser, login, logScan
from PasswordHashing import hash_password, verify_password
import yfinance as yf
# Removed matplotlib - using Chart.js instead for better performance and smaller bundle size
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import time
import json
import fitz  # PyMuPDF
import re

app = Flask(__name__)
app.secret_key = '1'

sector_companies = {
    "Financial": ["AGBA", "SQQQ", "TQQQ", "SPY", "MARA"],
    "Tech": ["MTTR", "NVDA", "AMD", "AAPL", "INTC"],
    "Communication_services": ["T", "VZ", "AMC", "GOOGL", "SNAP"],
    "Healthcare": ["JAGX", "NIVF", "MLEC", "DNA", "SINT"],
    "Energy": ["PBR", "TEL", "RIG", "KMI", "XOM"],
    "Utilities": ["NEE", "PCG", "AES", "SO", "EXC"],
    "Consumer_Cyclical": ["TSLA", "F", "NIO", "FFIE", "AMZN"],
    "Industrials": ["SPCB", "NKLA", "FCEL", "SPCE", "AAL"],
    "Real_Estate": ["AGNC", "MPW", "VICI", "OPEN", "BEKE"],
    "Basic_Materials": ["VALE", "GOLD", "KGC", "FCX", "BTG"],
    "Consumer_Defensive": ["KVUE", "EDBL", "KO", "WMT", "ABEV"]
}

sample_earnings = {
    'last_year':[20000, 25000, 18000, 30000],
    'this_year':[0,0,0,0]
}

def generate_chart_data(q1, q2, q3, q4):
    """Generate Chart.js compatible data instead of matplotlib"""
    quarters = ['Q1', 'Q2', 'Q3', 'Q4']
    values = [float(q1), float(q2), float(q3), float(q4)]
    
    chart_data = {
        'labels': quarters,
        'datasets': [{
            'label': 'Earnings',
            'data': values,
            'backgroundColor': ['#00c805', '#00e006', '#00c805', '#00e006'],
            'borderColor': '#ffffff',
            'borderWidth': 2,
            'tension': 0.1
        }]
    }
    return chart_data

def generate_balance_sheet_chart(data):
    """Generate balance sheet chart data for Chart.js"""
    categories = ['Current Assets', 'Total Assets', 'Current Liabilities', 'Stockholders Equity', 'Total Liabilities & Equity']
    values_2022 = [
        float(data['total_current_assets']['2022']),
        float(data['total_assets']['2022']),
        float(data['total_current_liabilities']['2022']),
        float(data['total_stockholders_equity']['2022']),
        float(data['total_liabilities_and_stockholders_equity']['2022'])
    ]
    values_2023 = [
        float(data['total_current_assets']['2023']),
        float(data['total_assets']['2023']),
        float(data['total_current_liabilities']['2023']),
        float(data['total_stockholders_equity']['2023']),
        float(data['total_liabilities_and_stockholders_equity']['2023'])
    ]
    
    chart_data = {
        'labels': categories,
        'datasets': [
            {
                'label': '2022',
                'data': values_2022,
                'backgroundColor': '#00c805',
                'borderColor': '#ffffff',
                'borderWidth': 2
            },
            {
                'label': '2023',
                'data': values_2023,
                'backgroundColor': '#ff6b6b',
                'borderColor': '#ffffff',
                'borderWidth': 2
            }
        ]
    }
    return chart_data

def generate_operations_chart(data):
    """Generate operations chart data for Chart.js"""
    categories = ['Cash Beginning', 'Net Income', 'Operating Cash', 'Investing Cash', 'Financing Cash', 'Cash End']
    values_2022 = [
        float(data['cash_beginning']['2022']),
        float(data['net_income']['2022']),
        float(data['net_operating_cash']['2022']),
        float(data['net_investing_cash']['2022']),
        float(data['net_financing_cash']['2022']),
        float(data['cash_end']['2022'])
    ]
    values_2023 = [
        float(data['cash_beginning']['2023']),
        float(data['net_income']['2023']),
        float(data['net_operating_cash']['2023']),
        float(data['net_investing_cash']['2023']),
        float(data['net_financing_cash']['2023']),
        float(data['cash_end']['2023'])
    ]
    
    chart_data = {
        'labels': categories,
        'datasets': [
            {
                'label': '2022',
                'data': values_2022,
                'borderColor': '#00c805',
                'backgroundColor': 'rgba(0, 200, 5, 0.1)',
                'borderWidth': 3,
                'tension': 0.4
            },
            {
                'label': '2023',
                'data': values_2023,
                'borderColor': '#ff6b6b',
                'backgroundColor': 'rgba(255, 107, 107, 0.1)',
                'borderWidth': 3,
                'tension': 0.4
            }
        ]
    }
    return chart_data

def generate_cash_flows_chart(data):
    """Generate cash flows chart data for Chart.js"""
    categories = ['Net Sales', 'Operating Expenses', 'Net Income', 'Weighted Shares Basic', 'Diluted Shares Basic']
    values_2022 = [
        float(data['total_net_sales']['2022']),
        float(data['total_operating_expenses']['2022']),
        float(data['net_income']['2022']),
        float(data['weighted_average_shares_basic']['2022']),
        float(data['diluted_average_shares_basic']['2022'])
    ]
    values_2023 = [
        float(data['total_net_sales']['2023']),
        float(data['total_operating_expenses']['2023']),
        float(data['net_income']['2023']),
        float(data['weighted_average_shares_basic']['2023']),
        float(data['diluted_average_shares_basic']['2023'])
    ]
    
    chart_data = {
        'labels': categories,
        'datasets': [
            {
                'label': '2022',
                'data': values_2022,
                'borderColor': '#00c805',
                'backgroundColor': '#00c805',
                'borderWidth': 2,
                'pointRadius': 6,
                'pointHoverRadius': 8
            },
            {
                'label': '2023',
                'data': values_2023,
                'borderColor': '#ff6b6b',
                'backgroundColor': '#ff6b6b',
                'borderWidth': 2,
                'pointRadius': 6,
                'pointHoverRadius': 8
            }
        ]
    }
    return chart_data

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'pdf'

def extract_financial_data(pdf_path):
    doc = fitz.open(pdf_path)
    text = ""
    for page in doc:
        text += page.get_text()
    doc.close()

    # Financial data extraction patterns
    data = {}
    
    # Current Assets
    current_assets_2022 = re.search(r'Total current assets.*?2022.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    current_assets_2023 = re.search(r'Total current assets.*?2023.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    
    data['total_current_assets'] = {
        '2022': current_assets_2022.group(1).replace(',', '') if current_assets_2022 else '0',
        '2023': current_assets_2023.group(1).replace(',', '') if current_assets_2023 else '0'
    }
    
    # Total Assets
    total_assets_2022 = re.search(r'Total assets.*?2022.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    total_assets_2023 = re.search(r'Total assets.*?2023.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    
    data['total_assets'] = {
        '2022': total_assets_2022.group(1).replace(',', '') if total_assets_2022 else '0',
        '2023': total_assets_2023.group(1).replace(',', '') if total_assets_2023 else '0'
    }
    
    # Current Liabilities
    current_liabilities_2022 = re.search(r'Total current liabilities.*?2022.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    current_liabilities_2023 = re.search(r'Total current liabilities.*?2023.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    
    data['total_current_liabilities'] = {
        '2022': current_liabilities_2022.group(1).replace(',', '') if current_liabilities_2022 else '0',
        '2023': current_liabilities_2023.group(1).replace(',', '') if current_liabilities_2023 else '0'
    }
    
    # Stockholders Equity
    stockholders_equity_2022 = re.search(r'Total stockholders\' equity.*?2022.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    stockholders_equity_2023 = re.search(r'Total stockholders\' equity.*?2023.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    
    data['total_stockholders_equity'] = {
        '2022': stockholders_equity_2022.group(1).replace(',', '') if stockholders_equity_2022 else '0',
        '2023': stockholders_equity_2023.group(1).replace(',', '') if stockholders_equity_2023 else '0'
    }
    
    # Total Liabilities and Stockholders Equity
    total_liab_equity_2022 = re.search(r'Total liabilities and stockholders\' equity.*?2022.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    total_liab_equity_2023 = re.search(r'Total liabilities and stockholders\' equity.*?2023.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    
    data['total_liabilities_and_stockholders_equity'] = {
        '2022': total_liab_equity_2022.group(1).replace(',', '') if total_liab_equity_2022 else '0',
        '2023': total_liab_equity_2023.group(1).replace(',', '') if total_liab_equity_2023 else '0'
    }
    
    # Net Income
    net_income_2022 = re.search(r'Net income.*?2022.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    net_income_2023 = re.search(r'Net income.*?2023.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    
    data['net_income'] = {
        '2022': net_income_2022.group(1).replace(',', '') if net_income_2022 else '0',
        '2023': net_income_2023.group(1).replace(',', '') if net_income_2023 else '0'
    }
    
    # Cash flows
    cash_beginning_2022 = re.search(r'Cash, cash equivalents.*?beginning.*?2022.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    cash_beginning_2023 = re.search(r'Cash, cash equivalents.*?beginning.*?2023.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    
    data['cash_beginning'] = {
        '2022': cash_beginning_2022.group(1).replace(',', '') if cash_beginning_2022 else '0',
        '2023': cash_beginning_2023.group(1).replace(',', '') if cash_beginning_2023 else '0'
    }
    
    # Operating cash
    operating_cash_2022 = re.search(r'Net cash provided by.*?operating.*?2022.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    operating_cash_2023 = re.search(r'Net cash provided by.*?operating.*?2023.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    
    data['net_operating_cash'] = {
        '2022': operating_cash_2022.group(1).replace(',', '') if operating_cash_2022 else '0',
        '2023': operating_cash_2023.group(1).replace(',', '') if operating_cash_2023 else '0'
    }
    
    # Investing cash
    investing_cash_2022 = re.search(r'Net cash used in investing.*?2022.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    investing_cash_2023 = re.search(r'Net cash used in investing.*?2023.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    
    data['net_investing_cash'] = {
        '2022': investing_cash_2022.group(1).replace(',', '') if investing_cash_2022 else '0',
        '2023': investing_cash_2023.group(1).replace(',', '') if investing_cash_2023 else '0'
    }
    
    # Financing cash
    financing_cash_2022 = re.search(r'Net cash provided by.*?financing.*?2022.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    financing_cash_2023 = re.search(r'Net cash provided by.*?financing.*?2023.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    
    data['net_financing_cash'] = {
        '2022': financing_cash_2022.group(1).replace(',', '') if financing_cash_2022 else '0',
        '2023': financing_cash_2023.group(1).replace(',', '') if financing_cash_2023 else '0'
    }
    
    # Cash end
    cash_end_2022 = re.search(r'Cash, cash equivalents.*?end.*?2022.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    cash_end_2023 = re.search(r'Cash, cash equivalents.*?end.*?2023.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    
    data['cash_end'] = {
        '2022': cash_end_2022.group(1).replace(',', '') if cash_end_2022 else '0',
        '2023': cash_end_2023.group(1).replace(',', '') if cash_end_2023 else '0'
    }
    
    # Net Sales
    net_sales_2022 = re.search(r'Total net sales.*?2022.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    net_sales_2023 = re.search(r'Total net sales.*?2023.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    
    data['total_net_sales'] = {
        '2022': net_sales_2022.group(1).replace(',', '') if net_sales_2022 else '0',
        '2023': net_sales_2023.group(1).replace(',', '') if net_sales_2023 else '0'
    }
    
    # Operating Expenses
    operating_expenses_2022 = re.search(r'Total operating expenses.*?2022.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    operating_expenses_2023 = re.search(r'Total operating expenses.*?2023.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    
    data['total_operating_expenses'] = {
        '2022': operating_expenses_2022.group(1).replace(',', '') if operating_expenses_2022 else '0',
        '2023': operating_expenses_2023.group(1).replace(',', '') if operating_expenses_2023 else '0'
    }
    
    # Weighted Average Shares Basic
    weighted_shares_2022 = re.search(r'Weighted average shares basic.*?2022.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    weighted_shares_2023 = re.search(r'Weighted average shares basic.*?2023.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    
    data['weighted_average_shares_basic'] = {
        '2022': weighted_shares_2022.group(1).replace(',', '') if weighted_shares_2022 else '0',
        '2023': weighted_shares_2023.group(1).replace(',', '') if weighted_shares_2023 else '0'
    }
    
    # Diluted Average Shares Basic
    diluted_shares_2022 = re.search(r'Diluted average shares basic.*?2022.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    diluted_shares_2023 = re.search(r'Diluted average shares basic.*?2023.*?(\d+(?:,\d{3})*(?:\.\d{2})?)', text, re.IGNORECASE | re.DOTALL)
    
    data['diluted_average_shares_basic'] = {
        '2022': diluted_shares_2022.group(1).replace(',', '') if diluted_shares_2022 else '0',
        '2023': diluted_shares_2023.group(1).replace(',', '') if diluted_shares_2023 else '0'
    }
    
    return data

@app.route('/')
def index():
    if 'username' in session:
        db = createConnection()
        user = db.users.find_one({"username": session['username']})
        if user:
            return render_template('index.html', name=user['name'], is_logged_in=True)
        else:
            return "User not found!", 404
    return render_template('index.html', name="Guest", is_logged_in=False)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        try:
            db = createConnection()
            createCollection(db)
            # Support minimal forms (username/password only)
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            # Optional fields defaulted for simplified UI
            name = request.form.get('name', username)
            date_of_birth = request.form.get('date_of_birth', '')
            admin_checked = 'admin' in request.form
            secret_key = request.form.get('secret_key', '')

            correct_secret_key = "admin"
            is_admin = admin_checked and secret_key == correct_secret_key

            # Basic validation
            if not username or not password:
                raise Exception('Username and password are required')

            success, message = registerUser(db, username, password, name, date_of_birth, is_admin)
            if success:
                return redirect(url_for('index'))
            else:
                error = message
        except Exception as e:
            error = "Registration failed: " + str(e)
            print("Registration error: " + str(e))

    return render_template('register.html', error=error)

@app.route('/admindashboard')
def admin_dashboard():
    if 'username' in session:
        db = createConnection()
        user = db.users.find_one({"username": session['username']})
        if user and user.get('is_admin', False):
            users = db.users.find({})
            return render_template('admindashboard.html', users=users)
        else:
            return redirect(url_for('index'))
    return redirect(url_for('login_page'))

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if 'username' in session:
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':
        try:
            db = createConnection()
            username = request.form['username']
            password = request.form['password']
            hashed_password = hash_password(password)

            success, user = login(db, username, hashed_password)
            if success:
                session['username'] = username
                return redirect(url_for('index'))
            else:
                error = "Invalid username or password"
        except Exception as e:
            error = "Login failed: " + str(e)
            print("Login error: " + str(e))

    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))

        db = createConnection()
        user = db.users.find_one({"username": session['username']})
    if not user:
        return redirect(url_for('login'))

    # Get scan history
    scan_history = db.scans.find({"username": session['username']}).sort("date", -1).limit(10)

    return render_template('profile.html', 
                         name=user['name'], 
                         username=user['username'],
                         scan_history=scan_history)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    message = None
    if request.method == 'POST':
        db = createConnection()
        username = session['username']
        current_password = request.form['current_password']
        new_password = request.form['new_password']

        # Verify current password
        user = db.users.find_one({"username": username})
        if user and verify_password(current_password, user['password']):
            # Update password
            hashed_new_password = hash_password(new_password)
            db.users.update_one(
                {"username": username},
                {"$set": {"password": hashed_new_password}}
            )
            message = "Password changed successfully!"
        else:
            message = "Current password is incorrect"

    return render_template('change_password.html', message=message)

@app.route('/earnings_report', methods=['GET', 'POST'])
def earnings_report():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    db = createConnection()
    user = db.users.find_one({"username": session['username']})
    if not user:
        return redirect(url_for('login'))
    
    # Get live market data
    tickers = ['AAPL', 'GOOGL', 'MSFT', 'TSLA', 'AMZN']
    data = {}
    
    def get_price(ticker):
        try:
            stock = yf.Ticker(ticker)
            price = stock.history(period='1d')['Close'].iloc[-1]
            return ticker, f"${price:.2f}"
        except:
            return ticker, "N/A"
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(get_price, ticker) for ticker in tickers]
        for future in as_completed(futures):
            ticker, price = future.result()
            data[ticker] = price
    
    chart_data = None
    if request.method == 'POST':
        q1 = request.form.get('Q1', '0')
        q2 = request.form.get('Q2', '0') 
        q3 = request.form.get('Q3', '0')
        q4 = request.form.get('Q4', '0')
        
        if q1 and q2 and q3 and q4:
            chart_data = generate_chart_data(q1, q2, q3, q4)
    
    return render_template('earnings_report.html', 
                         data=data, 
                         chart_data=json.dumps(chart_data) if chart_data else None,
                         name=user['name'])

@app.route('/compare', methods=['GET', 'POST'])
def compare():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    db = createConnection()
    user = db.users.find_one({"username": session['username']})
    if not user:
        return redirect(url_for('login'))
    
    results = None
    sector = None
    option = None
    message = None
    
    if request.method == 'POST':
        sector = request.form['sectors']
        option = request.form['options']
        
        companies = sector_companies.get(sector, [])
        results = []
        
        def get_financial_data(symbol):
            try:
                stock = yf.Ticker(symbol)
                info = stock.info
                
                if option == "Revenue":
                    value = info.get('totalRevenue', 'N/A')
                elif option == "Operating Income":
                    value = info.get('operatingIncome', 'N/A')
                elif option == "Net Income":
                    value = info.get('netIncome', 'N/A')
                elif option == "Earnings Per Share":
                    value = info.get('trailingEps', 'N/A')
                elif option == "Profit":
                    value = info.get('grossProfits', 'N/A')
                else:
                    value = 'N/A'
                
                return symbol, value
            except:
                return symbol, 'N/A'
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(get_financial_data, company) for company in companies]
            for future in as_completed(futures):
                symbol, value = future.result()
                if value != 'N/A':
                    results.append((symbol, value))
        
        if not results:
            message = "No data available for this sector"
    
    return render_template('compare.html', 
                         results=results, 
                         sector=sector, 
                         option=option, 
                         message=message,
                         name=user['name'])

@app.route('/instructions')
def instructions():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    db = createConnection()
    user = db.users.find_one({"username": session['username']})
    if not user:
        return redirect(url_for('login'))
    
    return render_template('instructions.html', name=user['name'])

# 60s cache to avoid rate limits
_ticker_cache = {'ts': 0, 'items': []}

@app.route('/live_ticker')
def live_ticker():
    # small cache window to reduce delay
    if time.time() - _ticker_cache['ts'] < 15 and _ticker_cache['items']:
        return jsonify({'items': _ticker_cache['items']})

    # Symbols and display names
    symbols = [
        '^DJI', '^GSPC', '^IXIC', '^VIX', 'SPY', 'QQQ',
        'AAPL', 'MSFT', 'GOOGL', 'AMZN', 'TSLA', 'NVDA', 'META', 'NFLX', 'AMD',
        'BRK-B', 'JPM', 'BAC', 'COST', 'WMT', 'NKE', 'UNH', 'XOM', 'CVX', 'V', 'MA',
        'BTC-USD', 'ETH-USD', 'GC=F', 'SI=F', 'CL=F'
    ]
    display = {
        '^DJI': 'DOW', '^GSPC': 'S&P 500', '^IXIC': 'NASDAQ', '^VIX': 'VIX',
        'GC=F': 'GOLD', 'SI=F': 'SILVER', 'CL=F': 'CRUDE',
        'BRK-B': 'BRK.B'
    }

    url = 'https://query1.finance.yahoo.com/v7/finance/quote'
    items = []

    try:
        resp = requests.get(url, params={'symbols': ','.join(symbols)}, timeout=5)
        data = resp.json().get('quoteResponse', {}).get('result', [])
        by_symbol = {q.get('symbol'): q for q in data}

        for s in symbols:
            q = by_symbol.get(s, {})
            price = q.get('regularMarketPrice')
            change_pct = q.get('regularMarketChangePercent')

            # Fallback with yfinance if Yahoo response is missing
            if price is None or change_pct is None:
                try:
                    t = yf.Ticker(s)
                    hist = t.history(period='2d')
                    if not hist.empty:
                        price = float(hist['Close'].iloc[-1])
                        prev = float(hist['Close'].iloc[-2]) if len(hist) > 1 else price
                        change_pct = ((price - prev) / prev) * 100 if prev else 0
                except Exception:
                    price = None
                    change_pct = None

            if price is None or change_pct is None:
                items.append({'text': f"{display.get(s, s)}: N/A", 'change': 0})
            else:
                sign = '+' if change_pct >= 0 else ''
                name = display.get(s, s)
                if s.endswith('-USD'):
                    text = f"{name}: ${price:,.0f} ({sign}{change_pct:.2f}%)"
                elif s in ('GC=F','SI=F','CL=F'):
                    text = f"{name}: ${price:,.2f} ({sign}{change_pct:.2f}%)"
                else:
                    text = f"{name}: {price:,.2f} ({sign}{change_pct:.2f}%)"
                items.append({'text': text, 'change': float(change_pct)})
    except Exception:
        items = [{'text': f"{display.get(s, s)}: N/A", 'change': 0} for s in symbols]

    _ticker_cache['ts'] = time.time()
    _ticker_cache['items'] = items
    return jsonify({'items': items})

@app.route('/upload_pdf', methods=['POST'])
def upload_pdf():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if 'pdf_file' not in request.files:
        return redirect(url_for('instructions'))
    
    file = request.files['pdf_file']
    if file.filename == '':
        return redirect(url_for('instructions'))
    
    if file and allowed_file(file.filename):
        try:
            # Use serverless writable tmp dir
            import os
            tmp_path = os.path.join('/tmp', f"{file.filename}")
            file.save(tmp_path)
            
            # Extract financial data
            data = extract_financial_data(tmp_path)
            
            # Get live market data
            tickers = ['AAPL', 'GOOGL', 'MSFT', 'TSLA', 'AMZN']
            live_market_data = {}
            
            def get_price(ticker):
                try:
                    stock = yf.Ticker(ticker)
                    price = stock.history(period='1d')['Close'].iloc[-1]
                    return ticker, f"${price:.2f}"
                except:
                    return ticker, "N/A"
            
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(get_price, ticker) for ticker in tickers]
                for future in as_completed(futures):
                    ticker, price = future.result()
                    live_market_data[ticker] = price
            
            # Get ticker info (using first ticker as example)
            ticker_info = {
                'ticker': 'AMZN',
                'current_price': '$150.00',
                'pe_ratio': '45.2',
                'week_change': '+12.5%',
                'earnings_growth': '+8.3%'
            }
            
            # Generate chart data for Chart.js
            balance_sheet_chart = generate_balance_sheet_chart(data)
            operations_chart = generate_operations_chart(data)
            cash_flows_chart = generate_cash_flows_chart(data)
            
            # Log the scan
            db = createConnection()
            logScan(db, session['username'], file.filename)
            
            # Clean up temp file
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            
            return render_template('scanResults.html',
                                 data=data,
                                 live_market_data=live_market_data,
                                 ticker_info=ticker_info,
                                 balance_sheet_chart=json.dumps(balance_sheet_chart),
                                 operations_chart=json.dumps(operations_chart),
                                 cash_flows_chart=json.dumps(cash_flows_chart),
                                 name=session['username'])
            
        except Exception as e:
            return f"Error processing PDF: {str(e)}"
    
    return redirect(url_for('instructions'))

@app.route('/compare_pdf')
def compare_pdf():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    return render_template('comparePDF.html')

@app.route('/scan_results')
def scan_results():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # This would typically get the last scan results
    # For now, return a placeholder
    return render_template('resultsInCompare.html',
                         data={'total_current_assets': {'2022': '100000', '2023': '120000'}},
                         live_market_data={'AAPL': '$150.00', 'GOOGL': '$2800.00'},
                         ticker_info={'ticker': 'AMZN', 'current_price': '$150.00'},
                         balance_sheet_chart='{}',
                         operations_chart='{}',
                         cash_flows_chart='{}')

if __name__ == '__main__':
    app.run(debug=True)