from flask import Flask, render_template, request, redirect, url_for, session, render_template_string, jsonify
from Database import createConnection, createCollection, registerUser, login, logScan
from PasswordHashing import hash_password, verify_password
# yfinance removed - using static data instead
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
    
    # Try 2024/2025 first, fallback to 2022/2023
    year1_key = '2024' if '2024' in data['total_current_assets'] else '2022'
    year2_key = '2025' if '2025' in data['total_current_assets'] else '2023'
    
    values_year1 = [
        float(data['total_current_assets'][year1_key]),
        float(data['total_assets'][year1_key]),
        float(data['total_current_liabilities'][year1_key]),
        float(data['total_stockholders_equity'][year1_key]),
        float(data['total_liabilities_and_stockholders_equity'][year1_key])
    ]
    values_year2 = [
        float(data['total_current_assets'][year2_key]),
        float(data['total_assets'][year2_key]),
        float(data['total_current_liabilities'][year2_key]),
        float(data['total_stockholders_equity'][year2_key]),
        float(data['total_liabilities_and_stockholders_equity'][year2_key])
    ]
    
    chart_data = {
        'labels': categories,
        'datasets': [
            {
                'label': year1_key,
                'data': values_year1,
                'backgroundColor': '#00c805',
                'borderColor': '#ffffff',
                'borderWidth': 2
            },
            {
                'label': year2_key,
                'data': values_year2,
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
    
    # Try 2024/2025 first, fallback to 2022/2023
    year1_key = '2024' if '2024' in data['cash_beginning'] else '2022'
    year2_key = '2025' if '2025' in data['cash_beginning'] else '2023'
    
    values_year1 = [
        float(data['cash_beginning'][year1_key]),
        float(data['net_income'][year1_key]),
        float(data['net_operating_cash'][year1_key]),
        float(data['net_investing_cash'][year1_key]),
        float(data['net_financing_cash'][year1_key]),
        float(data['cash_end'][year1_key])
    ]
    values_year2 = [
        float(data['cash_beginning'][year2_key]),
        float(data['net_income'][year2_key]),
        float(data['net_operating_cash'][year2_key]),
        float(data['net_investing_cash'][year2_key]),
        float(data['net_financing_cash'][year2_key]),
        float(data['cash_end'][year2_key])
    ]
    
    chart_data = {
        'labels': categories,
        'datasets': [
            {
                'label': year1_key,
                'data': values_year1,
                'borderColor': '#00c805',
                'backgroundColor': 'rgba(0, 200, 5, 0.1)',
                'borderWidth': 3,
                'tension': 0.4
            },
            {
                'label': year2_key,
                'data': values_year2,
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
    
    # Try 2024/2025 first, fallback to 2022/2023
    year1_key = '2024' if '2024' in data['total_net_sales'] else '2022'
    year2_key = '2025' if '2025' in data['total_net_sales'] else '2023'
    
    values_year1 = [
        float(data['total_net_sales'][year1_key]),
        float(data['total_operating_expenses'][year1_key]),
        float(data['net_income'][year1_key]),
        float(data['weighted_average_shares_basic'][year1_key]),
        float(data['diluted_average_shares_basic'][year1_key])
    ]
    values_year2 = [
        float(data['total_net_sales'][year2_key]),
        float(data['total_operating_expenses'][year2_key]),
        float(data['net_income'][year2_key]),
        float(data['weighted_average_shares_basic'][year2_key]),
        float(data['diluted_average_shares_basic'][year2_key])
    ]
    
    chart_data = {
        'labels': categories,
        'datasets': [
            {
                'label': year1_key,
                'data': values_year1,
                'borderColor': '#00c805',
                'backgroundColor': '#00c805',
                'borderWidth': 2,
                'pointRadius': 6,
                'pointHoverRadius': 8
            },
            {
                'label': year2_key,
                'data': values_year2,
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

    # Financial data extraction patterns - more flexible to handle different formats
    data = {}
    
    # Helper function to extract values from table format
    def extract_table_values(pattern, text):
        # Try multiple patterns for different table formats
        patterns = [
            # Pattern 1: "Metric Name    2024    2025"
            pattern + r'\s+(\d+(?:,\d{3})*(?:\.\d{2})?)\s+(\d+(?:,\d{3})*(?:\.\d{2})?)',
            # Pattern 2: "Metric Name    2024 (in million USD)    2025 (in million USD)"
            pattern + r'.*?2024.*?(\d+(?:,\d{3})*(?:\.\d{2})?).*?2025.*?(\d+(?:,\d{3})*(?:\.\d{2})?)',
            # Pattern 3: "Metric Name    $123,456    $789,012"
            pattern + r'\s+\$?\s*(\d+(?:,\d{3})*(?:\.\d{2})?)\s+\$?\s*(\d+(?:,\d{3})*(?:\.\d{2})?)',
            # Pattern 4: "Metric Name    2022    2023" (fallback for older documents)
            pattern + r'.*?2022.*?(\d+(?:,\d{3})*(?:\.\d{2})?).*?2023.*?(\d+(?:,\d{3})*(?:\.\d{2})?)',
        ]
        
        for p in patterns:
            match = re.search(p, text, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).replace(',', ''), match.group(2).replace(',', '')
        return '0', '0'
    
    # Current Assets
    val_2024, val_2025 = extract_table_values(r'Total current assets', text)
    data['total_current_assets'] = {'2024': val_2024, '2025': val_2025}
    
    # Total Assets
    val_2024, val_2025 = extract_table_values(r'Total assets', text)
    data['total_assets'] = {'2024': val_2024, '2025': val_2025}
    
    # Current Liabilities
    val_2024, val_2025 = extract_table_values(r'Total current liabilities', text)
    data['total_current_liabilities'] = {'2024': val_2024, '2025': val_2025}
    
    # Stockholders Equity
    val_2024, val_2025 = extract_table_values(r'Total stockholders\' equity', text)
    data['total_stockholders_equity'] = {'2024': val_2024, '2025': val_2025}
    
    # Total Liabilities and Stockholders Equity
    val_2024, val_2025 = extract_table_values(r'Total liabilities and stockholders\' equity', text)
    data['total_liabilities_and_stockholders_equity'] = {'2024': val_2024, '2025': val_2025}
    
    # Net Income
    val_2024, val_2025 = extract_table_values(r'Net income', text)
    data['net_income'] = {'2024': val_2024, '2025': val_2025}
    
    # Cash flows
    val_2024, val_2025 = extract_table_values(r'Cash, cash equivalents.*?beginning', text)
    data['cash_beginning'] = {'2024': val_2024, '2025': val_2025}
    
    # Operating cash
    val_2024, val_2025 = extract_table_values(r'Net cash provided by.*?operating', text)
    data['net_operating_cash'] = {'2024': val_2024, '2025': val_2025}
    
    # Investing cash
    val_2024, val_2025 = extract_table_values(r'Net cash used in investing', text)
    data['net_investing_cash'] = {'2024': val_2024, '2025': val_2025}
    
    # Financing cash
    val_2024, val_2025 = extract_table_values(r'Net cash provided by.*?financing', text)
    data['net_financing_cash'] = {'2024': val_2024, '2025': val_2025}
    
    # Cash end
    val_2024, val_2025 = extract_table_values(r'Cash, cash equivalents.*?end', text)
    data['cash_end'] = {'2024': val_2024, '2025': val_2025}
    
    # Net Sales
    val_2024, val_2025 = extract_table_values(r'Total net sales', text)
    data['total_net_sales'] = {'2024': val_2024, '2025': val_2025}
    
    # Operating Expenses
    val_2024, val_2025 = extract_table_values(r'Total operating expenses', text)
    data['total_operating_expenses'] = {'2024': val_2024, '2025': val_2025}
    
    # Weighted Average Shares Basic
    val_2024, val_2025 = extract_table_values(r'Weighted average shares basic', text)
    data['weighted_average_shares_basic'] = {'2024': val_2024, '2025': val_2025}
    
    # Diluted Average Shares Basic
    val_2024, val_2025 = extract_table_values(r'Diluted average shares basic', text)
    data['diluted_average_shares_basic'] = {'2024': val_2024, '2025': val_2025}
    
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
    try:
        scan_history = db.scans.find({"username": session['username']}).sort("date", -1).limit(10)
    except Exception as e:
        print(f"Error getting scan history: {e}")
        scan_history = []

    return render_template('profile.html', 
                         name=user.get('name', 'User'), 
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
    
    # Get live market data - using static data since yfinance was removed
    data = {
        'AAPL': '$195.50',
        'GOOGL': '$2,850.00', 
        'MSFT': '$420.30',
        'TSLA': '$245.80',
        'AMZN': '$155.20'
    }
    
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
            # Using static data since yfinance was removed
            static_data = {
                'AGBA': {'Revenue': '$50M', 'Operating Income': '$5M', 'Net Income': '$2M', 'Earnings Per Share': '$0.15', 'Profit': '$8M'},
                'SQQQ': {'Revenue': '$100M', 'Operating Income': '$15M', 'Net Income': '$10M', 'Earnings Per Share': '$0.25', 'Profit': '$20M'},
                'TQQQ': {'Revenue': '$200M', 'Operating Income': '$30M', 'Net Income': '$20M', 'Earnings Per Share': '$0.50', 'Profit': '$40M'},
                'SPY': {'Revenue': '$500M', 'Operating Income': '$75M', 'Net Income': '$50M', 'Earnings Per Share': '$1.25', 'Profit': '$100M'},
                'MARA': {'Revenue': '$150M', 'Operating Income': '$25M', 'Net Income': '$15M', 'Earnings Per Share': '$0.75', 'Profit': '$30M'},
                'MTTR': {'Revenue': '$80M', 'Operating Income': '$12M', 'Net Income': '$8M', 'Earnings Per Share': '$0.40', 'Profit': '$16M'},
                'NVDA': {'Revenue': '$2000M', 'Operating Income': '$400M', 'Net Income': '$300M', 'Earnings Per Share': '$12.00', 'Profit': '$600M'},
                'AMD': {'Revenue': '$800M', 'Operating Income': '$120M', 'Net Income': '$80M', 'Earnings Per Share': '$4.00', 'Profit': '$160M'},
                'AAPL': {'Revenue': '$5000M', 'Operating Income': '$1000M', 'Net Income': '$800M', 'Earnings Per Share': '$20.00', 'Profit': '$2000M'},
                'INTC': {'Revenue': '$1200M', 'Operating Income': '$180M', 'Net Income': '$120M', 'Earnings Per Share': '$6.00', 'Profit': '$240M'}
            }
            
            data = static_data.get(symbol, {})
            value = data.get(option, 'N/A')
            return symbol, value
        
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
    # 30s cache for stability
    if time.time() - _ticker_cache['ts'] < 30 and _ticker_cache['items']:
        return jsonify({'items': _ticker_cache['items']})

    # Symbols and display names
    # Keep a lean list for fast load; add the rest later via rotation if desired
    symbols = [
        '^DJI', '^GSPC', '^IXIC', 'SPY', 'QQQ',
        'AAPL', 'MSFT', 'NVDA', 'AMZN', 'TSLA', 'META', 'GOOGL',
        'BTC-USD', 'ETH-USD', 'GC=F', 'CL=F'
    ]
    display = {
        '^DJI': 'DOW', '^GSPC': 'S&P 500', '^IXIC': 'NASDAQ', '^VIX': 'VIX',
        'GC=F': 'GOLD', 'SI=F': 'SILVER', 'CL=F': 'CRUDE',
        'BRK-B': 'BRK.B'
    }

    url = 'https://query1.finance.yahoo.com/v7/finance/quote'
    items = []

    try:
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36'}
        resp = requests.get(url, params={'symbols': ','.join(symbols)}, headers=headers, timeout=6)
        data = resp.json().get('quoteResponse', {}).get('result', [])
        by_symbol = {q.get('symbol'): q for q in data}

        for s in symbols:
            q = by_symbol.get(s, {})
            price = q.get('regularMarketPrice')
            change_pct = q.get('regularMarketChangePercent')

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
            
            # Get live market data - using static data since we removed yfinance
            live_market_data = {
                'AAPL': '$195.50',
                'GOOGL': '$2,850.00', 
                'MSFT': '$420.30',
                'TSLA': '$245.80',
                'AMZN': '$155.20'
            }
            
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
            
            # Determine year keys for template
            year1_key = '2024' if '2024' in data.get('total_current_assets', {}) else '2022'
            year2_key = '2025' if '2025' in data.get('total_current_assets', {}) else '2023'
            
            # Log the scan
            try:
                db = createConnection()
                logScan(db, session['username'], file.filename)
            except Exception as e:
                print(f"Error logging scan: {e}")
            
            # Clean up temp file
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            
            return render_template('scanResults.html',
                                 data=data,
                                 year1_key=year1_key,
                                 year2_key=year2_key,
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