"""
Flask Web Dashboard for Network Intrusion Detection System
Real-time monitoring interface with live updates
"""
from flask import Flask, render_template, jsonify
import json
import os
from datetime import datetime

app = Flask(__name__)

# FIXED: Use absolute path
DATA_FILE = os.path.join(os.path.dirname(__file__), 'data', 'live_data.json')
print(f"🔍 Looking for data at: {DATA_FILE}")

def load_data():
    """Helper function to load data from file with better error handling"""
    try:
        print(f"🔍 Checking if file exists: {os.path.exists(DATA_FILE)}")
        
        if not os.path.exists(DATA_FILE):
            print(f"❌ Data file NOT found at: {DATA_FILE}")
            return get_empty_data_structure()
        
        # Check file size
        file_size = os.path.getsize(DATA_FILE)
        if file_size == 0:
            print(f"⚠️  Data file is empty (0 bytes)")
            return get_empty_data_structure()
        
        print(f"✓ File size: {file_size:,} bytes")
        
        # Try to load JSON
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Validate data structure
        if not isinstance(data, dict):
            print(f"⚠️  Invalid data type: {type(data)}")
            return get_empty_data_structure()
        
        # Check required keys
        required_keys = ['last_updated', 'summary', 'recent_alerts']
        missing_keys = [k for k in required_keys if k not in data]
        
        if missing_keys:
            print(f"⚠️  Missing keys: {missing_keys}")
            # Add missing keys with defaults
            if 'last_updated' not in data:
                data['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if 'summary' not in data:
                data['summary'] = {
                    'session_info': {'total_flows': 0, 'total_alerts': 0, 'total_packets': 0},
                    'statistics': {'decisions': {}, 'alert_levels': {}, 'protocols': {}}
                }
            if 'recent_alerts' not in data:
                data['recent_alerts'] = []
            if 'top_suspicious' not in data:
                data['top_suspicious'] = []
        
        # Log what we loaded
        flows = len(data.get('recent_alerts', []))
        total = data.get('summary', {}).get('session_info', {}).get('total_flows', 0)
        print(f"✅ Loaded data: {flows} recent alerts, {total} total flows")
        
        return data
    
    except json.JSONDecodeError as e:
        print(f"❌ JSON parsing error: {e}")
        print(f"   Position: line {e.lineno}, column {e.colno}")
        print(f"   Hint: JSON file may be corrupted. Re-run Cell 6 in notebook.")
        return get_empty_data_structure()
    
    except Exception as e:
        print(f"❌ Unexpected error loading data: {e}")
        import traceback
        traceback.print_exc()
        return get_empty_data_structure()

def get_empty_data_structure():
    """Return empty but valid data structure"""
    return {
        'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'summary': {
            'session_info': {
                'total_flows': 0,
                'total_alerts': 0,
                'total_packets': 0,
                'interface': 'N/A',
                'interface_ip': 'N/A',
                'capture_duration': 0
            },
            'statistics': {
                'decisions': {'NORMAL': 0, 'ATTACK': 0},
                'alert_levels': {'INFO': 0, 'WARNING': 0, 'CRITICAL': 0},
                'protocols': {}
            }
        },
        'recent_alerts': [],
        'top_suspicious': []
    }

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    """API endpoint for dashboard statistics"""
    print(f"\n📊 /api/stats called at {datetime.now().strftime('%H:%M:%S')}")
    
    data = load_data()
    
    # Always return valid data (never None)
    if data is None:
        print(f"⚠️  load_data() returned None, using empty structure")
        data = get_empty_data_structure()
    
    total_flows = data.get('summary', {}).get('session_info', {}).get('total_flows', 0)
    print(f"✅ Returning stats - Total flows: {total_flows}")
    
    return jsonify(data)

@app.route('/api/flows')
def get_flows():
    """API endpoint for all flow data"""
    print(f"\n📊 /api/flows called at {datetime.now().strftime('%H:%M:%S')}")
    
    data = load_data()
    
    if data is None:
        data = get_empty_data_structure()
    
    flows = data.get('recent_alerts', [])
    print(f"✅ Returning {len(flows)} flows")
    
    return jsonify(flows)

@app.route('/api/alerts')
def get_alerts():
    """API endpoint for alerts"""
    print(f"\n📊 /api/alerts called at {datetime.now().strftime('%H:%M:%S')}")
    
    data = load_data()
    
    if data is None:
        data = get_empty_data_structure()
    
    alerts = data.get('recent_alerts', [])
    print(f"✅ Returning {len(alerts)} alerts")
    
    return jsonify(alerts)

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    file_exists = os.path.exists(DATA_FILE)
    file_size = os.path.getsize(DATA_FILE) if file_exists else 0
    
    return jsonify({
        'status': 'ok',
        'data_file_exists': file_exists,
        'data_file_size': file_size,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

if __name__ == '__main__':
    print("="*60)
    print("🚀 NIDS WEB DASHBOARD STARTING")
    print("="*60)
    print(f"\n✓ Dashboard URL: http://localhost:5000")
    print(f"✓ Data file path: {DATA_FILE}")
    print(f"✓ Data file exists: {os.path.exists(DATA_FILE)}")
    
    if os.path.exists(DATA_FILE):
        size = os.path.getsize(DATA_FILE)
        print(f"✓ Data file size: {size:,} bytes")
        
        # Load and preview data
        try:
            with open(DATA_FILE, 'r') as f:
                preview = json.load(f)
            flows = len(preview.get('recent_alerts', []))
            total = preview.get('summary', {}).get('session_info', {}).get('total_flows', 0)
            print(f"✓ Preview: {flows} recent alerts, {total} total flows")
        except Exception as e:
            print(f"✗ Could not preview data: {e}")
    else:
        print(f"⚠️  Data file NOT FOUND!")
        print(f"   Expected location: {DATA_FILE}")
        print(f"   Please run Cell 6 in notebook to create data file")
    
    print("\n✓ API Endpoints:")
    print("   - / (Dashboard UI)")
    print("   - /api/stats (Summary statistics)")
    print("   - /api/flows (All flow data)")
    print("   - /api/alerts (Alert data for table)")
    print("   - /api/health (Health check)")
    
    print("\n⚠️  Press Ctrl+C to stop server\n")
    print("="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
