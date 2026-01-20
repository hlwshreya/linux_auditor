import os
import re
from flask import Flask, render_template_string, jsonify, abort
from bs4 import BeautifulSoup

app = Flask(__name__)

# CONFIGURATION: Point this to your guides directory
GUIDES_DIR = "/opt/scap-security-guide-0.1.79/guides"

def get_available_profiles():
    """Scans the directory for .html guide files."""
    files = [f for f in os.listdir(GUIDES_DIR) if f.endswith('.html')]
    profiles = []
    for f in files:
        # Extract a clean name from the filename
        display_name = f.replace('ssg-', '').replace('-guide-', ' ').replace('.html', '').replace('_', ' ').title()
        profiles.append({'id': f, 'name': display_name})
    return sorted(profiles, key=lambda x: x['name'])

def parse_guide(filename):
    """Parses the OpenSCAP HTML file and extracts rules into a JSON-like format."""
    path = os.path.join(GUIDES_DIR, filename)
    if not os.path.exists(path):
        return None
    
    with open(path, 'r', encoding='utf-8') as f:
        soup = BeautifulSoup(f, 'html.parser')

    rules_data = []
    # OpenSCAP guides usually put rules in specific containers
    # Note: Selectors might need minor adjustment based on specific SCAP versions
    rules = soup.find_all('div', class_='rule-description') or soup.find_all('div', id=re.compile('^rule-'))
    
    for rule in rules:
        title_tag = rule.find_previous(['h2', 'h3'])
        severity = "Unknown"
        if "low" in rule.get_text().lower(): severity = "Low"
        if "medium" in rule.get_text().lower(): severity = "Medium"
        if "high" in rule.get_text().lower(): severity = "High"

        rules_data.append({
            'title': title_tag.get_text().strip() if title_tag else "Unnamed Rule",
            'severity': severity,
            'description': rule.get_text()[:300] + "...",
            'id': rule.get('id', 'N/A')
        })
    
    return rules_data

# --- HTML TEMPLATE (Frontend) ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SCAP Security Explorer</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/alpinejs" defer></script>
</head>
<body class="bg-slate-100 font-sans text-slate-900" x-data="scapApp()">

    <div class="flex h-screen overflow-hidden">
        <aside class="w-80 bg-slate-900 text-white flex flex-col">
            <div class="p-6 border-b border-slate-700">
                <h1 class="text-xl font-bold tracking-tight">SCAP Explorer</h1>
                <p class="text-xs text-slate-400 mt-1">v0.1.79 Guides</p>
            </div>
            
            <div class="p-4 flex-grow overflow-y-auto">
                <h2 class="text-xs font-semibold text-slate-500 uppercase mb-4">Available Profiles</h2>
                <div class="space-y-1">
                    <template x-for="profile in profiles" :key="profile.id">
                        <button @click="loadProfile(profile.id)" 
                                :class="selectedProfile === profile.id ? 'bg-blue-600 text-white' : 'hover:bg-slate-800 text-slate-300'"
                                class="w-full text-left px-3 py-2 rounded text-sm transition-colors duration-150">
                            <span x-text="profile.name"></span>
                        </button>
                    </template>
                </div>
            </div>
        </aside>

        <main class="flex-grow flex flex-col overflow-hidden">
            <header class="bg-white shadow-sm z-10 p-4 flex justify-between items-center">
                <div class="flex items-center space-x-4">
                    <input type="text" x-model="searchQuery" placeholder="Search rules..." 
                           class="border border-slate-300 rounded-md px-4 py-2 text-sm w-96 focus:ring-2 focus:ring-blue-500 outline-none">
                    
                    <div class="flex bg-slate-100 rounded-md p-1 border">
                        <button @click="filterSeverity = 'all'" :class="filterSeverity === 'all' ? 'bg-white shadow-sm' : ''" class="px-3 py-1 text-xs rounded font-medium">All</button>
                        <button @click="filterSeverity = 'High'" :class="filterSeverity === 'High' ? 'bg-white shadow-sm text-red-600' : ''" class="px-3 py-1 text-xs rounded font-medium">High</button>
                        <button @click="filterSeverity = 'Medium'" :class="filterSeverity === 'Medium' ? 'bg-white shadow-sm text-amber-600' : ''" class="px-3 py-1 text-xs rounded font-medium">Med</button>
                    </div>
                </div>
                <div class="text-xs text-slate-500">
                    Showing <span x-text="filteredRules.length" class="font-bold text-slate-900"></span> rules
                </div>
            </header>

            <div class="flex-grow overflow-y-auto p-8">
                <div x-show="loading" class="flex items-center justify-center h-64 text-slate-400">
                    <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mr-3"></div>
                    Loading profile data...
                </div>

                <div class="grid grid-cols-1 gap-6" x-show="!loading">
                    <template x-for="rule in filteredRules" :key="rule.id">
                        <div class="bg-white rounded-xl shadow-sm border border-slate-200 p-6 hover:shadow-md transition-shadow duration-200">
                            <div class="flex justify-between items-start mb-3">
                                <span :class="{
                                    'bg-red-50 text-red-700': rule.severity === 'High',
                                    'bg-amber-50 text-amber-700': rule.severity === 'Medium',
                                    'bg-emerald-50 text-emerald-700': rule.severity === 'Low',
                                    'bg-slate-50 text-slate-700': rule.severity === 'Unknown'
                                }" class="text-[10px] font-bold uppercase px-2 py-1 rounded tracking-widest" x-text="rule.severity"></span>
                                <span class="text-[10px] font-mono text-slate-400" x-text="rule.id"></span>
                            </div>
                            <h3 class="text-lg font-bold text-slate-900 mb-2" x-text="rule.title"></h3>
                            <p class="text-sm text-slate-600 leading-relaxed mb-4" x-text="rule.description"></p>
                            <div class="flex space-x-2">
                                <button class="text-xs font-bold text-blue-600 hover:underline">Full Documentation</button>
                                <span class="text-slate-300">|</span>
                                <button class="text-xs font-bold text-blue-600 hover:underline">Copy Remediation</button>
                            </div>
                        </div>
                    </template>
                </div>
            </div>
        </main>
    </div>

    <script>
        function scapApp() {
            return {
                profiles: [],
                selectedProfile: '',
                rules: [],
                searchQuery: '',
                filterSeverity: 'all',
                loading: false,

                init() {
                    fetch('/api/profiles')
                        .then(res => res.json())
                        .then(data => {
                            this.profiles = data;
                            if(data.length > 0) this.loadProfile(data[0].id);
                        });
                },

                loadProfile(id) {
                    this.selectedProfile = id;
                    this.loading = true;
                    fetch(`/api/rules/${id}`)
                        .then(res => res.json())
                        .then(data => {
                            this.rules = data;
                            this.loading = false;
                        });
                },

                get filteredRules() {
                    return this.rules.filter(r => {
                        const matchesSearch = r.title.toLowerCase().includes(this.searchQuery.toLowerCase()) || 
                                              r.id.toLowerCase().includes(this.searchQuery.toLowerCase());
                        const matchesSeverity = this.filterSeverity === 'all' || r.severity === this.filterSeverity;
                        return matchesSearch && matchesSeverity;
                    });
                }
            }
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/profiles')
def api_profiles():
    return jsonify(get_available_profiles())

@app.route('/api/rules/<filename>')
def api_rules(filename):
    data = parse_guide(filename)
    if data is None: abort(404)
    return jsonify(data)

if __name__ == '__main__':
    print(f"Starting SCAP Explorer on http://localhost:5000")
    print(f"Scanning directory: {GUIDES_DIR}")
    app.run(debug=True, port=5000)
