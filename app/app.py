import os
import re
from flask import Flask, render_template_string, jsonify, abort
from bs4 import BeautifulSoup

app = Flask(__name__)

# CONFIGURATION: Point this to your guides directory
GUIDES_DIR = "/opt/scap-security-guide-0.1.79/guides"

def get_available_profiles():
    """Scans the directory for .html guide files."""
    if not os.path.exists(GUIDES_DIR):
        print(f"ERROR: Directory not found: {GUIDES_DIR}")
        return []
    files = [f for f in os.listdir(GUIDES_DIR) if f.endswith('.html')]
    profiles = []
    for f in files:
        display_name = f.replace('ssg-', '').replace('-guide-', ' ').replace('.html', '').replace('_', ' ').title()
        profiles.append({'id': f, 'name': display_name})
    return sorted(profiles, key=lambda x: x['name'])

def parse_guide(filename):
    """Robust parser for OpenSCAP Bootstrap-based HTML guides."""
    path = os.path.join(GUIDES_DIR, filename)
    print(f"DEBUG: Parsing file: {path}")
    
    with open(path, 'r', encoding='utf-8') as f:
        soup = BeautifulSoup(f, 'html.parser')

    rules_data = []
    
    # OpenSCAP guides typically use 'panel-default' for each rule block
    # and IDs starting with 'rule-'
    rule_panels = soup.find_all('div', class_='panel-default')
    
    for panel in rule_panels:
        # Check if this panel is actually a rule (OpenSCAP rules have specific IDs)
        panel_id = panel.get('id', '')
        if not panel_id.startswith('rule-'):
            continue

        # 1. Extract Title
        title_elem = panel.find('h3', class_='panel-title')
        title = title_elem.get_text(strip=True) if title_elem else "Unnamed Rule"

        # 2. Extract Severity
        # Usually looks like <span class="label label-warning">medium</span>
        severity = "Unknown"
        sev_badge = panel.find('span', class_='label')
        if sev_badge:
            text = sev_badge.get_text().lower()
            if 'high' in text or 'danger' in text: severity = "High"
            elif 'medium' in text or 'warning' in text: severity = "Medium"
            elif 'low' in text or 'info' in text: severity = "Low"

        # 3. Extract Description
        # Description is usually in a div with class 'panel-body' or similar
        body = panel.find('div', class_='panel-body')
        description = "No description available."
        if body:
            # We try to find the specific description text, or just take the first few paragraphs
            desc_text = body.get_text(strip=True)
            description = (desc_text[:350] + '...') if len(desc_text) > 350 else desc_text

        rules_data.append({
            'title': title,
            'severity': severity,
            'description': description,
            'id': panel_id
        })
    
    print(f"DEBUG: Found {len(rules_data)} rules in {filename}")
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
        <aside class="w-80 bg-slate-900 text-white flex flex-col shadow-2xl">
            <div class="p-6 border-b border-slate-700 bg-slate-950">
                <h1 class="text-xl font-bold tracking-tight">SCAP Explorer</h1>
                <p class="text-xs text-slate-400 mt-1 uppercase tracking-widest font-semibold">v0.1.79 Local Library</p>
            </div>
            
            <div class="p-4 flex-grow overflow-y-auto">
                <h2 class="text-xs font-semibold text-slate-500 uppercase mb-4 px-3">Available Profiles</h2>
                <div class="space-y-1">
                    <template x-for="profile in profiles" :key="profile.id">
                        <button @click="loadProfile(profile.id)" 
                                :class="selectedProfile === profile.id ? 'bg-blue-600 text-white shadow-lg' : 'hover:bg-slate-800 text-slate-400 hover:text-white'"
                                class="w-full text-left px-3 py-2.5 rounded-lg text-sm transition-all duration-200 flex items-center">
                            <i class="fas fa-file-shield mr-3 opacity-50"></i>
                            <span x-text="profile.name" class="truncate"></span>
                        </button>
                    </template>
                </div>
            </div>
        </aside>

        <main class="flex-grow flex flex-col overflow-hidden">
            <header class="bg-white shadow-sm z-10 p-6 flex justify-between items-center border-b">
                <div class="flex items-center space-x-6">
                    <div>
                        <h2 class="text-sm font-bold text-slate-400 uppercase tracking-tighter">Current Profile</h2>
                        <p class="text-lg font-bold text-slate-800" x-text="profiles.find(p => p.id === selectedProfile)?.name || 'Select a profile'"></p>
                    </div>
                    
                    <div class="h-10 w-px bg-slate-200"></div>

                    <input type="text" x-model="searchQuery" placeholder="Search rules or IDs..." 
                           class="border border-slate-200 rounded-xl px-4 py-2.5 text-sm w-80 focus:ring-4 focus:ring-blue-100 focus:border-blue-500 outline-none transition-all">
                </div>
                
                <div class="flex items-center space-x-3 bg-slate-100 rounded-xl p-1.5 border border-slate-200">
                    <button @click="filterSeverity = 'all'" :class="filterSeverity === 'all' ? 'bg-white shadow-sm text-blue-600' : 'text-slate-500'" class="px-4 py-1.5 text-xs rounded-lg font-bold transition-all">ALL</button>
                    <button @click="filterSeverity = 'High'" :class="filterSeverity === 'High' ? 'bg-white shadow-sm text-red-600' : 'text-slate-500'" class="px-4 py-1.5 text-xs rounded-lg font-bold transition-all">HIGH</button>
                    <button @click="filterSeverity = 'Medium'" :class="filterSeverity === 'Medium' ? 'bg-white shadow-sm text-amber-600' : 'text-slate-500'" class="px-4 py-1.5 text-xs rounded-lg font-bold transition-all">MED</button>
                </div>
            </header>

            <div class="flex-grow overflow-y-auto p-8 bg-slate-50/50">
                <div x-show="loading" class="flex flex-col items-center justify-center h-full text-slate-400 animate-pulse">
                    <div class="w-12 h-12 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mb-4"></div>
                    <p class="font-medium">Analyzing Security Guide...</p>
                </div>

                <div x-show="!loading && filteredRules.length === 0" class="flex flex-col items-center justify-center h-full text-slate-400">
                    <p class="text-lg font-medium">No rules match your search or filters.</p>
                </div>

                <div class="grid grid-cols-1 xl:grid-cols-2 gap-6" x-show="!loading">
                    <template x-for="rule in filteredRules" :key="rule.id">
                        <div class="bg-white rounded-2xl shadow-sm border border-slate-200 p-6 hover:shadow-xl hover:border-blue-200 transition-all duration-300 group">
                            <div class="flex justify-between items-start mb-4">
                                <span :class="{
                                    'bg-red-100 text-red-700': rule.severity === 'High',
                                    'bg-amber-100 text-amber-700': rule.severity === 'Medium',
                                    'bg-emerald-100 text-emerald-700': rule.severity === 'Low',
                                    'bg-slate-100 text-slate-700': rule.severity === 'Unknown'
                                }" class="text-[10px] font-black uppercase px-2.5 py-1 rounded-md tracking-wider" x-text="rule.severity"></span>
                                <span class="text-[10px] font-mono text-slate-300 group-hover:text-slate-500 transition-colors" x-text="rule.id"></span>
                            </div>
                            <h3 class="text-base font-bold text-slate-900 mb-3 leading-snug group-hover:text-blue-600 transition-colors" x-text="rule.title"></h3>
                            <p class="text-sm text-slate-500 leading-relaxed mb-6" x-text="rule.description"></p>
                            
                            <div class="pt-4 border-t border-slate-50 flex justify-between items-center">
                                <button class="text-xs font-bold text-blue-600 hover:text-blue-800 flex items-center">
                                    Full Documentation <i class="fas fa-arrow-right ml-2 text-[10px]"></i>
                                </button>
                                <button class="p-2 hover:bg-slate-100 rounded-lg text-slate-400 transition-colors" title="Copy ID">
                                    <i class="far fa-copy text-sm"></i>
                                </button>
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
                    this.rules = []; // Clear current rules while loading
                    fetch(`/api/rules/${id}`)
                        .then(res => res.json())
                        .then(data => {
                            this.rules = data;
                            this.loading = false;
                        })
                        .catch(err => {
                            console.error("Error loading rules:", err);
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
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
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
    app.run(debug=True, port=5000)
