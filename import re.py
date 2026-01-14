import re
import os
import webbrowser
import csv
import markdown
from collections import Counter
from datetime import datetime

DANGER_CRITIQUE = "#ef4444" # Rouge
DANGER_ELEVE = "#f97316"    # Orange
DANGER_MOYEN = "#eab308"    # Jaune
DANGER_INFO = "#3b82f6"     # Bleu

def hex_to_ascii(hex_str):
    """Traduit le code hexadécimal en texte lisible."""
    try:
        clean_hex = hex_str.replace(" ", "").replace("\t", "").replace("\n", "")
        bytes_data = bytes.fromhex(clean_hex)
        return bytes_data.decode('utf-8', errors='ignore') 
    except:
        return ""

def detecter_buffer_overflow(payload_hex):
    """Détecte les répétitions de caractères typiques des Buffer Overflows."""
    clean_hex = payload_hex.replace(" ", "").replace("\t", "").replace("\n", "")
    if len(clean_hex) > 100:
        most_common = Counter([clean_hex[i:i+2] for i in range(0, len(clean_hex), 2)]).most_common(1)
        if most_common and most_common[0][1] > 40:
            return True
    return False

def generer_analyse(chemin_fichier):
    # Validation
    if not os.path.exists(chemin_fichier):
        print(f"❌ ERREUR FATALE : Le fichier '{chemin_fichier}' est introuvable.")
        return

    # Chemins
    dossier_script = os.path.dirname(os.path.abspath(__file__)) if '__file__' in locals() else os.getcwd()
    chemin_csv = os.path.join(dossier_script, "RAPPORT_MENACES.csv")
    chemin_md = os.path.join(dossier_script, "RAPPORT_SECURITE.md")
    chemin_html = os.path.join(dossier_script, "dashboard_securite.html")

    #Analyse de l'heure
    # On capture l'heure au début : (\d{2}:\d{2}:\d{2}\.\d+)
    pattern_ip = re.compile(r'(\d{2}:\d{2}:\d{2}\.\d+) IP ([\w\.-]+) > ([\w\.-]+):.*Flags \[([\w\.]+)\].*length (\d+)')
    pattern_hex = re.compile(r'^\t0x[0-9a-f]{4}:  ((?:[0-9a-f]{4}\s?)+)', re.MULTILINE)
    
    alertes = []
    
    print("⏳ Analyse en cours... Veuillez patienter.")
    
    with open(chemin_fichier, 'r', encoding='utf-8', errors='ignore') as f:
        contenu = f.read()

    paquets = re.split(r'\n(?=\d{2}:\d{2}:\d{2}\.\d+ IP)', contenu)

    for p in paquets:
        header = pattern_ip.search(p)
        if header:
            timestamp, src, dst, flags, length = header.groups()
            
            hex_raw = "".join(pattern_hex.findall(p))
            payload_ascii = hex_to_ascii(hex_raw).lower()
            
            menace = None
            gravite = "INFO"
            couleur = DANGER_INFO
            
            # detections
            if detecter_buffer_overflow(hex_raw):
                menace = "Buffer Overflow (Padding)"
                gravite = "CRITIQUE"
                couleur = DANGER_CRITIQUE
            elif "<script>" in payload_ascii or "alert(" in payload_ascii:
                menace = "XSS (Injection de Script)"
                gravite = "ÉLEVÉ"
                couleur = DANGER_ELEVE
            elif any(x in payload_ascii for x in ["union select", "or 1=1", "drop table"]):
                menace = "Injection SQL"
                gravite = "CRITIQUE"
                couleur = DANGER_CRITIQUE
            elif "../" in payload_ascii or "/etc/passwd" in payload_ascii:
                menace = "Path Traversal (Accès Fichiers)"
                gravite = "ÉLEVÉ"
                couleur = DANGER_ELEVE
            elif "http" in dst and flags == "S" and "5858" in hex_raw: 
                menace = "HTTP Flood (DoS)"
                gravite = "MOYEN"
                couleur = DANGER_MOYEN
            elif ".ssh" in dst or ".ssh" in src:
                menace = "Trafic SSH (Admin ou BruteForce)"
                gravite = "INFO"
                couleur = DANGER_INFO
            elif "dns" in p.lower() or "ptr?" in p or "a?" in p:
                menace = "Reconnaissance DNS"
                gravite = "INFO"
                couleur = DANGER_INFO

            if menace:
                alertes.append({
                    "Heure": timestamp,
                    "Source": src, "Cible": dst, "Menace": menace,
                    "Gravité": gravite, "Détails": f"Paquet {length} bytes", "Couleur": couleur
                })

    #CSV
    try:
        with open(chemin_csv, 'w', newline='', encoding='utf-8-sig') as csvfile:
            fieldnames = ['Heure', 'Source', 'Cible', 'Menace', 'Gravité', 'Détails']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')
            writer.writeheader()
            for a in alertes:
                writer.writerow({k: a[k] for k in fieldnames})
        print(f"Fichier CSV généré : {chemin_csv}")
    except Exception as e:
        print(f" Erreur CSV : {e}")

    #MARKDOWN
    md_content = f"""
# Rapport de Sécurité
**Fichier :** `{os.path.basename(chemin_fichier)}`  
**Date du rapport :** {datetime.now().strftime("%d/%m/%Y %H:%M")}

---
## Synthèse
- **Total Alertes :** {len(alertes)}
- **Critiques :** {len([a for a in alertes if a['Gravité'] == 'CRITIQUE'])}
- **Élevées :** {len([a for a in alertes if a['Gravité'] == 'ÉLEVÉ'])}

---
## 🚨Journal des Menaces (Extrait)
| Heure | Gravité | Menace | Source | Cible |
| :--- | :--- | :--- | :--- | :--- |
"""
    for a in alertes[:50]:
        icon = "🔴" if a['Gravité'] == "CRITIQUE" else "🟠" if a['Gravité'] == "ÉLEVÉ" else "🟡"
        md_content += f"| `{a['Heure']}` | {icon} {a['Gravité']} | {a['Menace']} | `{a['Source']}` | `{a['Cible']}` |\n"
    
    with open(chemin_md, "w", encoding="utf-8") as f:
        f.write(md_content)
    print(f"✅ Fichier Markdown généré : {chemin_md}")

    # Page web
    stats_menaces = Counter([a['Menace'] for a in alertes])
    
    lignes_tableau = ""
    for a in alertes[:20]:
        lignes_tableau += f"""
        <tr>
            <td class="text-monospace">{a['Heure']}</td> <td><span class="badge" style="background-color:{a['Couleur']}">{a['Gravité']}</span></td>
            <td>{a['Menace']}</td>
            <td>{a['Source']}</td>
            <td>{a['Cible']}</td>
        </tr>
        """

    html = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Analyse</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            body {{ background-color: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', sans-serif; }}
            .navbar {{ background: #1e293b; border-bottom: 1px solid #334155; }}
            .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5); }}
            .card-header {{ background: transparent; border-bottom: 1px solid #334155; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; color: #94a3b8; }}
            .stat-value {{ font-size: 2.5rem; font-weight: bold; color: white; }}
            .table {{ color: #cbd5e1; font-family: 'JetBrains Mono', monospace; font-size: 0.9em; }}
            .text-monospace {{ font-family: 'JetBrains Mono', monospace; color: #94a3b8; }}
            .table-hover tbody tr:hover {{ background-color: #334155; color: white; }}
            @media print {{ 
                body {{ background: white; color: black; }} 
                .card {{ border: 1px solid #ccc; box-shadow: none; }}
                .no-print {{ display: none; }}
            }}
        </style>
    </head>
    <body class="pb-5">
        <nav class="navbar navbar-expand-lg navbar-dark px-4 py-3 mb-4">
            <div class="container-fluid">
                <a class="navbar-brand fw-bold text-info" href="#">Analyse</a>
                <div class="d-flex no-print">
                    <button onclick="window.print()" class="btn btn-outline-light btn-sm me-2">PDF</button>
                    <a href="{os.path.basename(chemin_md)}" class="btn btn-outline-warning btn-sm me-2">Markdown</a>
                    <a href="{os.path.basename(chemin_csv)}" class="btn btn-primary btn-sm">CSV</a>
                </div>
            </div>
        </nav>

        <div class="container-fluid px-4">
            <div class="row g-4 mb-4">
                <div class="col-md-3">
                    <div class="card h-100 p-3">
                        <small class="text-muted">Total Alertes</small>
                        <div class="stat-value text-primary">{len(alertes)}</div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card h-100 p-3">
                        <small class="text-muted">Menaces Critiques</small>
                        <div class="stat-value text-danger">
                            {len([a for a in alertes if a['Gravité'] == 'CRITIQUE'])}
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card h-100 p-3 d-flex align-items-center justify-content-center">
                        <h5 class="m-0 text-warning">Rapports générés : CSV & Markdown</h5>
                    </div>
                </div>
            </div>

            <div class="row g-4">
                <div class="col-md-4">
                    <div class="card h-100">
                        <div class="card-header">Répartition des Attaques</div>
                        <div class="card-body">
                            <canvas id="vulnChart"></canvas>
                        </div>
                    </div>
                </div>

                <div class="col-md-8">
                    <div class="card h-100">
                        <div class="card-header d-flex justify-content-between">
                            <span>Flux en Temps Réel (Top 20)</span>
                            <span class="badge bg-secondary">{len(alertes)} événements</span>
                        </div>
                        <div class="table-responsive">
                            <table class="table table-hover align-middle mb-0">
                                <thead class="table-dark">
                                    <tr>
                                        <th>Heure</th> <th>Gravité</th>
                                        <th>Menace</th>
                                        <th>Source</th>
                                        <th>Cible</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {lignes_tableau}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            const ctx = document.getElementById('vulnChart').getContext('2d');
            new Chart(ctx, {{
                type: 'doughnut',
                data: {{
                    labels: {list(stats_menaces.keys())},
                    datasets: [{{
                        data: {list(stats_menaces.values())},
                        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#8b5cf6'],
                        borderWidth: 0
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{ position: 'bottom', labels: {{ color: '#94a3b8' }} }}
                    }}
                }}
            }});
        </script>
    </body>
    </html>
    """

    with open(chemin_html, "w", encoding="utf-8") as f:
        f.write(html)
    
    print("✅Analyse terminée avec succès.")
    webbrowser.open('file://' + chemin_html)

# Lancement
generer_analyse(r"C:\Users\Irmane\Documents\SAE1.05\DumpFile.txt")